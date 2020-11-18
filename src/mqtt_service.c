#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "tuya_log.h"
#include "tuya_error_code.h"
#include "system_interface.h"
#include "network_interface.h"

#include "cJSON.h"
#include "crc32.h"
#include "uni_md5.h"
#include "aes_inf.h"
#include "core_mqtt.h"
#include "mqtt_service.h"

enum {
	MQTT_STATE_INIT,
	MQTT_STATE_IDLE,
	MQTT_STATE_TLS_CONNECTING,
	MQTT_STATE_CONNECTING,
	MQTT_STATE_CONNECTED,
	MQTT_STATE_STOP,
	MQTT_STATE_WAIT_CONNECTED_CONFIRM,
	MQTT_STATE_WAIT_SUBSCRIBED_CONFIRM,
	MQTT_STATE_YIELD,
};

extern const unsigned char tuya_rootCA_pem[];

/*-----------------------------------------------------------*/
#define NETWORK_BUFFER_SIZE    ( 1024U )

/**
 * @brief Timeout for receiving CONNACK packet in milli seconds.
 */
#define CONNACK_RECV_TIMEOUT_MS             ( 5000U )

/**
 * @brief The network buffer must remain valid for the lifetime of the MQTT context.
 */
static uint8_t buffer[ NETWORK_BUFFER_SIZE ];

/*-----------------------------------------------------------*/


static int tuya_mqtt_signature_tool(const tuya_meta_info_t *input, tuya_mqtt_access_t *signout)
{
	if (NULL == input || signout == NULL) {
		TY_LOGE("param error");
		return OPRT_INVALID_PARM;
	}

    // clear
	int i;
    uint8_t digest[16] = {0};
    memset(signout, 0, sizeof(tuya_mqtt_access_t));

    if (input->devid && input->seckey && input->localkey) {
        // ACTIVED
        memcpy(signout->cipherkey, input->localkey, 16);
        sprintf(signout->clientid, "%s",input->devid);
        sprintf(signout->username, "%s", input->devid);
		uni_md5_digest_tolal((const uint8_t*)input->seckey, strlen(input->seckey), digest);
        for (i = 0; i < 8; ++i) {
            sprintf(&signout->password[i * 2], "%02x", (unsigned char)digest[i+4]);
        }

		// IO topic
        sprintf(signout->topic_in, "smart/device/in/%s", input->devid);
        sprintf(signout->topic_out, "smart/device/out/%s", input->devid);

    } else if(input->uuid && input->authkey) {
		// UNACTIVED
        memcpy(signout->cipherkey, input->authkey, 16);
        sprintf(signout->clientid, "acon_%s",input->uuid);
        sprintf(signout->username, "acon_%s", input->uuid);
		uni_md5_digest_tolal((const uint8_t*)input->authkey, strlen(input->authkey), digest);
        for (i = 0; i < 8; ++i) {
            sprintf(&signout->password[i * 2], "%02x", (unsigned char)digest[i+4]);
        }

		// IO topic
        sprintf(signout->topic_in, "d/ai/%s", input->uuid);
        sprintf(signout->topic_out, "%s", ""); // not support publish data on direct mode

    } else {
        TY_LOGE("input error");
		return OPRT_INVALID_PARM;
    }
    return OPRT_OK;
}

/*-----------------------------------------------------------*/

static void mqtt_event_data_on(tuya_mqtt_context_t* context, const uint8_t* payload, size_t payload_len)
{
	int rt = OPRT_OK;
	int i;

	/* package length check */
	if (payload_len < TUYA_MQTT_DATA_OFFSET) {
		TY_LOGE("len too short");
		return;
	}

	/* unpack tuya protocol 2.2 */
	/* verison filter */
	char ver[4] = {0}; 
	memcpy(ver, payload, TUYA_MQTT_VER_LEN);
	if (strcmp(ver, "2.2") != 0) {
		TY_LOGE("verison error:%s", ver);
		return;
	}

	uint32_t crc32, sequence, source;
	memcpy(&crc32, payload + TUYA_MQTT_CRC32_OFFSET, TUYA_MQTT_CRC32_LEN);
	memcpy(&sequence, payload + TUYA_MQTT_SEQUENCE_OFFSET, TUYA_MQTT_SEQUENCE_LEN);
	memcpy(&source, payload + TUYA_MQTT_SOURCE_OFFSET, TUYA_MQTT_SOURCE_LEN);
#if BYTE_ORDER == LITTLE_ENDIAN
	sequence = DWORD_SWAP(sequence);
	source = DWORD_SWAP(source);
#endif
	TY_LOGD("version:%s, crc32:%08x, sequence:%d, source:%d", ver, crc32, sequence, source);

	/* get encrypt data */
	uint8_t* data = (uint8_t*)payload + TUYA_MQTT_DATA_OFFSET;
	size_t data_len = (size_t)(payload_len - TUYA_MQTT_DATA_OFFSET);
	TY_LOGD("data len:%d", (int)data_len);

	// decrypt buffer
	uint8_t* jsonstr = NULL;
	size_t jsonstr_len = 0;

	char* cipherkey = context->signature.cipherkey;
	TY_LOGV("cipherkey:%s", cipherkey);
	rt = aes128_ecb_decode((const uint8_t*)data, data_len, &jsonstr, (uint32_t*)&jsonstr_len, (const uint8_t*)cipherkey);
	if (OPRT_OK != rt) {
		TY_LOGE("mqtt data decrypt fail:%d", rt);
		system_free(jsonstr);
		return;
	}
	jsonstr[jsonstr_len] = '\0';
	TY_LOGD("MQTT recv len:%d, output:%s", (int)jsonstr_len, jsonstr);
	
	// json parse
	cJSON *root = NULL;
    cJSON *json = NULL;
    root = cJSON_Parse((const char *)jsonstr);
	system_free(jsonstr);
    if(NULL == root) {
        TY_LOGE("JSON parse error");
		rt = OPRT_CJSON_PARSE_ERR;
        goto exit;
    }

	/* JSON key verfiy */
    if(( NULL == cJSON_GetObjectItem(root,"protocol")) || \
       ( NULL == cJSON_GetObjectItem(root,"t")) || \
       ( NULL == cJSON_GetObjectItem(root,"data"))) {
        TY_LOGE("param is no correct");
		rt = OPRT_CJSON_GET_ERR;
        goto exit;
    }

    // protocol
    int protocol_id = cJSON_GetObjectItem(root,"protocol")->valueint;
    json = cJSON_GetObjectItem(root,"data");
    if(NULL == json) {
        TY_LOGE("get json err");
        goto exit;
    }

    // dispatch
	for (i = 0; i < context->handle_num; i++) {
		if (context->protocol_handle[i].id == protocol_id) {
			tuya_mqtt_event_t event = {
				.event_id = protocol_id,
				.data = cJSON_GetObjectItem(root, "data"),
				.data_len = 0,
				.user_data = context->protocol_handle[i].user_data,
			};
			context->protocol_handle[i].cb(&event);
			break;
		}
	}

exit:
	cJSON_Delete(root);
}

/*-----------------------------------------------------------*/
#define MQTT_EVENT_2STR(S)\
((S) == MQTT_PACKET_TYPE_CONNECT ? "MQTT_PACKET_TYPE_CONNECT":\
((S) == MQTT_PACKET_TYPE_CONNACK ? "MQTT_PACKET_TYPE_CONNACK":\
((S) == MQTT_PACKET_TYPE_PUBLISH ? "MQTT_PACKET_TYPE_PUBLISH":\
((S) == MQTT_PACKET_TYPE_PUBACK ? "MQTT_PACKET_TYPE_PUBACK":\
((S) == MQTT_PACKET_TYPE_PUBREC ? "MQTT_PACKET_TYPE_PUBREC":\
((S) == MQTT_PACKET_TYPE_PUBREL ? "MQTT_PACKET_TYPE_PUBREL":\
((S) == MQTT_PACKET_TYPE_PUBCOMP ? "MQTT_PACKET_TYPE_PUBCOMP":\
((S) == MQTT_PACKET_TYPE_SUBSCRIBE ? "MQTT_PACKET_TYPE_SUBSCRIBE":\
((S) == MQTT_PACKET_TYPE_SUBACK ? "MQTT_PACKET_TYPE_SUBACK":\
((S) == MQTT_PACKET_TYPE_UNSUBSCRIBE ? "MQTT_PACKET_TYPE_UNSUBSCRIBE":\
((S) == MQTT_PACKET_TYPE_UNSUBACK ? "MQTT_PACKET_TYPE_UNSUBACK":\
((S) == MQTT_PACKET_TYPE_PINGREQ ? "MQTT_PACKET_TYPE_PINGREQ":\
((S) == MQTT_PACKET_TYPE_DISCONNECT ? "MQTT_PACKET_TYPE_DISCONNECT":\
"Unknown")))))))))))))

/*-----------------------------------------------------------*/
static void eventCallback( MQTTContext_t * pMqttContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo )
{
    uint16_t packetIdentifier;

    assert( pMqttContext != NULL );
    assert( pPacketInfo != NULL );
    assert( pDeserializedInfo != NULL );

    /* Suppress unused parameter warning when asserts are disabled in build. */
    ( void ) pMqttContext;

    packetIdentifier = pDeserializedInfo->packetIdentifier;

	TY_LOGD("pPacketInfo->type:0x%x(%s), packetIdentifier:%d", 
			pPacketInfo->type, MQTT_EVENT_2STR(pPacketInfo->type), packetIdentifier );

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
		/* topic filter */
		// TODO

        /* Handle incoming publish. */
        mqtt_event_data_on((tuya_mqtt_context_t*)(pMqttContext->userData), 
			pDeserializedInfo->pPublishInfo->pPayload, 
			pDeserializedInfo->pPublishInfo->payloadLength);
    }
    else
    {
        /* Handle other packets. */
        switch( pPacketInfo->type )
        {
            case MQTT_PACKET_TYPE_SUBACK:

                /* A SUBACK from the broker, containing the server response to our subscription request, has been received.
                 * It contains the status code indicating server approval/rejection for the subscription to the single topic
                 * requested. The SUBACK will be parsed to obtain the status code, and this status code will be stored in global
                 * variable globalSubAckStatus. */
                break;

            case MQTT_PACKET_TYPE_PINGRESP:

                /* Nothing to be done from application as library handles
                 * PINGRESP. */
                TY_LOGD( "PINGRESP should not be handled by the application "
                           "callback when using MQTT_ProcessLoop.\n\n" );
                break;

            case MQTT_PACKET_TYPE_PUBREC:
                TY_LOGD( "PUBREC received for packet id %u.\n\n",
                           packetIdentifier );
                /* Cleanup publish packet when a PUBREC is received. */
                // cleanupOutgoingPublishWithPacketID( packetIdentifier );
                break;

            case MQTT_PACKET_TYPE_PUBREL:

                /* Nothing to be done from application as library handles
                 * PUBREL. */
                TY_LOGD( "PUBREL received for packet id %u.\n\n",
                           packetIdentifier );
                break;

            case MQTT_PACKET_TYPE_PUBCOMP:

                /* Nothing to be done from application as library handles
                 * PUBCOMP. */
                TY_LOGD( "PUBCOMP received for packet id %u.\n\n",
                           packetIdentifier );
                break;

            case MQTT_PACKET_TYPE_PUBACK:

                /* Nothing to be done from application as library handles
                 * PUBACK. */
                TY_LOGD( "PUBACK received for packet id %u.\n\n",
                           packetIdentifier );
                break;

            /* Any other packet type is invalid. */
            default:
                TY_LOGE( "Unknown packet type received:(%02x).\n\n",
                            pPacketInfo->type );
        }
    }
}

int tuya_mqtt_init(tuya_mqtt_context_t* context, const tuya_mqtt_config_t* config)
{
	int rt = OPRT_OK;

	/* Device token signature */
	rt = tuya_mqtt_signature_tool(
			&(const tuya_meta_info_t){
				.uuid = config->uuid,
				.authkey = config->authkey,
				.devid = config->devid,
				.seckey = config->seckey,
				.localkey = config->localkey,
			},
			&context->signature);
	if (OPRT_OK != rt) {
		TY_LOGE("mqtt token sign error:%d", rt);
		return rt;
	}

	/* TLS pre init */
	rt = iot_tls_init(&context->network, config->rootCA, NULL, NULL,
						config->host, config->port, config->timeout, true);
	if (OPRT_OK != rt) {
		TY_LOGE("iot_tls_init fail:%d", rt);
		return rt;
	}

    MQTTStatus_t mqttStatus;
    MQTTFixedBuffer_t networkBuffer;
    TransportInterface_t transport;

    /* Fill in TransportInterface send and receive function pointers.
     * For this demo, TCP sockets are used to send and receive data
     * from network. Network context is SSL context for OpenSSL.*/
    transport.pNetworkContext = &context->network;
    transport.send = (TransportSend_t)iot_tls_write;
    transport.recv = (TransportRecv_t)iot_tls_read;

	/* Fill the values for network buffer. */
    networkBuffer.pBuffer = buffer;
    networkBuffer.size = NETWORK_BUFFER_SIZE;

    /* Initialize MQTT library. */
    mqttStatus = MQTT_Init( &(context->mqclient),
                            &transport,
                            system_ticks,
                            eventCallback,
                            &networkBuffer,
							context );

    if( mqttStatus != MQTTSuccess ) {
        TY_LOGE( "MQTT init failed: Status = %s.", MQTT_Status_strerror( mqttStatus ) );
		iot_tls_destroy(&context->network);
		// TODO new error code
		return OPRT_COM_ERROR;
    }
	
	// rand
    context->sequence_out = rand() & 0xffff;
	context->sequence_in = -1;
	return OPRT_OK;
}

int tuya_mqtt_start(tuya_mqtt_context_t* context)
{
	int rt = OPRT_OK;
	TY_LOGI("clientid:%s", context->signature.clientid);
	TY_LOGI("username:%s", context->signature.username);
	TY_LOGD("password:%s", context->signature.password);
	TY_LOGI("topic_in:%s", context->signature.topic_in);
	TY_LOGI("topic_out:%s", context->signature.topic_out);
	TY_LOGI("tuya_mqtt_start...");
	context->manual_disconnect = false;
	context->state = MQTT_STATE_TLS_CONNECTING;
	return rt;
}

int tuya_mqtt_stop(tuya_mqtt_context_t* context)
{
	MQTTStatus_t mqttStatus;
	mqttStatus = MQTT_Unsubscribe(&context->mqclient,
								&(const MQTTSubscribeInfo_t){
									.qos = MQTTQoS1,
									.pTopicFilter = context->signature.topic_in,
									.topicFilterLength = strlen(context->signature.topic_in)
								},
								1,
								MQTT_GetPacketId( &context->mqclient ) );
	if (MQTTSuccess != mqttStatus) {
		TY_LOGE("MQTT unsubscribe fail");
	}
	TY_LOGD("MQTT unsubscribe");

	mqttStatus = MQTT_Disconnect(&context->mqclient);
	if (MQTTSuccess != mqttStatus) {
		TY_LOGE("MQTT disconnect fail");
	}
	TY_LOGD("MQTT disconnect.");

	context->manual_disconnect = true;
	context->state = MQTT_STATE_STOP;
	return OPRT_OK;
}

int tuya_mqtt_reconnect(tuya_mqtt_context_t* context)
{
	int rt = OPRT_OK;

	rt = context->network.disconnect(&context->network);
	if (OPRT_OK != rt) {
		TY_LOGE("disconnect error:%d", rt);
		return rt;
	}

	TY_LOGI("TLS Connecting...");
	context->state = MQTT_STATE_TLS_CONNECTING;

	return rt;
}

void tuya_mqtt_protocol_register(tuya_mqtt_context_t* context, uint16_t protocol_id, tuya_mqtt_protocol_cb_t cb, void* user_data)
{
	int i = 0;
    for (; i < context->handle_num; i++) {
		if (context->protocol_handle[i].id == protocol_id) {
			break;
		}
	}
	context->protocol_handle[i].id = protocol_id;
	context->protocol_handle[i].cb = cb;
	context->protocol_handle[i].user_data = user_data;
	context->handle_num = i + 1;
}

int tuya_mqtt_report_data(tuya_mqtt_context_t* context, uint16_t protocol_id, uint8_t* data, uint16_t length)
{
	int rt = OPRT_OK;
	char* json_buffer = (char*)system_malloc(MQTT_FMT_MAX + length + 16);
	if (NULL == json_buffer) {
		TY_LOGE("encrypto_buffer malloc fail");
		return OPRT_MALLOC_FAILED;
	}

	size_t encrpyt_len = 0;
	uint8_t* buffer = system_malloc(TUYA_MQTT_DATA_OFFSET + MQTT_FMT_MAX + length + 16);
	if (NULL == buffer) {
		TY_LOGE("buffer malloc fail");
		system_free(json_buffer);
		return OPRT_MALLOC_FAILED;
	}

	int printlen = sprintf(json_buffer, MQTT_REPORT_FMT, protocol_id, system_timestamp(), (char*)data);
	TY_LOGD("%s", json_buffer);

	// data
	uint8_t* encrypt_buffer = NULL;
	rt = aes128_ecb_encode((const uint8_t*)json_buffer, printlen, 
		&encrypt_buffer, (uint32_t*)&encrpyt_len, (const uint8_t*)context->signature.cipherkey);
	system_free(json_buffer);
	if (OPRT_OK != rt) {
		TY_LOGE("encrypt fail:%d", rt);
		system_free(buffer);
		return OPRT_COM_ERROR;
	}
	TY_LOGD("printlen:%d, encryptlen:%d", printlen, (int)encrpyt_len);

	// buffer copy
	memcpy(buffer + TUYA_MQTT_DATA_OFFSET, encrypt_buffer, encrpyt_len);
	system_free(encrypt_buffer);

	// verison
	memcpy(buffer, "2.2", TUYA_MQTT_VER_LEN);

	// squence
	uint32_t sequence_out = context->sequence_out++;
	TY_LOGD("sequence out:%d", sequence_out);
#if BYTE_ORDER == LITTLE_ENDIAN
	sequence_out = DWORD_SWAP(sequence_out);
#endif
	memcpy(buffer + TUYA_MQTT_SEQUENCE_OFFSET, &sequence_out, TUYA_MQTT_SEQUENCE_LEN);

	// source
	uint8_t source_num[4] = {0x00, 0x00, 0x00, 0x01};
	memcpy(buffer + TUYA_MQTT_SOURCE_OFFSET, source_num, TUYA_MQTT_SOURCE_LEN);

	// crc32 calculate
	uint32_t crc32_value = crc_32(buffer + TUYA_MQTT_SEQUENCE_OFFSET, 
		TUYA_MQTT_SEQUENCE_LEN + TUYA_MQTT_SOURCE_LEN + encrpyt_len);

#if BYTE_ORDER == LITTLE_ENDIAN
	crc32_value = DWORD_SWAP(crc32_value);
#endif
	memcpy(buffer + TUYA_MQTT_CRC32_OFFSET, &crc32_value, TUYA_MQTT_CRC32_LEN);

	// report
	MQTTStatus_t mqttStatus = MQTT_Publish( &context->mqclient,
								&(const MQTTPublishInfo_t){
									.qos = MQTTQoS1,
									.pTopicName = context->signature.topic_out,
									.topicNameLength = strlen(context->signature.topic_out),
									.pPayload = buffer,
									.payloadLength = TUYA_MQTT_DATA_OFFSET + encrpyt_len
								},
								MQTT_GetPacketId( &context->mqclient ));
	system_free(buffer);
	if (MQTTSuccess != mqttStatus) {
		// TODO add error code
		rt = OPRT_COM_ERROR;
	} else {
		rt = OPRT_OK;
	}
	return rt;
}

int tuya_mqtt_loop(tuya_mqtt_context_t* context)
{
	int rt = OPRT_OK;
	MQTTStatus_t mqttStatus;

	switch (context->state) {
		case MQTT_STATE_INIT:
			context->state = MQTT_STATE_IDLE;
			break;

		case MQTT_STATE_IDLE:
			break;
		
		case MQTT_STATE_TLS_CONNECTING:
			rt = context->network.connect(&context->network, NULL);
			if (OPRT_OK == rt) {

			} else {
				context->network.disconnect(&context->network);
			}

			if (rt == 1) {
				context->state = MQTT_STATE_CONNECTING;
			} else if ( rt != 0) {
				/* reset tls connect */
				rt = context->network.disconnect(&context->network);
			}

			TY_LOGD("MQTT connected.");
			context->state = MQTT_STATE_CONNECTING;
			break;

		case MQTT_STATE_CONNECTING: {
			TY_LOGI("MQTT Connecting...");
			bool pSessionPresent = false;
			
			/* Send MQTT CONNECT packet to broker. */
    		mqttStatus = MQTT_Connect( &context->mqclient,
				&(const MQTTConnectInfo_t){
					.cleanSession = true,
					.keepAliveSeconds = MQTT_KEEPALIVE_INTERVALIN,
					.pClientIdentifier = context->signature.clientid,
					.clientIdentifierLength = strlen(context->signature.clientid),
					.pUserName = context->signature.username,
					.userNameLength = strlen(context->signature.username),
					.pPassword = context->signature.password,
					.passwordLength = strlen(context->signature.password)
				}, 
				NULL, 
				CONNACK_RECV_TIMEOUT_MS, 
				&pSessionPresent );
			if (MQTTSuccess != mqttStatus) {
				TY_LOGE("mqtt connect err: %d", mqttStatus);
				tuya_mqtt_reconnect(context);
				break;
			}
			context->state = MQTT_STATE_CONNECTED;
			break;
		}

		case MQTT_STATE_CONNECTED:{
			mqttStatus = MQTT_Subscribe( &context->mqclient,
										&(const MQTTSubscribeInfo_t){
											.qos = MQTTQoS1,
											.pTopicFilter = context->signature.topic_in,
											.topicFilterLength = strlen(context->signature.topic_in)
										},
										1,
										MQTT_GetPacketId( &context->mqclient ) );

			if( mqttStatus != MQTTSuccess ) {
				TY_LOGE( "Failed to send SUBSCRIBE packet to broker with error = %s.",
							MQTT_Status_strerror( mqttStatus ) );
				rt = OPRT_COM_ERROR;
			}
			else {
				TY_LOGI( "SUBSCRIBE sent for topic %s to broker.\n", context->signature.topic_in );
			}

			context->state = MQTT_STATE_YIELD;
			break;
		}

		case MQTT_STATE_STOP:
			context->state = MQTT_STATE_IDLE;
			break;

		case MQTT_STATE_YIELD:
			mqttStatus = MQTT_ProcessLoop( &context->mqclient, 1000 );

			if( mqttStatus != MQTTSuccess ) {
				// TODO add error code
				TY_LOGE( "MQTT_ProcessLoop returned with status = %s.",
					MQTT_Status_strerror( mqttStatus ) );
				context->network.disconnect(&context->network);
				context->state = MQTT_STATE_TLS_CONNECTING;
			}
			break;

		default:
			break;
	}

	return rt;
}

int tuya_mqtt_destory(tuya_mqtt_context_t* context)
{
	if (context->state != MQTT_STATE_IDLE) {
		return OPRT_COM_ERROR;
	}
	return context->network.destroy(&context->network);
}

bool tuya_mqtt_connected(tuya_mqtt_context_t* context)
{
	if (context->state == MQTT_STATE_YIELD) {
		return true;
	} else {
		return false;
	}
}

int tuya_mqtt_upgrade_progress_report_v41(tuya_mqtt_context_t* context, int percent, int type)
{
    if(percent > 100) {
        TY_LOGE("input invalid:%d", percent);
        return OPRT_INVALID_PARM;
    }

    uint8_t *data_buf = system_malloc(128);
    if(NULL == data_buf) {
        return OPRT_MALLOC_FAILED;
    }

    INT_T offset = 0;
    offset = sprintf((char*)data_buf,"{\"progress\":\"%d\",\"firmwareType\":%d}", percent, type);

    int ret = 0;
	ret = tuya_mqtt_report_data(context, PRO_UPGE_PUSH, data_buf, offset);
    system_free(data_buf);
    return ret;
}
