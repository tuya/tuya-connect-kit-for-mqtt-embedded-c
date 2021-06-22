#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "tuya_config_defaults.h"
#include "tuya_log.h"
#include "tuya_error_code.h"
#include "system_interface.h"
#include "mqtt_client_interface.h"

#include "cJSON.h"
#include "crc32.h"
#include "uni_md5.h"
#include "aes_inf.h"
#include "mqtt_service.h"

// mqtt message package
#define PV22_VER_LENGTH 3
#define PV22_CRC32_LENGTH 4
#define PV22_SEQUENCE_LENGTH 4
#define PV22_SOURCE_LENGTH 4

#define PV22_CRC32_OFFSET (0 + PV22_VER_LENGTH)
#define PV22_SEQUENCE_OFFSET (PV22_CRC32_OFFSET + PV22_CRC32_LENGTH)
#define PV22_SOURCE_OFFSET (PV22_SEQUENCE_OFFSET + PV22_SEQUENCE_LENGTH)
#define PV22_FIXED_HEADER_LENGTH (15)

#define MQTT_REPORT_FMT "{\"protocol\":%d,\"t\":%d,\"data\":%s}"
#define MQTT_FMT_MAX (64)

typedef struct {
	uint32_t sequence;
	uint32_t source;
	size_t   datalen; 
	uint8_t  data[0];
} pv22_packet_object_t;

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

static int pv22_packet_encode(const uint8_t* key, const pv22_packet_object_t* input, uint8_t* output, size_t* olen)
{
	int rt = OPRT_OK;

	// data
	size_t encrypt_len = 0;
	uint8_t* encrypt_data;
	// rt = aes128_ecb_encode((const uint8_t*)input->data, input->datalen, (uint8_t*)(output + PV22_FIXED_HEADER_LENGTH), (uint32_t*)&encrypt_len, key);
	rt = aes128_ecb_encode((const uint8_t*)input->data, input->datalen, &encrypt_data, (uint32_t*)&encrypt_len, key);
	if (OPRT_OK != rt) {
		TY_LOGE("encrypt fail:%d", rt);
		return OPRT_COM_ERROR;
	}
	memcpy(output + PV22_FIXED_HEADER_LENGTH, encrypt_data, encrypt_len);
	system_free(encrypt_data);

	// verison
	memcpy(output, "2.2", PV22_VER_LENGTH);

	// squence
	uint32_t sequence_out = input->sequence;
#if BYTE_ORDER == LITTLE_ENDIAN
	sequence_out = DWORD_SWAP(sequence_out);
#endif
	memcpy(output + PV22_SEQUENCE_OFFSET, &sequence_out, PV22_SEQUENCE_LENGTH);
	memcpy(output + PV22_SOURCE_OFFSET, &input->source, PV22_SOURCE_LENGTH);

	// crc32 calculate
	uint32_t crc32_value = crc_32(output + PV22_SEQUENCE_OFFSET, PV22_SEQUENCE_LENGTH + PV22_SOURCE_LENGTH + encrypt_len);
#if BYTE_ORDER == LITTLE_ENDIAN
	crc32_value = DWORD_SWAP(crc32_value);
#endif
	memcpy(output + PV22_CRC32_OFFSET, &crc32_value, PV22_CRC32_LENGTH);
	*olen = PV22_FIXED_HEADER_LENGTH + encrypt_len;
	return OPRT_OK;
}

static int pv22_packet_decode(const uint8_t* key, const uint8_t* input, size_t ilen, pv22_packet_object_t* output)
{
	/* package length check */
	if (ilen < PV22_FIXED_HEADER_LENGTH) {
		TY_LOGE("len too short");
		return;
	}

	/* unpack tuya protocol 2.2 */
	/* verison filter */
	if (memcmp(input, "2.2", PV22_VER_LENGTH) != 0) {
		TY_LOGE("verison error:%.*s", PV22_VER_LENGTH, input);
		return OPRT_COM_ERROR;
	}

	uint32_t crc32, sequence, source;
	memcpy(&crc32, input + PV22_CRC32_OFFSET, PV22_CRC32_LENGTH);
	memcpy(&sequence, input + PV22_SEQUENCE_OFFSET, PV22_SEQUENCE_LENGTH);
	memcpy(&source, input + PV22_SOURCE_OFFSET, PV22_SOURCE_LENGTH);

#if BYTE_ORDER == LITTLE_ENDIAN
	sequence = DWORD_SWAP(sequence);
	source = DWORD_SWAP(source);
#endif
	output->sequence = sequence;
	output->source = source;
	TY_LOGD("crc32:%08x, sequence:%d, source:%d", crc32, sequence, source);

	/* get encrypt data */
	uint8_t* data = (uint8_t*)input + PV22_FIXED_HEADER_LENGTH;
	size_t data_len = (size_t)(ilen - PV22_FIXED_HEADER_LENGTH);
	TY_LOGD("data len:%d", (int)data_len);

	// decrypt buffer
	uint8_t* decrypt_data;
	size_t decrypt_len = 0;
	// int rt = aes128_ecb_decode((const uint8_t*)data, data_len, &output->data, (uint32_t*)&output->datalen, key);
	int rt = aes128_ecb_decode((const uint8_t*)data, data_len, &decrypt_data, (uint32_t*)&decrypt_len, key);
	if (OPRT_OK != rt) {
		TY_LOGE("mqtt data decrypt fail:%d", rt);
		return OPRT_COM_ERROR;
	}
	memcpy(output->data, decrypt_data, decrypt_len);
	output->datalen = decrypt_len;
	system_free(decrypt_data);
	
	return OPRT_OK;
}

static int mqtt_event_data_on(tuya_mqtt_context_t* context, const uint8_t* payload, size_t payload_len)
{
	int ret = OPRT_OK;
	int i;

	pv22_packet_object_t* packet = system_malloc(payload_len);
	if (!packet) {
		TY_LOGE("packet malloc fail.");
		return OPRT_MALLOC_FAILED;
	}
	
	ret = pv22_packet_decode((const uint8_t*)context->signature.cipherkey, payload, payload_len, packet);
	if (ret != OPRT_OK) {
		TY_LOGE("packet decode fail.");
		system_free(packet);
		return OPRT_COM_ERROR;
	}
	
	// json parse
	cJSON *root = NULL;
    cJSON *json = NULL;
    root = cJSON_Parse((const char *)packet->data);
	system_free(packet);
    if(NULL == root) {
        TY_LOGE("JSON parse error");
		return OPRT_CJSON_PARSE_ERR;
    }

	/* JSON key verfiy */
    if(( NULL == cJSON_GetObjectItem(root,"protocol")) || \
       ( NULL == cJSON_GetObjectItem(root,"t")) || \
       ( NULL == cJSON_GetObjectItem(root,"data"))) {
        TY_LOGE("param is no correct");
		cJSON_Delete(root);
		return OPRT_CJSON_GET_ERR;
    }

    // protocol
    int protocol_id = cJSON_GetObjectItem(root,"protocol")->valueint;
    json = cJSON_GetObjectItem(root,"data");
    if(NULL == json) {
        TY_LOGE("get json err");
		cJSON_Delete(root);
        return OPRT_CJSON_GET_ERR;
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

	cJSON_Delete(root);
	return OPRT_OK;
}

static void mqtt_client_connected_cb(void* client, void* userdata)
{
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;
	TY_LOGD("mqtt client connected!");

	uint16_t msgid = mqtt_client_subscribe(client, context->signature.topic_in, MQTT_QOS_1);
	TY_LOGD("SUBSCRIBE id:%d sent for topic %s to broker.", msgid, context->signature.topic_in);
	context->is_connected = true;
}

static void mqtt_client_disconnected_cb(void* client, void* userdata)
{
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;
	TY_LOGD("mqtt client disconnected!");
	context->is_connected = false;

	if (context->manual_disconnect == true) {
		return;
	}

	/* reconnect */
	mqtt_client_connect(context->mqttctx);
}

static void mqtt_client_message_cb(void* client, uint16_t msgid, const mqtt_client_message_t* msg, void* userdata)
{
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;

	/* topic filter */
	TY_LOGD("recv message TopicName:%s, payload len:%d", msg->topic, msg->length);

	if (memcmp(msg->topic, context->signature.topic_in, strlen(msg->topic)) == 0) {
		mqtt_event_data_on(context, msg->payload, msg->length);
	}
}

int tuya_mqtt_init(tuya_mqtt_context_t* context, const tuya_mqtt_config_t* config)
{
	int rt = OPRT_OK;
    mqtt_client_status_t mqtt_status;

	/* Clean to zero */
	memset(context, 0, sizeof(tuya_mqtt_context_t));

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

	/* MQTT Client object new */
	context->mqttctx = mqtt_client_new();
	if (context->mqttctx == NULL) {
		TY_LOGE("mqtt client new fault.");
		return OPRT_MALLOC_FAILED;
	}

	/* MQTT Client init */
	const mqtt_client_config_t mqtt_config = {
		.cacert = config->cacert,
		.cacert_len = config->cacert_len,
		.host = config->host,
		.port = config->port,
		.keepalive = MQTT_KEEPALIVE_INTERVALIN,
		.timeout_ms = config->timeout,
		.clientid = context->signature.clientid,
		.username = context->signature.username,
		.password = context->signature.password,
		.on_connected = mqtt_client_connected_cb,
		.on_disconnected = mqtt_client_disconnected_cb,
		.on_message = mqtt_client_message_cb,
		.userdata = context
	};
	mqtt_status = mqtt_client_init(context->mqttctx, &mqtt_config);
    if( mqtt_status != MQTT_STATUS_SUCCESS ) {
        TY_LOGE( "MQTT init failed: Status = %d.", mqtt_status);
		return OPRT_COM_ERROR;
    }

	// rand
    context->sequence_out = rand() & 0xffff;
	context->sequence_in = -1;

	/* Wait start task */
	context->is_inited = true;
	context->manual_disconnect = true;
	return OPRT_OK;
}

int tuya_mqtt_start(tuya_mqtt_context_t* context)
{
	if (context == NULL || context->is_inited == false) {
		return OPRT_INVALID_PARM;
	}

	TY_LOGI("clientid:%s", context->signature.clientid);
	TY_LOGI("username:%s", context->signature.username);
	TY_LOGD("password:%s", context->signature.password);
	TY_LOGI("topic_in:%s", context->signature.topic_in);
	TY_LOGI("topic_out:%s",context->signature.topic_out);
	TY_LOGI("tuya_mqtt_start...");
	context->manual_disconnect = false;

	mqtt_client_status_t mqtt_status;

	mqtt_status = mqtt_client_connect(context->mqttctx);
	if (MQTT_STATUS_SUCCESS != mqtt_status) {
		TY_LOGE("MQTT connect fail:%d", mqtt_status);
		return OPRT_COM_ERROR;
	}
	return OPRT_OK;
}

int tuya_mqtt_stop(tuya_mqtt_context_t* context)
{
	if (context == NULL || context->is_inited == false) {
		return OPRT_INVALID_PARM;
	}

	mqtt_client_status_t mqtt_status;
	mqtt_status = mqtt_client_unsubscribe(context->mqttctx, context->signature.topic_in, 1);
	TY_LOGD("MQTT unsubscribe result:%d", mqtt_status);

	mqtt_status = mqtt_client_disconnect(context->mqttctx);
	TY_LOGD("MQTT disconnect result:%d", mqtt_status);

	context->manual_disconnect = true;
	return OPRT_OK;
}

int tuya_mqtt_protocol_register(tuya_mqtt_context_t* context, uint16_t protocol_id, tuya_mqtt_protocol_cb_t cb, void* user_data)
{
	if (context == NULL || context->is_inited == false) {
		return OPRT_INVALID_PARM;
	}

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
	return OPRT_OK;
}

int tuya_mqtt_report_data(tuya_mqtt_context_t* context, uint16_t protocol_id, uint8_t* data, uint16_t length)
{
	if (context == NULL || context->is_inited == false) {
		return OPRT_INVALID_PARM;
	}

	if (context->is_connected == false) {
		return OPRT_COM_ERROR;
	}

	int ret = OPRT_OK;

	pv22_packet_object_t* packet = system_malloc(PV22_FIXED_HEADER_LENGTH + MQTT_FMT_MAX + length + 16);
	if (!packet) {
		TY_LOGE("packet malloc fail.");
		return OPRT_MALLOC_FAILED;
	}

	size_t buffer_len = 0;
	uint8_t* buffer = system_malloc(PV22_FIXED_HEADER_LENGTH + MQTT_FMT_MAX + length + 16);
	if (NULL == buffer) {
		TY_LOGE("buffer malloc fail");
		system_free(buffer);
		return OPRT_MALLOC_FAILED;
	}

	packet->datalen = sprintf((char*)packet->data, MQTT_REPORT_FMT, protocol_id, system_timestamp(), (char*)data);
	TY_LOGD("Report data:%s", (char*)packet->data);

	packet->sequence = context->sequence_out++;
	packet->source = 1;

	ret = pv22_packet_encode((const uint8_t*)context->signature.cipherkey, (const pv22_packet_object_t*)packet, buffer, &buffer_len);
	system_free(packet);
	if (ret != OPRT_OK) {
		TY_LOGE("pv22_packet_encode error:%d", ret);
		system_free(buffer);
		return OPRT_COM_ERROR;
	}

	// report
	uint16_t msgid = mqtt_client_publish( context->mqttctx,
										  context->signature.topic_out,
										  buffer,
										  buffer_len,
										  MQTT_QOS_1);
	system_free(buffer);
	return msgid;
}

int tuya_mqtt_loop(tuya_mqtt_context_t* context)
{
	if (context == NULL) {
		return OPRT_COM_ERROR;
	}

	int rt = OPRT_OK;

	if (context->is_inited == false ||
		context-> manual_disconnect == true) {
		return rt;
	}

	mqtt_client_yield(context->mqttctx);

	return rt;
}

int tuya_mqtt_destory(tuya_mqtt_context_t* context)
{
	if (context == NULL || context->is_inited != false) {
		return OPRT_COM_ERROR;
	}

	mqtt_client_status_t mqtt_status = mqtt_client_deinit(context->mqttctx);
	mqtt_client_free(context->mqttctx);
	if (mqtt_status != MQTT_STATUS_SUCCESS) {
		return OPRT_COM_ERROR;
	}

	return OPRT_OK;
}

bool tuya_mqtt_connected(tuya_mqtt_context_t* context)
{
	if (context == NULL) {
		return false;
	}
	return context->is_connected;
}

int tuya_mqtt_upgrade_progress_report(tuya_mqtt_context_t* context, int channel, int percent)
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
    offset = sprintf((char*)data_buf,"{\"progress\":\"%d\",\"firmwareType\":%d}", percent, channel);

	uint16_t msgid = tuya_mqtt_report_data(context, PRO_UPGE_PUSH, data_buf, offset);
    system_free(data_buf);
	if (msgid <= 0) {
    	return OPRT_COM_ERROR;
	}
	return OPRT_OK;
}
