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
#define TUYA_MQTT_VER_LEN 3
#define TUYA_MQTT_CRC32_LEN 4
#define TUYA_MQTT_SEQUENCE_LEN 4
#define TUYA_MQTT_SOURCE_LEN 4
#define TUYA_MQTT_CRC32_OFFSET (0 + TUYA_MQTT_VER_LEN)
#define TUYA_MQTT_SEQUENCE_OFFSET (TUYA_MQTT_CRC32_OFFSET + TUYA_MQTT_CRC32_LEN)
#define TUYA_MQTT_SOURCE_OFFSET (TUYA_MQTT_SEQUENCE_OFFSET + TUYA_MQTT_SEQUENCE_LEN)
#define TUYA_MQTT_DATA_OFFSET (TUYA_MQTT_SOURCE_OFFSET + TUYA_MQTT_SOURCE_LEN)
#define MQTT_REPORT_FMT "{\"protocol\":%d,\"t\":%d,\"data\":%s}"
#define MQTT_FMT_MAX (64)

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

	int rt = OPRT_OK;
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
	if (MQTT_STATUS_SUCCESS != mqtt_status) {
		TY_LOGE("MQTT unsubscribe fail");
	}
	TY_LOGD("MQTT unsubscribe");

	mqtt_status = mqtt_client_disconnect(context->mqttctx);
	if (MQTT_STATUS_SUCCESS != mqtt_status) {
		TY_LOGE("MQTT disconnect fail");
	}
	TY_LOGD("MQTT disconnect.");

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

	int rt = OPRT_OK;
	char* json_buffer = (char*)system_malloc(MQTT_FMT_MAX + length + 16);
	if (NULL == json_buffer) {
		TY_LOGE("encrypto_buffer malloc fail");
		return OPRT_MALLOC_FAILED;
	}

	size_t encrpyt_len = 0;
	size_t buffer_len;
	uint8_t* buffer = system_malloc(TUYA_MQTT_DATA_OFFSET + MQTT_FMT_MAX + length + 16);
	if (NULL == buffer) {
		TY_LOGE("buffer malloc fail");
		system_free(json_buffer);
		return OPRT_MALLOC_FAILED;
	}

	int printlen = sprintf(json_buffer, MQTT_REPORT_FMT, protocol_id, system_timestamp(), (char*)data);
	TY_LOGD("Report data:%s", json_buffer);

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
	TY_LOGV("printlen:%d, encryptlen:%d", printlen, (int)encrpyt_len);

	// buffer copy
	memcpy(buffer + TUYA_MQTT_DATA_OFFSET, encrypt_buffer, encrpyt_len);
	system_free(encrypt_buffer);

	// verison
	memcpy(buffer, "2.2", TUYA_MQTT_VER_LEN);

	// squence
	uint32_t sequence_out = context->sequence_out++;
	TY_LOGV("sequence out:%d", sequence_out);
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
	buffer_len = TUYA_MQTT_DATA_OFFSET + encrpyt_len;

	// report
	uint16_t msgid = mqtt_client_publish( context->mqttctx, 
										  context->signature.topic_out, 
										  buffer, 
										  buffer_len, 
										  MQTT_QOS_1);
	system_free(buffer);
	if (0 == msgid) {
		return OPRT_COM_ERROR;
	}
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
