#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "tuya_log.h"
#include "tuya_error_code.h"
#include "system_interface.h"
#include "mqtt_client_interface.h"

#include "tuyalink_core.h"
#include "cipher_wrapper.h"
#include "core_json.h"

const char tylink_suffix_map[][48] = {
	"thing/model/get",
	"thing/model/get_response",
	"thing/property/report",
	"thing/property/report_response",
	"thing/property/set",
	"thing/property/set_response",
	"thing/property/desired/get",
	"thing/property/desired/get_response",
	"thing/property/desired/delete",
	"thing/property/desired/delete_response",
	"thing/event/trigger",
	"thing/event/trigger_response",
	"thing/action/execute",
	"thing/action/execute_response",
	"thing/data/batch_report",
	"thing/data/batch_report_response",
	"device/sub/bind",
	"device/sub/bind_response",
	"device/sub/login",
	"device/sub/logout",
	"device/topo/add",
	"device/topo/add_response",
	"device/topo/delete",
	"device/topo/delete_response",
	"device/topo/get",
	"device/topo/get_response",
};

enum {
	TUYA_STATE_UNINIT = 0,
	TUYA_STATE_IDLE,
	TUYA_STATE_CONNECTING,
	TUYA_STATE_SUBSCRIBING,
	TUYA_STATE_SUBSCRIBE_COMPLETE,
	TUYA_STATE_YIELD,
	TUYA_STATE_RECONNECT
};

/* -------------------------------------------------------------------------- */
/*                             MQTT Auth Signature                            */
/* -------------------------------------------------------------------------- */
static int hmac_sha256_once(const uint8_t* key, const uint8_t* input, size_t ilen, uint8_t* digest)
{
    return mbedtls_message_digest_hmac(MBEDTLS_MD_SHA256, key, 16, input, ilen, digest);
}

static int tuya_mqtt_auth_signature_calculate(const char* deviceId, const char* deviceSecret,
											  char* clientID, char* username, char* password)
{
    if (NULL == deviceId || NULL == deviceSecret ||
        NULL == clientID || NULL == username || NULL == password) {
        return OPRT_INVALID_PARM;
    }

    uint32_t timestamp = system_timestamp();

    /* client ID */
    sprintf(username, "%s|signMethod=hmacSha256,timestamp=%d,securemode=1,accessType=1", deviceId, timestamp);
    TY_LOGD("username:%s", username);

    /* username */
    sprintf(clientID, "tuyalink_%s", deviceId);
    TY_LOGD("clientID:%s", clientID);

    /* password */
    int i = 0;
    char passward_stuff[255];
    uint8_t digest[32];
    size_t slen = sprintf(passward_stuff, "deviceId=%s,timestamp=%d,secureMode=1,accessType=1", deviceId, timestamp);
    hmac_sha256_once(deviceSecret, passward_stuff, slen, digest);
    for (i = 0; i < 32; i++) {
        sprintf(password + 2*i, "%02x", digest[i]);
    }
    TY_LOGD("password:%s", password);

    return OPRT_OK;
}

/* -------------------------------------------------------------------------- */
/*                                String tools                                */
/* -------------------------------------------------------------------------- */
char *string_strdup(char *src)
{
    char *str;
    char *p;
    int len = 0;

    while (src[len])
        len++;
    str = malloc(len + 1);
    p = str;
    while (*src)
        *p++ = *src++;
    *p = '\0';
    return str;
}

int string_find_count(const char *str, char c)
{
	int count = 0;
	char* s = (char*)str;
	if (str == NULL || c == '\0') {
		return -1;
	}
	while (*s) {
		if (*s++ == c) {
			count++;
		}
	}
	return count;
}

int string_find(const char *str, char c, int index)
{
	int count = 0;
	char* s = (char*)str;
	if (str == NULL || c == '\0') {
		return -1;
	}
	while (*s) {
		if (*s++ == c) {
			if (count++ == index) {
				return s - str - 1;
			}
		}
	}
	return -1;
}

tuyalink_thing_type_t thing_type_match(const char* thing, uint8_t length)
{
	int i = 0;
	for (; i < THING_TYPE_MAX; i++) {
		if (strncmp(tylink_suffix_map[i], thing, length) == 0) {
			return (tuyalink_thing_type_t)i;
		}
	}
	return THING_TYPE_UNKNOWN;
}
/* -------------------------------------------------------------------------- */
/*                          Subscribe message handle                          */
/* -------------------------------------------------------------------------- */
int tuya_mqtt_subscribe_message_callback_register(tuya_mqtt_context_t* context,
												  const char* topic,
												  mqtt_subscribe_message_cb_t cb,
												  void* userdata)
{
	if (!context || !topic) {
		return OPRT_INVALID_PARM;
	}

	if (context->auto_subscribe_enabled == false) {
		uint16_t msgid = mqtt_client_subscribe(context->mqtt_client, topic, MQTT_QOS_1);
		if (msgid <= 0) {
			return OPRT_COM_ERROR;
		}
	}

	/* Repetition filter */
	mqtt_subscribe_handle_t* target = context->subscribe_list;
	while (target) {
		if (!memcmp(target->topic, topic, target->topic_length) && target->cb == cb) {
			TY_LOGW("Repetition:%s", topic);
			return OPRT_OK;
		}
		target = target->next;
	}

	/* Intser new handle */
	mqtt_subscribe_handle_t* newtarget = system_calloc(1, sizeof(mqtt_subscribe_handle_t));
	if (!newtarget) {
		TY_LOGE("malloc error");
		return OPRT_MALLOC_FAILED;
	}

	newtarget->topic_length = strlen(topic);
	newtarget->topic = system_calloc(1, newtarget->topic_length + 1); //strdup
	strcpy(newtarget->topic, topic);
	newtarget->cb = cb;
	newtarget->userdata = userdata;
	/* LOCK */
	newtarget->next = context->subscribe_list;
	context->subscribe_list = newtarget;
	/* UNLOCK */
	return OPRT_OK;
}

int tuya_mqtt_subscribe_message_callback_unregister(tuya_mqtt_context_t* context, const char* topic)
{
	if (!context || !topic) {
		return OPRT_INVALID_PARM;
	}

	size_t topic_length = strlen(topic);

	/* LOCK */
	/* Remove object form list */
	mqtt_subscribe_handle_t** target = &context->subscribe_list;
	while (*target) {
		mqtt_subscribe_handle_t* entry = *target;
		if (entry->topic_length == topic_length &&\
			!memcmp(topic, entry->topic, topic_length)) {
			*target = entry->next;
			system_free(entry->topic);
			system_free(entry);
		} else {
			target = &entry->next;
		}
	}
	/* UNLOCK */

	uint16_t msgid = mqtt_client_unsubscribe(context->mqtt_client, topic, MQTT_QOS_1);
	if (msgid <= 0) {
		return OPRT_COM_ERROR;
	}

	return OPRT_OK;
}

static void mqtt_subscribe_message_distribute(tuya_mqtt_context_t* context, uint16_t msgid, const mqtt_client_message_t* msg)
{
	const char* topic = msg->topic;
	size_t topic_length = strlen(msg->topic);

	/* LOCK */
	mqtt_subscribe_handle_t* target = context->subscribe_list;
	for (; target; target = target->next) {
		if (target->topic_length == topic_length &&\
			!memcmp(topic, target->topic, target->topic_length)) {
			target->cb(msgid, msg, target->userdata);
		}
	}
	/* UNLOCK */
}

/* -------------------------------------------------------------------------- */
/*                       Tuya internal subscribe message                      */
/* -------------------------------------------------------------------------- */
int tuya_link_thing_message_parse(const char* topic, const char* payload, int payload_len, tuyalink_message_t* out)
{
	if (!topic || !payload) {
		return OPRT_INVALID_PARM;
	}

	size_t topic_length = strlen(topic);

	if (string_find_count(topic, '/') < 4) {
		TY_LOGE("topic format error!");	
		return OPRT_INVALID_PARM;
	}

	if (memcmp(topic, "tylink/", 7) != 0) {
		TY_LOGE("topic prefix error!");
		return OPRT_INVALID_PARM;
	}

	/* topic string split */
	uint8_t devid_offset = string_find(topic, '/', 0);
	uint8_t thing_offset = string_find(topic, '/', 1);

	/* device id */
	uint8_t devid_length = thing_offset - devid_offset - 1;
	char* devid = (char*)topic + devid_offset + 1;
	out->device_id = system_malloc(devid_length + 1);
	if (!out->device_id) { TY_LOGE("system_malloc failed!"); return;}
	snprintf(out->device_id, devid_length + 1, "%.*s", devid_length, devid);
	TY_LOGV("device id:%s", out->device_id);

	/* thing */
	uint8_t thing_length = topic_length - thing_offset - 1;
	char* thing = (char*)topic + thing_offset + 1;
	TY_LOGV("thing:%s", out->device_id);

	/* type */
	out->type = thing_type_match(thing, thing_length);
	TY_LOGV("type:%s", THING_TYPE_ID2STR(out->type));

	/* payload parse */
	JSONStatus_t result;
    char* value;
    size_t value_length;
	result = JSON_Validate((const char*)payload, payload_len);
    if( result != JSONSuccess ) {
        TY_LOGE("JSON_Validate error");
		system_free(out->device_id);
        return OPRT_CJSON_PARSE_ERR;
    }

	/* code */
    result = JSON_Search((char*)payload, payload_len, "code", sizeof("code") - 1, &value, &value_length);
    if( result == JSONSuccess ) {
		out->code = atoi(value);
		TY_LOGV("code:%d", out->code);
    }

	/* message id */
	result = JSON_Search((char*)payload, payload_len, "msgId", sizeof("msgId") - 1, &value, &value_length);
	if( result == JSONSuccess ) {
		out->msgid = system_malloc(value_length + 1);
		if (!out->msgid) {
			TY_LOGE("system_malloc failed!");
			system_free(out->device_id);
			return OPRT_MALLOC_FAILED;
		}
		memcpy(out->msgid, value, value_length);
		out->msgid[value_length] = '\0';
		TY_LOGV("msgid:%s", out->msgid);
	}

	/* time */
	result = JSON_Search((char*)payload, payload_len, "time", sizeof("time") - 1, &value, &value_length);
    if( result == JSONSuccess ) {
		out->time = atoi(value);
		TY_LOGV("time:%d", out->time);
    }

	/* data */
	result = JSON_Search((char*)payload, payload_len, "data", sizeof("data") - 1, &value, &value_length);
	if( result == JSONSuccess ) {
		out->data_string = system_malloc(value_length + 1);
		if (!out->data_string) {
			TY_LOGE("system_malloc failed!");
			system_free(out->device_id);
			system_free(out->msgid);
			return OPRT_MALLOC_FAILED;
		}
		memcpy(out->data_string, value, value_length);
		out->data_string[value_length] = '\0';
	}

	return OPRT_OK;
}

/* -------------------------------------------------------------------------- */
/*                         MQTT Client event callback                         */
/* -------------------------------------------------------------------------- */
static void mqtt_client_connected_cb(void* client, void* userdata)
{
	client = client;
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;
	TY_LOGI("mqtt client connected!");
	
	/* Auto subscribe */
	char auto_subscribe_topic[64];
	sprintf(auto_subscribe_topic, "tylink/%s/channel/downlink/auto_subscribe", context->config.device_id);
	context->auto_subscribe_id = mqtt_client_subscribe(client, auto_subscribe_topic, MQTT_QOS_1);
}

static void mqtt_client_disconnected_cb(void* client, void* userdata)
{
	client = client;
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;
	TY_LOGI("mqtt client disconnected!");
	context->auto_subscribe_enabled = false;
	context->is_connected = false;
	if (context->config.on_disconnect) {
		context->config.on_disconnect(context, context->user_data);
	}

	if (context->manual_disconnect == false) {
		context->state = TUYA_STATE_CONNECTING;
	}
}

static void mqtt_client_message_cb(void* client, uint16_t msgid, const mqtt_client_message_t* msg, void* userdata)
{
	client = client;
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;

	/* topic filter */
	int topic_len = strlen(msg->topic);
	TY_LOGD("\r\nrecv message TopicName:%s, payload len:%d", msg->topic, msg->length);
	TY_LOGD("payload:%.*s", msg->length, msg->payload);
	mqtt_subscribe_message_distribute(context, msgid, msg);

	/* IoT core message parse */
	tuyalink_message_t out_message;
	memset(&out_message, 0, sizeof(tuyalink_message_t));
	tuya_link_thing_message_parse(msg->topic, msg->payload, msg->length, &out_message);

	/* message callback */
	if (context->config.on_messages) {
		context->config.on_messages(context, context->user_data, &out_message);
	}

	if (out_message.device_id) {
		system_free(out_message.device_id);
	}
	if (out_message.msgid) {
		system_free(out_message.msgid);
	}
	if (out_message.data_string) {
		system_free(out_message.data_string);
	}
}

static void mqtt_client_subscribed_cb(void* client, uint16_t msgid, void* userdata)
{
	client = client;
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;

	TY_LOGD("Subscribe successed ID:%d", msgid);
	if (msgid == context->auto_subscribe_id) {
		context->auto_subscribe_id = 0;
		context->auto_subscribe_enabled = true;
		TY_LOGI("auto subscribe enable.");
		context->state = TUYA_STATE_SUBSCRIBE_COMPLETE;
	}
}

static void mqtt_client_puback_cb(void* client, uint16_t msgid, void* userdata)
{
	client = client;
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;
	TY_LOGD("PUBACK ID:%d", msgid);
}

/* -------------------------------------------------------------------------- */
/*                                Tuya MQTT API                               */
/* -------------------------------------------------------------------------- */
int tuya_mqtt_init(tuya_mqtt_context_t* context, const tuya_mqtt_config_t* config)
{
	int rt = OPRT_OK;
    mqtt_client_status_t mqtt_status;

	/* Clean to zero */
	memset(context, 0, sizeof(tuya_mqtt_context_t));

	/* configuration */
	context->config = *config;

	/* Device token signature */
	rt = tuya_mqtt_auth_signature_calculate(config->device_id, config->device_secret,
		context->mqtt_auth.clientid, context->mqtt_auth.username, context->mqtt_auth.password);
	if (OPRT_OK != rt) {
		TY_LOGE("mqtt token sign error:%d", rt);
		return rt;
	}

	/* MQTT Client object new */
	context->mqtt_client = mqtt_client_new();
	if (context->mqtt_client == NULL) {
		TY_LOGE("mqtt client new fault.");
		return OPRT_MALLOC_FAILED;
	}

	/* MQTT Client init */
	const mqtt_client_config_t mqtt_config = {
		.cacert = config->cacert,
		.cacert_len = config->cacert_len,
		.host = config->host,
		.port = config->port,
		.keepalive = config->keepalive,
		.timeout_ms = config->timeout_ms,
		.clientid = context->mqtt_auth.clientid,
		.username = context->mqtt_auth.username,
		.password = context->mqtt_auth.password,
		.on_connected = mqtt_client_connected_cb,
		.on_disconnected = mqtt_client_disconnected_cb,
		.on_message = mqtt_client_message_cb,
		.on_subscribed = mqtt_client_subscribed_cb,
		.on_published = mqtt_client_puback_cb,
		.userdata = context
	};
	mqtt_status = mqtt_client_init(context->mqtt_client, &mqtt_config);
    if( mqtt_status != MQTT_STATUS_SUCCESS ) {
        TY_LOGE( "MQTT init failed: Status = %d.", mqtt_status);
		return OPRT_COM_ERROR;
    }

	/* Wait start task */
	context->manual_disconnect = true;
	context->state = TUYA_STATE_IDLE;
	return OPRT_OK;
}

int tuya_mqtt_connect(tuya_mqtt_context_t* context)
{
	if (context == NULL || context->state == TUYA_STATE_UNINIT) {
		return OPRT_INVALID_PARM;
	}
	mqtt_client_status_t mqtt_status;

	TY_LOGI("Start tuya mqtt connect...");
	context->manual_disconnect = false;
	mqtt_status = mqtt_client_connect(context->mqtt_client);
	if (mqtt_status != MQTT_STATUS_SUCCESS) {
		TY_LOGE("MQTT connect failed: Status = %d.", mqtt_status);
		return OPRT_LINK_CORE_MQTT_CONNECT_ERROR;
	}
	context->state = TUYA_STATE_SUBSCRIBING;
	return OPRT_OK;
}

int tuya_mqtt_disconnect(tuya_mqtt_context_t* context)
{
	if (context == NULL || context->state == TUYA_STATE_UNINIT) {
		return OPRT_INVALID_PARM;
	}

	mqtt_client_status_t mqtt_status;
	mqtt_status = mqtt_client_disconnect(context->mqtt_client);
	TY_LOGD("MQTT disconnect result:%d", mqtt_status);
	context->manual_disconnect = true;
	return OPRT_OK;
}

int tuya_state_mqtt_yield(tuya_mqtt_context_t* context)
{
	if (context == NULL) {
		return OPRT_COM_ERROR;
	}
	mqtt_client_yield(context->mqtt_client);
	return OPRT_OK;
}

int tuya_mqtt_loop(tuya_mqtt_context_t* context)
{
	if (context == NULL) {
		return OPRT_INVALID_PARM;
	}

	int ret = OPRT_OK;

	switch (context->state) {
	case TUYA_STATE_IDLE:
		break;
	
	case TUYA_STATE_CONNECTING:
		if( mqtt_client_connect(context->mqtt_client) == MQTT_STATUS_SUCCESS ) {
			context->state = TUYA_STATE_SUBSCRIBING;
			break;
		}
		system_sleep(1000);
		break;

	case TUYA_STATE_SUBSCRIBING:
		mqtt_client_yield(context->mqtt_client);
		break;

	case TUYA_STATE_SUBSCRIBE_COMPLETE:
		/* 实际以自动订阅成功作为连接成功的标志 */
		context->is_connected = true;
		if (context->config.on_connected) {
			context->config.on_connected(context, context->user_data);
		}
		context->state = TUYA_STATE_YIELD;
		break;

	case TUYA_STATE_YIELD:
		ret = tuya_state_mqtt_yield(context);
		break;

	case TUYA_STATE_RECONNECT:
		mqtt_client_disconnect(context->mqtt_client);
		context->state = TUYA_STATE_CONNECTING;
		break;
	}

	return ret;
}

int tuya_mqtt_deinit(tuya_mqtt_context_t* context)
{
	if (context == NULL || context->state == TUYA_STATE_UNINIT) {
		return OPRT_COM_ERROR;
	}

	mqtt_client_status_t mqtt_status = mqtt_client_deinit(context->mqtt_client);
	mqtt_client_free(context->mqtt_client);
	if (mqtt_status != MQTT_STATUS_SUCCESS) {
		return OPRT_COM_ERROR;
	}

	return OPRT_OK;
}

bool tuya_mqtt_connected(tuya_mqtt_context_t* context)
{
	if (context == NULL || context->state == TUYA_STATE_UNINIT) {
		return false;
	}
	return context->is_connected;
}

/* -------------------------------------------------------------------------- */
/*                                  IOT CORE                                  */
/* -------------------------------------------------------------------------- */
static uint32_t thing_send_msgid_get(tuya_mqtt_context_t* context)
{
	return context->msgid_inc++;
}

int tuyalink_message_send(tuya_mqtt_context_t* context, tuyalink_message_t* message)
{
	if (context == NULL || message == NULL) {
		return OPRT_INVALID_PARM;
	}

	/* Device ID */
	char* device_id = (char*)(message->device_id ? message->device_id : context->config.device_id);

	/* Topic */
	#define TOPIC_LEN_MAX (128)
	char topic_stuff[TOPIC_LEN_MAX];
	snprintf(topic_stuff, TOPIC_LEN_MAX, "tylink/%s/%s", device_id, tylink_suffix_map[message->type]);

	/* Make payload */
	size_t payload_length = 0;
	uint32_t msgid_int = 0;
	size_t alloc_size = 128;
	if (message->data_string) {
		alloc_size += strlen(message->data_string);
	}
	char* payload = system_malloc(alloc_size);
	if (payload == NULL) {
		return OPRT_MALLOC_FAILED;
	}

	/* JSON start  */
	payload_length = snprintf(payload, alloc_size, "{");

	/* msgId */
	if (message->msgid && message->msgid[0] != 0) {
		payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
			"\"msgId\":\"%s\"", message->msgid);
	} else {
		msgid_int = thing_send_msgid_get(context);
		payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
			"\"msgId\":\"%d\"", msgid_int);
	}

	/* time */
	if (message->time) {
		payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
			",\"time\":%ld", message->time);
	} else {
		payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
			",\"time\":%d", system_timestamp());
	}

	/* data */
	if (message->data_string && message->data_string[0] != 0) {
		payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
			",\"data\":%s", message->data_string);
	}

	/* ack */
	if (message->ack) {
		payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
			",\"sys\":{\"ack\":%d}", message->ack);
	}

	/* JSON end */
	payload_length += snprintf(payload + payload_length, alloc_size - payload_length, "}");

	TY_LOGD("publish topic:%s", topic_stuff);
	TY_LOGD("payload size:%d, %s\r\n", payload_length, payload);
	uint16_t mqmsgid = mqtt_client_publish(context->mqtt_client, topic_stuff, payload, payload_length, MQTT_QOS_0);
	system_free(payload);
	if (mqmsgid <= 0) {
		return OPRT_LINK_CORE_MQTT_PUBLISH_ERROR;
	}
	return (int)msgid_int;
}

int tuyalink_thing_data_model_get(tuya_mqtt_context_t* context, const char* device_id)
{
	if(context == NULL) {
		return OPRT_INVALID_PARM;
	}	

	tuyalink_message_t message = {
		.type = THING_TYPE_MODEL_GET,
		.device_id = (char*)device_id,
		.data_string = "{\"format\":\"simple\"}"
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_thing_property_report(tuya_mqtt_context_t* context, const char* device_id, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_PROPERTY_REPORT,
		.device_id = (char*)device_id,
		.data_string = (char*)data,
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_thing_property_report_with_ack(tuya_mqtt_context_t* context, const char* device_id, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_PROPERTY_REPORT,
		.device_id = (char*)device_id,
		.data_string = (char*)data,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_thing_event_trigger(tuya_mqtt_context_t* context, const char* device_id, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_EVENT_TRIGGER,
		.device_id = (char*)device_id,
		.data_string = (char*)data,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_thing_desired_get(tuya_mqtt_context_t* context, const char* device_id, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_PROPERTY_DESIRED_GET,
		.device_id = (char*)device_id,
		.data_string = (char*)data,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_thing_batch_report(tuya_mqtt_context_t* context, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_BATCH_REPORT,
		.device_id = (char*)context->config.device_id,
		.data_string = (char*)data,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_subdevice_bind(tuya_mqtt_context_t* context, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_DEVICE_SUB_BIND,
		.device_id = (char*)context->config.device_id,
		.data_string = (char*)data,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_subdevice_bind_login(tuya_mqtt_context_t* context, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_DEVICE_SUB_LOGIN,
		.device_id = (char*)context->config.device_id,
		.data_string = (char*)data,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_subdevice_bind_logout(tuya_mqtt_context_t* context, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_DEVICE_SUB_LOGOUT,
		.device_id = (char*)context->config.device_id,
		.data_string = (char*)data,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_subdevice_topo_add(tuya_mqtt_context_t* context, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_DEVICE_TOPO_ADD,
		.device_id = (char*)context->config.device_id,
		.data_string = (char*)data,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_subdevice_topo_delete(tuya_mqtt_context_t* context, const char* data)
{
	if(context == NULL || data == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_DEVICE_TOPO_DEL,
		.device_id = (char*)context->config.device_id,
		.data_string = (char*)data,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}

int tuyalink_subdevice_topo_get(tuya_mqtt_context_t* context)
{
	if(context == NULL) {
		return OPRT_INVALID_PARM;
	}

	tuyalink_message_t message = {
		.type = THING_TYPE_DEVICE_TOPO_GET,
		.device_id = (char*)context->config.device_id,
		.ack = true
	};
	return tuyalink_message_send(context, &message);
}