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

static void on_subscribe_message_default(uint16_t msgid, const mqtt_client_message_t* msg, void* userdata);

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

/* -------------------------------------------------------------------------- */
/*                              PV22 packet parse                             */
/* -------------------------------------------------------------------------- */
static int pv22_packet_encode(const uint8_t* key, const pv22_packet_object_t* input, uint8_t* output, size_t* olen)
{
	int rt = OPRT_OK;

	// data
	size_t encrypt_len = 0;
	uint8_t* encrypt_data;
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
		return OPRT_INVALID_PARM;
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

	/* get encrypt data */
	uint8_t* data = (uint8_t*)input + PV22_FIXED_HEADER_LENGTH;
	size_t data_len = (size_t)(ilen - PV22_FIXED_HEADER_LENGTH);
	TY_LOGD("crc32:%08x, sequence:%d, source:%d, datalen:%d", crc32, sequence, source, (int)data_len);

	// decrypt buffer
	uint8_t* decrypt_data;
	size_t decrypt_len = 0;
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

	uint16_t msgid = mqtt_client_subscribe(context->mqtt_client, topic, MQTT_QOS_1);
	if (msgid <= 0) {
		return OPRT_COM_ERROR;
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

	if (cb) {
		newtarget->cb = cb;
	} else {
		newtarget->cb = on_subscribe_message_default;
	}
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
static int tuya_protocol_message_parse_process(tuya_mqtt_context_t* context, const uint8_t* payload, size_t payload_len)
{
	int ret = OPRT_OK;

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
	TY_LOGV("Data JSON:%.*s", packet->datalen, packet->data);

	/* json parse */
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

    /* protocol ID */
    int protocol_id = cJSON_GetObjectItem(root,"protocol")->valueint;
    json = cJSON_GetObjectItem(root,"data");
    if(NULL == json) {
        TY_LOGE("get json err");
		cJSON_Delete(root);
        return OPRT_CJSON_GET_ERR;
    }

    /* dispatch */
	tuya_protocol_event_t event;
	event.event_id = protocol_id;
	event.data = cJSON_GetObjectItem(root, "data");

	/* LOCK */
	tuya_protocol_handle_t* target = context->protocol_list;
	for (; target; target = target->next) {
		if (target->id == protocol_id) {
			event.user_data = target->user_data,
			target->cb(&event);
		}
	}
	/* UNLOCK */

	cJSON_Delete(root);
	return OPRT_OK;
}

static void on_subscribe_message_default(uint16_t msgid, const mqtt_client_message_t* msg, void* userdata)
{
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;
	int ret = tuya_protocol_message_parse_process(context, msg->payload, msg->length);
	if(ret != OPRT_OK) {
		TY_LOGE("protocol message parse error:%d", ret);
	}
}

/* -------------------------------------------------------------------------- */
/*                         MQTT Client event callback                         */
/* -------------------------------------------------------------------------- */
static void mqtt_client_connected_cb(void* client, void* userdata)
{
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;
	TY_LOGD("mqtt client connected!");

	tuya_mqtt_subscribe_message_callback_register(context, 
											      context->signature.topic_in, 
											      on_subscribe_message_default, 
											      userdata);
	TY_LOGD("SUBSCRIBE sent for topic %s to broker.", context->signature.topic_in);
	context->is_connected = true;
	if (context->on_connected) {
		context->on_connected(context, context->user_data);
	}
}

static void mqtt_client_disconnected_cb(void* client, void* userdata)
{
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;
	TY_LOGD("mqtt client disconnected!");
	context->is_connected = false;
	if (context->on_disconnect) {
		context->on_disconnect(context, context->user_data);
	}
}

static void mqtt_client_message_cb(void* client, uint16_t msgid, const mqtt_client_message_t* msg, void* userdata)
{
	tuya_mqtt_context_t* context = (tuya_mqtt_context_t*)userdata;

	/* topic filter */
	TY_LOGD("recv message TopicName:%s, payload len:%d", msg->topic, msg->length);
	mqtt_subscribe_message_distribute(context, msgid, msg);
}

static void mqtt_client_subscribed_cb(void* client, uint16_t msgid, void* userdata)
{
	client = client;
	userdata = userdata;
	TY_LOGD("Subscribe successed ID:%d", msgid);
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
	context->user_data = config->user_data;
	context->on_unbind = config->on_unbind;
	context->on_connected = config->on_connected;
	context->on_disconnect = config->on_disconnect;

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
		.keepalive = MQTT_KEEPALIVE_INTERVALIN,
		.timeout_ms = config->timeout,
		.clientid = context->signature.clientid,
		.username = context->signature.username,
		.password = context->signature.password,
		.on_connected = mqtt_client_connected_cb,
		.on_disconnected = mqtt_client_disconnected_cb,
		.on_message = mqtt_client_message_cb,
		.on_subscribed = mqtt_client_subscribed_cb,
		.userdata = context
	};
	mqtt_status = mqtt_client_init(context->mqtt_client, &mqtt_config);
    if( mqtt_status != MQTT_STATUS_SUCCESS ) {
        TY_LOGE( "MQTT init failed: Status = %d.", mqtt_status);
		return OPRT_COM_ERROR;
    }

	BackoffAlgorithm_InitializeParams(&context->backoff_algorithm,
									  MQTT_CONNECT_RETRY_MIN_DELAY_MS,
									  MQTT_CONNECT_RETRY_MAX_DELAY_MS,
									  MQTT_CONNECT_RETRY_MAX_ATTEMPTS );

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

	mqtt_status = mqtt_client_connect(context->mqtt_client);
	if (MQTT_STATUS_NOT_AUTHORIZED == mqtt_status) {
		TY_LOGE("MQTT connect fail:%d", mqtt_status);
		if (context->on_unbind) {
			context->on_unbind(context, context->user_data);
		}
		return OPRT_LINK_CORE_MQTT_NOT_AUTHORIZED;
	}

	if (MQTT_STATUS_SUCCESS != mqtt_status) {
		TY_LOGE("MQTT connect fail:%d", mqtt_status);
		/* Generate a random number and get back-off value (in milliseconds) for the next connection retry. */
		uint16_t nextRetryBackOff = 0U;
		if( BackoffAlgorithm_GetNextBackoff(&context->backoff_algorithm,\
			system_random(), &nextRetryBackOff ) == BackoffAlgorithmSuccess ) {
			TY_LOGW("Connection to the MQTT server failed. Retrying "
					"connection after %hu ms backoff.",
					( unsigned short ) nextRetryBackOff );
			system_sleep(nextRetryBackOff);
		}
		return OPRT_COM_ERROR;
	}
	return OPRT_OK;
}

int tuya_mqtt_stop(tuya_mqtt_context_t* context)
{
	if (context == NULL || context->is_inited == false) {
		return OPRT_INVALID_PARM;
	}

	int ret = tuya_mqtt_subscribe_message_callback_unregister(context, context->signature.topic_in);
	TY_LOGD("MQTT unsubscribe result:%d", ret);

	mqtt_client_status_t mqtt_status;
	mqtt_status = mqtt_client_disconnect(context->mqtt_client);
	TY_LOGD("MQTT disconnect result:%d", mqtt_status);

	context->manual_disconnect = true;
	return OPRT_OK;
}

int tuya_mqtt_protocol_register(tuya_mqtt_context_t* context, uint16_t protocol_id, tuya_protocol_callback_t cb, void* user_data)
{
	if (context == NULL || context->is_inited == false || cb == NULL) {
		return OPRT_INVALID_PARM;
	}

	/* LOCK */
	/* Repetition filter */
	tuya_protocol_handle_t* target = context->protocol_list;
	while (target) {
		if (target->id == protocol_id && target->cb == cb) {
			return OPRT_COM_ERROR;
		}
		target = target->next;
	}

	tuya_protocol_handle_t* new_handle = system_calloc(1, sizeof(tuya_protocol_handle_t));
	if (!new_handle) {
		return OPRT_MALLOC_FAILED;
	}
	new_handle->id = protocol_id;
	new_handle->cb = cb;
	new_handle->user_data = user_data;
	new_handle->next = context->protocol_list;
	context->protocol_list = new_handle;
	/* UNLOCK */

	return OPRT_OK;
}

int tuya_mqtt_protocol_unregister(tuya_mqtt_context_t* context, uint16_t protocol_id, tuya_protocol_callback_t cb)
{
	if (context == NULL || context->is_inited == false || cb == NULL) {
		return OPRT_INVALID_PARM;
	}

	/* LOCK */
	/* Remove object form list */
	tuya_protocol_handle_t** target = &context->protocol_list;
	while (*target) {
		tuya_protocol_handle_t* entry = *target;
		if (entry->id == protocol_id && entry->cb == cb) {
			*target = entry->next;
			system_free(entry);
		} else {
			target = &entry->next;
		}
	}
	/* UNLOCK */

	return OPRT_OK;
}

int tuya_mqtt_protocol_data_publish_with_topic(tuya_mqtt_context_t* context, const char* topic, uint16_t protocol_id, uint8_t* data, uint16_t length)
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
	packet->sequence = context->sequence_out++;
	packet->source = 1;
	TY_LOGD("Report data:%s", (char*)packet->data);

	ret = pv22_packet_encode((const uint8_t*)context->signature.cipherkey,
							 (const pv22_packet_object_t*)packet, buffer, &buffer_len);
	system_free(packet);
	if (ret != OPRT_OK) {
		TY_LOGE("pv22_packet_encode error:%d", ret);
		system_free(buffer);
		return OPRT_COM_ERROR;
	}

	/* mqtt client publish */
	uint16_t msgid = mqtt_client_publish( context->mqtt_client,
										  topic,
										  buffer,
										  buffer_len,
										  MQTT_QOS_0);
	system_free(buffer);
	return msgid;
}

int tuya_mqtt_protocol_data_publish(tuya_mqtt_context_t* context, uint16_t protocol_id, uint8_t* data, uint16_t length)
{
	return tuya_mqtt_protocol_data_publish_with_topic(context, context->signature.topic_out, protocol_id, data, length);
}

int tuya_mqtt_loop(tuya_mqtt_context_t* context)
{
	if (context == NULL) {
		return OPRT_COM_ERROR;
	}

	int rt = OPRT_OK;
	mqtt_client_status_t mqtt_status;

	if (context->is_inited == false ||
		context-> manual_disconnect == true) {
		return rt;
	}

	if (context->is_connected) {
		mqtt_client_yield(context->mqtt_client);
		return rt;
	}

	/* reconnect */
	mqtt_status = mqtt_client_connect(context->mqtt_client);
	if (mqtt_status == MQTT_STATUS_NOT_AUTHORIZED) {
		if(context->on_unbind) {
			context->on_unbind(context, context->user_data);
		}
		return rt;

	} else if (mqtt_status != MQTT_STATUS_SUCCESS) {
		uint16_t nextRetryBackOff = 0U;
		if( BackoffAlgorithm_GetNextBackoff(&context->backoff_algorithm,\
			system_random(), &nextRetryBackOff ) == BackoffAlgorithmSuccess ) {
			TY_LOGW("Connection to the MQTT server failed. Retrying "
					"connection after %hu ms backoff.",
					( unsigned short ) nextRetryBackOff );
			system_sleep(nextRetryBackOff);
			return rt;
		}
	}

	return rt;
}

int tuya_mqtt_destory(tuya_mqtt_context_t* context)
{
	if (context == NULL || context->is_inited != false) {
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

    int buffer_size = sprintf((char*)data_buf,"{\"progress\":\"%d\",\"firmwareType\":%d}", percent, channel);
	uint16_t msgid = tuya_mqtt_protocol_data_publish(context, PRO_UPGE_PUSH, data_buf, (uint16_t)buffer_size);
    system_free(data_buf);
	if (msgid <= 0) {
    	return OPRT_COM_ERROR;
	}
	return OPRT_OK;
}
