#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "tuya_log.h"
#include "tuya_error_code.h"
#include "tuya_cloud_types.h"
#include "system_interface.h"

#include "cJSON.h"
#include "matop_service.h"
#include "atop_base.h"

#define MATOP_DEFAULT_BUFFER_LEN (128)

/* -------------------------------------------------------------------------- */
/*                              Internal callback                             */
/* -------------------------------------------------------------------------- */
static int matop_service_data_receive_cb(void* context, const uint8_t* input, size_t ilen)
{
	matop_context_t* matop = (matop_context_t*)context;

	TY_LOGV("atop response raw:\r\n%.*s", ilen, input);

	/* json parse */
    cJSON* root = cJSON_Parse((const char*)input);
    if (NULL == root) {
        TY_LOGE("Json parse error");
        return OPRT_CJSON_PARSE_ERR;
    }

	if (cJSON_GetObjectItem(root, "id") == NULL ||
		cJSON_GetObjectItem(root, "id")->type != cJSON_Number ||
		cJSON_GetObjectItem(root, "data") == NULL) {
		cJSON_Delete(root);
		return OPRT_CJSON_GET_ERR;
	}

	uint16_t id = cJSON_GetObjectItem(root, "id")->valueint;
	cJSON* data = cJSON_GetObjectItem(root, "data");

	/* found message id */
	mqtt_atop_message_t* target_message = matop->message_list;
	while (target_message) {
		if (target_message->id == id) {
			break;
		}
		target_message = target_message->next;
	}

	if (target_message == NULL) {
		TY_LOGW("not found id.");
		cJSON_Delete(root);
		return OPRT_COM_ERROR;
	}

	/* result parse */
	bool success = false;
	cJSON* result = NULL;

	if (cJSON_GetObjectItem(data, "result")) {
		result = cJSON_GetObjectItem(data, "result");
		success = cJSON_IsTrue(cJSON_GetObjectItem(result, "success"));
		result = cJSON_GetObjectItem(result, "result");
	}

	atop_base_response_t response = {
		.success = success,
		.result = result,
		.t = success ? cJSON_GetObjectItem(data, "t")->valueint:0,
		.user_data = target_message->user_data
	};

	if(target_message->notify_cb) {
		target_message->notify_cb(&response, target_message->user_data);
	}

	cJSON_Delete(root);

	/* remove target from list  */
	mqtt_atop_message_t** current;
	for(current = &matop->message_list; *current; ) {
		mqtt_atop_message_t* entry = *current;
		if (entry == target_message) {
			*current = entry->next;
			system_free(entry);
		} else {
			current = &entry->next;
		}
	}
	return 0;
}

static int matop_service_file_rawdata_receive_cb(void* context, const uint8_t* input, size_t ilen)
{
	matop_context_t* matop = (matop_context_t*)context;

	if (ilen < sizeof(uint32_t)) {
		TY_LOGE("error ilen:%d", ilen);
		return OPRT_INVALID_PARM;
	}

#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t id = DWORD_SWAP(*((uint32_t*)input));
#else
	uint32_t id = *((uint32_t*)input);
#endif
	TY_LOGI("file data id:%d", id);

	/* found message id */
	mqtt_atop_message_t* target_message = matop->message_list;
	while (target_message) {
		if (target_message->id == id) {
			break;
		}
		target_message = target_message->next;
	}

	if (target_message == NULL) {
		TY_LOGW("not found id.");
		return OPRT_COM_ERROR;
	}

	atop_base_response_t response = {
		.success = true,
		.result = NULL,
		.t = 0,
		.raw_data = (uint8_t*)(input + sizeof(uint32_t)),
		.raw_data_len = ilen - sizeof(uint32_t),
		.user_data = target_message->user_data,
	};

	if(target_message->notify_cb) {
		target_message->notify_cb(&response, target_message->user_data);
	}

	/* remove target from list  */
	mqtt_atop_message_t** current;
	for(current = &matop->message_list; *current; ) {
		mqtt_atop_message_t* entry = *current;
		if (entry == target_message) {
			*current = entry->next;
			system_free(entry);
		} else {
			current = &entry->next;
		}
	}
    return 0;
}

static void on_matop_service_data_receive(uint16_t msgid, const mqtt_client_message_t* msg, void* userdata)
{
	matop_service_data_receive_cb(userdata, msg->payload, msg->length);
}

static void on_matop_service_file_rawdata_receive(uint16_t msgid, const mqtt_client_message_t* msg, void* userdata)
{
	matop_service_file_rawdata_receive_cb(userdata, msg->payload, msg->length);
}

static int matop_request_send(matop_context_t* context, const uint8_t* data, size_t datalen)
{
	uint16_t msgid = mqtt_client_publish(context->config.mqctx->mqtt_client, context->resquest_topic, data, datalen, MQTT_QOS_0);

	if (msgid <= 0) {
		// TODO add error code
		TY_LOGE("mqtt connect err:%d", msgid);
		return OPRT_COM_ERROR;
	}
	return OPRT_OK;
}

/* -------------------------------------------------------------------------- */
/*                                 MATOP base                                 */
/* -------------------------------------------------------------------------- */
int matop_serice_init(matop_context_t* context, const matop_config_t* config)
{
	int ret;
	char topic_buffer[48];

	memset(context, 0, sizeof(matop_context_t));
	context->config = *config;

	sprintf(topic_buffer, "rpc/rsp/%s", config->devid);
	ret = tuya_mqtt_subscribe_message_callback_register(context->config.mqctx, topic_buffer, on_matop_service_data_receive, context);
	if (ret != OPRT_OK) {
		TY_LOGE("Topic subscribe error:%s", topic_buffer);
		return ret;
	}

	sprintf(topic_buffer, "rpc/file/%s", config->devid);
	tuya_mqtt_subscribe_message_callback_register(context->config.mqctx, topic_buffer, on_matop_service_file_rawdata_receive, context);
	if (ret != OPRT_OK) {
		TY_LOGE("Topic subscribe error:%s", topic_buffer);
		return ret;
	}

	sprintf(context->resquest_topic, "rpc/req/%s", config->devid);
	return OPRT_OK;
}

int matop_serice_yield(matop_context_t* context)
{
	if (context == NULL) {
		return OPRT_INVALID_PARM;
	}

	/* remove target from list  */
	mqtt_atop_message_t** current;
	for(current = &context->message_list; *current; ) {
		mqtt_atop_message_t* entry = *current;
		if (system_ticks() > entry->timeout) {
			TY_LOGW("Message id %d timeout.", entry->id);
			if (entry->notify_cb) {
				entry->notify_cb(&(atop_base_response_t){.success = false}, entry->user_data);
			}
			*current = entry->next;
			system_free(entry);
			return OPRT_TIMEOUT;
		} else {
			current = &entry->next;
		}
	}
	return OPRT_OK;
}

int matop_service_request_async(matop_context_t* context,
								const mqtt_atop_request_t* request,
								mqtt_atop_response_cb_t notify_cb,
								void* user_data)
{
    if (NULL == context || NULL == request) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;
	matop_context_t* matop = context;

	/* handle init */
	mqtt_atop_message_t* message_handle = system_malloc(sizeof(mqtt_atop_message_t));
	if (message_handle == NULL) {
		TY_LOGE("response_buffer malloc fail");
        return OPRT_MALLOC_FAILED;
	}
	message_handle->next = NULL;
	message_handle->id = ++matop->id_cnt;
	message_handle->timeout = system_ticks() + (request->timeout == 0 ? 5000:request->timeout);
	message_handle->notify_cb = notify_cb;
	message_handle->user_data = user_data;

	/* request buffer make */
    size_t request_datalen = 0;
    size_t request_bufferlen = strlen((char*)request->data) + 128;
    char* request_buffer = system_malloc(request_bufferlen);
    if (request_buffer == NULL) {
        TY_LOGE("response_buffer malloc fail");
		system_free(message_handle);
        return OPRT_MALLOC_FAILED;
    }

	/* buffer format */
    request_datalen = snprintf(request_buffer, request_bufferlen,
						"{\"id\":%d,\"a\":\"%s\",\"t\":%d,\"data\":%s",
						message_handle->id, request->api, system_timestamp(), (char*)request->data);
	if (request->version) {
		request_datalen += snprintf(request_buffer + request_datalen, request_bufferlen - request_datalen,
									",\"v\":\"%s\"",
									request->version);
	}
	request_datalen += snprintf(request_buffer + request_datalen, request_bufferlen - request_datalen, "}");
	TY_LOGD("atop request: %s", request_buffer);

    rt = matop_request_send(matop, (const uint8_t*)request_buffer, request_datalen);
	system_free(request_buffer);

	if (rt != OPRT_OK) {
		TY_LOGE("mqtt_atop_request_send error:%d", rt);
		system_free(message_handle);
		return rt;
	}

	/* first head message */
	if (matop->message_list == NULL) {
		matop->message_list = message_handle;
		return OPRT_OK;
	}

	/* add to message list */
	mqtt_atop_message_t* target = matop->message_list;
	while(target->next) {
		target = target->next;
	}
	target->next = message_handle;

	return OPRT_OK;
}

/* -------------------------------------------------------------------------- */
/*                           ATOP Over MQTT Service                           */
/* -------------------------------------------------------------------------- */
int matop_service_client_reset(matop_context_t* context)
{
    if (NULL == context) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    size_t buffer_len = 0;
    char* buffer = system_malloc(MATOP_DEFAULT_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    buffer_len = snprintf(buffer, MATOP_DEFAULT_BUFFER_LEN, "{\"t\":%d}", system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* ATOP service request send */
	rt = matop_service_request_async(context,
        &(const mqtt_atop_request_t){
            .api = "tuya.device.reset",
            .version = "4.0",
            .data = (uint8_t*)buffer,
            .data_len = buffer_len,
        },
        NULL,
        context);
	system_free(buffer);
    return rt;
}

int matop_service_version_update(matop_context_t* context, const char *versions)
{
    if (NULL == context || NULL == versions) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    #define UPDATE_VERSION_BUFFER_LEN 196
    size_t buffer_len = 0;
    char* buffer = system_malloc(UPDATE_VERSION_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    buffer_len = snprintf(buffer, UPDATE_VERSION_BUFFER_LEN, "{\"versions\":\"%s\",\"t\":%d}", versions, system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* ATOP service request send */
	rt = matop_service_request_async(context,
        &(const mqtt_atop_request_t){
            .api = "tuya.device.versions.update",
            .version = "4.1",
            .data = (uint8_t*)buffer,
            .data_len = buffer_len,
        },
        NULL,
        context);
	system_free(buffer);
    return rt;
}

int matop_service_upgrade_status_update(matop_context_t* context, int channel, int status)
{
    if (NULL == context) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    size_t buffer_len = 0;
    char* buffer = system_malloc(MATOP_DEFAULT_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    buffer_len = snprintf(buffer, MATOP_DEFAULT_BUFFER_LEN,
        "{\"type\":%d,\"upgradeStatus\":%d,\"t\":%d}", channel, status, system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* ATOP service request send */
	rt = matop_service_request_async(context,
        &(const mqtt_atop_request_t){
            .api = "tuya.device.upgrade.status.update",
            .version = "4.1",
            .data = (uint8_t*)buffer,
            .data_len = buffer_len,
        },
        NULL,
        context);
	system_free(buffer);
    return rt;
}

int matop_service_upgrade_info_get(matop_context_t* context, int channel,
									mqtt_atop_response_cb_t notify_cb, void* user_data)
{
    if (NULL == context) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    size_t buffer_len = 0;
    char* buffer = system_malloc(MATOP_DEFAULT_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    buffer_len = snprintf(buffer, MATOP_DEFAULT_BUFFER_LEN, "{\"type\":%d,\"t\":%d}", channel, system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* ATOP service request send */
	rt = matop_service_request_async(context,
        &(const mqtt_atop_request_t){
            .api = "tuya.device.upgrade.get",
            .version = "4.4",
            .data = (uint8_t*)buffer,
            .data_len = buffer_len,
            .timeout = 10000
        },
        notify_cb,
        user_data);
	system_free(buffer);
    return rt;
}

int matop_service_auto_upgrade_info_get(matop_context_t* context,
										mqtt_atop_response_cb_t notify_cb,
										void* user_data)
{
    if (NULL == context) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    size_t buffer_len = 0;
    char* buffer = system_malloc(MATOP_DEFAULT_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    buffer_len = snprintf(buffer, MATOP_DEFAULT_BUFFER_LEN, "{\"subId\":null,\"t\":%d}", system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* ATOP service request send */
	rt = matop_service_request_async(context,
        &(const mqtt_atop_request_t){
            .api = "tuya.device.upgrade.silent.get",
            .version = "4.4",
            .data = (uint8_t*)buffer,
            .data_len = buffer_len,
        },
        notify_cb,
        user_data);
	system_free(buffer);
    return rt;
}

int matop_service_file_download_range(matop_context_t* context,
										const char* url,
										int range_start,
										int range_end,
										uint32_t timeout_ms,
										mqtt_atop_response_cb_t notify_cb,
										void* user_data)
{
    if (NULL == context) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
	#define MATOP_DOWNLOAD_BUFFER_LEN 511
    size_t buffer_len = 0;
    char* buffer = system_malloc(MATOP_DOWNLOAD_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    buffer_len = snprintf(buffer, MATOP_DOWNLOAD_BUFFER_LEN,
						"{\"url\":\"%s\",\"range\":\"bytes=%d-%d\",\"type\":%d}",
						url, range_start, range_end, (range_start == 0 && range_end == 0) ? 1:2);
    TY_LOGV("POST JSON:%s", buffer);

    /* ATOP service request send */
	rt = matop_service_request_async(context,
        &(const mqtt_atop_request_t){
            .api = "tuya.device.file.download",
            .version = "1.0",
            .data = (uint8_t*)buffer,
            .data_len = buffer_len,
            .timeout = timeout_ms
        },
        notify_cb,
        user_data);
	system_free(buffer);
    return rt;
}

int matop_service_put_rst_log(matop_context_t* context, int reason)
{
    if (NULL == context) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

	#define RST_BUFFER_MAX (128)
    char* rst_buffer = system_malloc(RST_BUFFER_MAX);
    if (rst_buffer == NULL) {
		TY_LOGE("rst_buffer buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    /* Format rst_info JSON buffer */
    snprintf(rst_buffer, RST_BUFFER_MAX,
        "\"data\":%d", reason);

    /* post data */
    #define UPDATE_VERSION_BUFFER_LEN 196
    size_t buffer_len = 0;
    char* buffer = system_malloc(UPDATE_VERSION_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
		system_free(rst_buffer);
        return OPRT_MALLOC_FAILED;
    }

	buffer_len = snprintf(buffer, UPDATE_VERSION_BUFFER_LEN, "{%s,\"t\":%d}", rst_buffer, system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* ATOP service request send */
	rt = matop_service_request_async(context,
        &(const mqtt_atop_request_t){
            .api = "atop.online.debug.log",
            .version = NULL,
            .data = (uint8_t*)buffer,
            .data_len = buffer_len,
        },
        NULL,
        context);
	system_free(buffer);
	system_free(rst_buffer);
    return rt;
}

int matop_service_dynamic_cfg_get(matop_context_t* context,
								  HTTP_DYNAMIC_CFG_TYPE type,
								  mqtt_atop_response_cb_t notify_cb,
								  void* user_data)
{
    if (NULL == context) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    size_t buffer_len = 0;
    char* buffer = system_malloc(MATOP_DEFAULT_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    uint32_t timestamp = system_timestamp();

    switch (type) {
    case HTTP_DYNAMIC_CFG_TZ:
        snprintf(buffer, MATOP_DEFAULT_BUFFER_LEN, "{\"type\":\"[\\\"timezone\\\"]\",\"t\":%d}", timestamp);
        break;
    case HTTP_DYNAMIC_CFG_RATERULE:
        snprintf(buffer, MATOP_DEFAULT_BUFFER_LEN, "{\"type\":\"[\\\"rateRule\\\"]\",\"t\":%d}", timestamp);
        break;
    case HTTP_DYNAMIC_CFG_ALL:
    default:
        snprintf(buffer, MATOP_DEFAULT_BUFFER_LEN, "{\"type\":\"[\\\"timezone\\\",\\\"rateRule\\\"]\",\"t\":%d}", timestamp);
        break;
    }

    buffer_len = strlen(buffer) + 1;
    TY_LOGV("dynamic cfg get data:%s", buffer);

    /* ATOP service request send */
    rt = matop_service_request_async(context,
        &(const mqtt_atop_request_t) {
            .api = "tuya.device.dynamic.config.get",
            .version = "2.0",
            .data = (uint8_t*)buffer,
            .data_len = buffer_len,
        },
        notify_cb,
        user_data);
    system_free(buffer);
    return rt;
}

int matop_service_dynamic_cfg_ack(matop_context_t* context,
								  const char* timezone_ackId,
								  const char* rateRule_actId,
								  mqtt_atop_response_cb_t notify_cb,
								  void* user_data)
{
    if (NULL == context) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;
    uint16_t offset = 0;

#define DYNAMIC_CFG_ACK_BUFFER_LEN MATOP_DEFAULT_BUFFER_LEN
    size_t buffer_len = 0;
    char* buffer = system_malloc(DYNAMIC_CFG_ACK_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    memset(buffer, 0, DYNAMIC_CFG_ACK_BUFFER_LEN);
    offset = snprintf(buffer, DYNAMIC_CFG_ACK_BUFFER_LEN, "{\"ackList\":[");

    if (timezone_ackId) {
        offset += snprintf(buffer + offset, DYNAMIC_CFG_ACK_BUFFER_LEN - offset, "{\"type\":\"timezone\",\"ackId\":\"%s\"}", timezone_ackId);
    }

    if (rateRule_actId) {
        offset += snprintf(buffer + offset, DYNAMIC_CFG_ACK_BUFFER_LEN - offset, "{\"type\":\"rateRule\",\"ackId\":%s}", rateRule_actId);
    }

    snprintf(buffer + offset, DYNAMIC_CFG_ACK_BUFFER_LEN, "],\"t\":%d}", system_timestamp());

    buffer_len = strlen(buffer) + 1;
    TY_LOGV("dynamic cfg ack data:%s", buffer);

    rt = matop_service_request_async(context,
        &(const mqtt_atop_request_t) {
            .api = "tuya.device.dynamic.config.ack",
            .version = "2.0",
            .data = (uint8_t*)buffer,
            .data_len = buffer_len,
        },
        notify_cb,
        user_data);

    system_free(buffer);
    return rt;
}
