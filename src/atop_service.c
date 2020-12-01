/**
 * @file atop_service.c
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2020-10-29
 * 
 * @copyright Copyright (c) 2020
 * 
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "tuya_url.h"
#include "tuya_log.h"

#include "system_interface.h"
#include "network_interface.h"
#include "atop_base.h"
#include "atop_service.h"
#include "cJSON.h"

#define ATOP_DEFAULT_POST_BUFFER_LEN (128)

#define ATOP_ACTIVATE_POST_FMT "{\"productKey\":\"%s\",\"token\":\"%s\",\"protocolVer\":\"%s\",\"baselineVer\":\"%s\",\"softVer\":\"%s\",\"t\":%d}"
#define ATOP_ACTIVATE_API "tuya.device.active"
#define ATOP_ACTIVATE_API_VERSION "4.3"

#define ATOP_RESET_API "tuya.device.reset"
#define ATOP_RESET_API_VERSION "4.0"

#define ATOP_GW_DYN_CFG_GET "tuya.device.dynamic.config.get"
#define ATOP_GW_DYN_CFG_GET_VER "1.0"

int atop_service_activate_request(const tuya_activite_request_t* request, 
                                        atop_base_response_t* response)
{
    if (NULL == request || NULL == response) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    #define ACTIVATE_POST_BUFFER_LEN (255)
    size_t buffer_len = 0;
    char* buffer = system_malloc(ACTIVATE_POST_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    /* activate JSON format */
    buffer_len = snprintf(buffer, ACTIVATE_POST_BUFFER_LEN, ATOP_ACTIVATE_POST_FMT, 
                            request->product_key,
                            request->token,
                            request->pv,
                            request->bv,
                            request->sw_ver,
                            system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* atop_base_request object construct */
    atop_base_request_t atop_request = {
        .host = tuya_atop_server_host_get(),
        .port = tuya_atop_server_port_get(),
        .uuid = request->uuid,
        .key = request->authkey,
        .path = "/d.json",
        .timestamp = system_timestamp(),
        .api = ATOP_ACTIVATE_API,
        .version = ATOP_ACTIVATE_API_VERSION,
        .data = buffer,
        .datalen = buffer_len,
        .buflen_custom = request->buflen_custom,
        .user_data = request->user_data
    };

    /* ATOP service request send */
    rt = atop_base_request(&atop_request, response);
    system_free(buffer);
    if (OPRT_OK != rt) {
        TY_LOGE("atop_base_request error:%d", rt);
        return rt;
    }
    return rt;
}

int atop_service_client_reset(const char* id, const char* key, atop_base_response_t* response)
{
    if (NULL == id || NULL == key || NULL == response) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    #define RESET_POST_BUFFER_LEN 32
    size_t buffer_len = 0;
    char* buffer = system_malloc(RESET_POST_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    buffer_len = snprintf(buffer, RESET_POST_BUFFER_LEN, "{\"t\":%d}", system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* atop_base_request object construct */
    atop_base_request_t atop_request = {
        .host = tuya_atop_server_host_get(),
        .port = tuya_atop_server_port_get(),
        .devid = id,
        .key = key,
        .path = "/d.json",
        .timestamp = system_timestamp(),
        .api = ATOP_RESET_API,
        .version = ATOP_RESET_API_VERSION,
        .data = buffer,
        .datalen = buffer_len,
        .user_data = NULL
    };

    /* ATOP service request send */
    rt = atop_base_request(&atop_request, response);
    system_free(buffer);
    if (OPRT_OK != rt) {
        TY_LOGE("atop_base_request error:%d", rt);
        return rt;
    }
    return rt;
}

int atop_service_dynamic_cfg_get_v20(const char* id, const char* key, HTTP_DYNAMIC_CFG_TYPE type, atop_base_response_t* response)
{
    if (NULL == id || NULL == key || NULL == response) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    size_t buffer_len = 0;
    char* buffer = system_malloc(ATOP_DEFAULT_POST_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    /* timestamp */
    uint32_t timestamp = system_timestamp();

    //当前种类较少，后续如果增加，需要动态拼装消息内容
    switch(type){
        case HTTP_DYNAMIC_CFG_TZ:
            snprintf(buffer, ATOP_DEFAULT_POST_BUFFER_LEN, "{\"type\":\"[\\\"timezone\\\"]\",\"t\":%d}", timestamp);
            break;
        case HTTP_DYNAMIC_CFG_RATERULE:
            snprintf(buffer, ATOP_DEFAULT_POST_BUFFER_LEN, "{\"type\":\"[\\\"rateRule\\\"]\",\"t\":%d}", timestamp);
            break;
        case HTTP_DYNAMIC_CFG_ALL:
        default:
            snprintf(buffer, ATOP_DEFAULT_POST_BUFFER_LEN, "{\"type\":\"[\\\"timezone\\\",\\\"rateRule\\\"]\",\"t\":%d}", timestamp);
            break;
    }

    buffer_len = strlen(buffer) + 1;
    TY_LOGV("POST JSON:%s", buffer);

    /* atop_base_request object construct */
    atop_base_request_t atop_request = {
        .host = tuya_atop_server_host_get(),
        .port = tuya_atop_server_port_get(),
        .devid = id,
        .key = key,
        .path = "/d.json",
        .timestamp = timestamp,
        .api = ATOP_GW_DYN_CFG_GET,
        .version = ATOP_GW_DYN_CFG_GET_VER,
        .data = buffer,
        .datalen = buffer_len,
        .user_data = NULL
    };

    /* ATOP service request send */
    rt = atop_base_request(&atop_request, response);
    system_free(buffer);
    if (OPRT_OK != rt) {
        TY_LOGE("atop_base_request error:%d", rt);
        return rt;
    }
    return rt;
}

int atop_service_upgrade_info_get_v44(const char* id, const char* key, int channel, atop_base_response_t* response)
{
    if (NULL == id || NULL == key || NULL == response) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    size_t buffer_len = 0;
    char* buffer = system_malloc(ATOP_DEFAULT_POST_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    buffer_len = snprintf(buffer, ATOP_DEFAULT_POST_BUFFER_LEN, "{\"type\":%d,\"t\":%d}", channel, system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* atop_base_request object construct */
    atop_base_request_t atop_request = {
        .host = tuya_atop_server_host_get(),
        .port = tuya_atop_server_port_get(),
        .devid = id,
        .key = key,
        .path = "/d.json",
        .timestamp = system_timestamp(),
        .api = "tuya.device.upgrade.get",
        .version = "4.4",
        .data = buffer,
        .datalen = buffer_len,
        .user_data = NULL,
        .buflen_custom = 1024 * 2
    };

    /* ATOP service request send */
    rt = atop_base_request(&atop_request, response);
    system_free(buffer);
    if (OPRT_OK != rt) {
        TY_LOGE("atop_base_request error:%d", rt);
        return rt;
    }
    return rt;
}

int atop_service_upgrade_status_update_v41(const char* id, const char* key, int channel, int status, atop_base_response_t* response)
{
    if (NULL == id || NULL == key || NULL == response) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* post data */
    size_t buffer_len = 0;
    char* buffer = system_malloc(ATOP_DEFAULT_POST_BUFFER_LEN);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    buffer_len = snprintf(buffer, ATOP_DEFAULT_POST_BUFFER_LEN, 
        "{\"type\":%d,\"upgradeStatus\":%d,\"t\":%d}", channel, status, system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* atop_base_request object construct */
    atop_base_request_t atop_request = {
        .host = tuya_atop_server_host_get(),
        .port = tuya_atop_server_port_get(),
        .devid = id,
        .key = key,
        .path = "/d.json",
        .timestamp = system_timestamp(),
        .api = "tuya.device.upgrade.status.update",
        .version = "4.1",
        .data = buffer,
        .datalen = buffer_len,
        .user_data = NULL,
    };

    /* ATOP service request send */
    rt = atop_base_request(&atop_request, response);
    system_free(buffer);
    if (OPRT_OK != rt) {
        TY_LOGE("atop_base_request error:%d", rt);
        return rt;
    }
    return rt;
}

int atop_service_version_update_v41(const char* id, const char* key, const char *versions, atop_base_response_t* response)
{
    if (NULL == id || NULL == key || NULL == versions || NULL == response) {
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

    /* atop_base_request object construct */
    atop_base_request_t atop_request = {
        .host = tuya_atop_server_host_get(),
        .port = tuya_atop_server_port_get(),
        .devid = id,
        .key = key,
        .path = "/d.json",
        .timestamp = system_timestamp(),
        .api = "tuya.device.versions.update",
        .version = "4.1",
        .data = buffer,
        .datalen = buffer_len,
        .user_data = NULL,
    };

    /* ATOP service request send */
    rt = atop_base_request(&atop_request, response);
    system_free(buffer);
    if (OPRT_OK != rt) {
        TY_LOGE("atop_base_request error:%d", rt);
        return rt;
    }
    return rt;
}