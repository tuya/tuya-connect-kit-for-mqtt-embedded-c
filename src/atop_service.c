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

#define ATOP_ACTIVATE_API "tuya.device.active"
#define ATOP_ACTIVATE_API_VERSION "4.3"
#define ATOP_ACTIVATE_POST_FMT "{\"productKey\":\"%s\",\"token\":\"%s\",\"protocolVer\":\"%s\",\"baselineVer\":\"%s\",\"softVer\":\"%s\",\"t\":%d}"


int tuya_device_activate_request(const device_activite_params_t* request, 
                                        atop_base_response_t* response)
{
    int rt = OPRT_OK;

    /* post data */
    size_t buffer_len = 0;
    char* buffer = system_malloc(255);
    if (NULL == buffer) {
        TY_LOGE("post buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    /* activate JSON format */
    buffer_len = sprintf(buffer, ATOP_ACTIVATE_POST_FMT, 
                            request->product_key,
                            request->token,
                            request->pv,
                            request->bv,
                            request->sw_ver,
                            system_timestamp());
    TY_LOGV("POST JSON:%s", buffer);

    /* atop_base_request object construct */
    atop_base_request_t atop_request = {
        .host = tuya_atop_http_url_get(),
        .port = TUYA_ATOP_PORT,
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
        // TODO define new return code
        return rt;
    }
    return rt;
}
