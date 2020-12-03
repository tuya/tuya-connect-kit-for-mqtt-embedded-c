#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "tuya_error_code.h"
#include "tuya_log.h"
#include "tuya_iot.h"
#include "tuya_url.h"

#include "system_interface.h"
#include "mqtt_service.h"
#include "cJSON.h"

#define MQTT_BIND_NET_TIMEOUT         (5000)

extern const char tuya_rootCA_pem[];

typedef enum {
    STATE_MQTT_BIND_START,
    STATE_MQTT_BIND_COMPLETE,
    STATE_MQTT_BIND_TIMEOUT,
    STATE_MQTT_BIND_FAILED,
    STATE_MQTT_BIND_EXIT,
    STATE_MQTT_BIND_CONNECTED_WAIT,
    STATE_MQTT_BIND_TOKEN_WAIT,
} mqtt_bind_state_t;

static void mqtt_bind_activate_token_on(tuya_mqtt_event_t* ev)
{
    cJSON* data = (cJSON*)(ev->data);
    tuya_binding_info_t* binding = (tuya_binding_info_t*)(ev->user_data);

    if (NULL == cJSON_GetObjectItem(data, "token")) {
        TY_LOGE("not found token");
        return;
    }

    if (NULL == cJSON_GetObjectItem(data, "region")) {
        TY_LOGE("not found region");
        return;
    }

    /* get token from cJSON object */
    char* token = cJSON_GetObjectItem(data, "token")->valuestring;
    char* region = cJSON_GetObjectItem(data, "region")->valuestring;

    if (strlen(token) > MAX_LENGTH_TOKEN) {
        TY_LOGE("token length error");
        return;
    }

    if (strlen(region) > MAX_LENGTH_REGION) {
        TY_LOGE("region length error");
        return;
    }

    strcpy(binding->token, token);
    strcpy(binding->region, region);
}

static int mqtt_bind_mode_start(tuya_mqtt_context_t* mqctx, const tuya_iot_config_t* config)
{
    int rt = OPRT_OK;

    /* mqtt init */
    rt = tuya_mqtt_init(mqctx, &(const tuya_mqtt_config_t){
        .rootCA = tuya_rootCA_pem,
        .host = tuya_mqtt_server_host_get(),
        .port = tuya_mqtt_server_port_get(),
        .uuid = config->uuid,
        .authkey = config->authkey,
        .timeout = MQTT_BIND_NET_TIMEOUT,
    });
    if (OPRT_OK != rt) {
        TY_LOGE("tuya mqtt init error:%d", rt);
        return rt;
    }

    rt = tuya_mqtt_start(mqctx);
    if (OPRT_OK != rt) {
        TY_LOGE("tuya_mqtt_start error:%d", rt);
        return rt;
    }

    return rt;
}

int mqtt_bind_token_get(const tuya_iot_config_t* config, tuya_binding_info_t* binding)
{
    int ret = OPRT_OK;
    mqtt_bind_state_t mqtt_bind_state = STATE_MQTT_BIND_START;
    tuya_mqtt_context_t mqctx;

    while(mqtt_bind_state != STATE_MQTT_BIND_EXIT) {

        switch(mqtt_bind_state) {
        case STATE_MQTT_BIND_START:
            ret = mqtt_bind_mode_start(&mqctx, config);
            if (OPRT_OK == ret) {
                /* register token callback */
                tuya_mqtt_protocol_register(&mqctx, PRO_MQ_ACTIVE_TOKEN_ON, 
                                mqtt_bind_activate_token_on, binding);
                mqtt_bind_state = STATE_MQTT_BIND_CONNECTED_WAIT;
            }
            break;

        case STATE_MQTT_BIND_CONNECTED_WAIT:
            if (tuya_mqtt_connected(&mqctx)) {
                TY_LOGI("MQTT direct connected!");
                TY_LOGI("Wait Tuya APP scan the Device QR code...");
                mqtt_bind_state = STATE_MQTT_BIND_TOKEN_WAIT;
            }
            break;
        
        case STATE_MQTT_BIND_TOKEN_WAIT:
            if (strlen(binding->token) == 0) {
                break;
            }
            mqtt_bind_state = STATE_MQTT_BIND_COMPLETE;

        case STATE_MQTT_BIND_COMPLETE:
            tuya_mqtt_stop(&mqctx);
            tuya_mqtt_destory(&mqctx);
            mqtt_bind_state = STATE_MQTT_BIND_EXIT;
            break;
        
        default:
            TY_LOGE("state error:%d", mqtt_bind_state);
            break;
        }

        tuya_mqtt_loop(&mqctx);
    }
}