#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "tuya_config_defaults.h"
#include "tuya_error_code.h"
#include "tuya_log.h"
#include "tuya_iot.h"
#include "tuya_endpoint.h"

#include "system_interface.h"
#include "mqtt_service.h"
#include "cJSON.h"

typedef enum {
    STATE_MQTT_BIND_START,
    STATE_MQTT_BIND_CONNECT,
    STATE_MQTT_BIND_COMPLETE,
    STATE_MQTT_BIND_TIMEOUT,
    STATE_MQTT_BIND_FAILED,
    STATE_MQTT_BIND_EXIT,
    STATE_MQTT_BIND_CONNECTED_WAIT,
    STATE_MQTT_BIND_TOKEN_WAIT,
} mqtt_bind_state_t;

static void mqtt_bind_activate_token_on(tuya_protocol_event_t* ev)
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
    char* regist_key = "pro"; // online env default

    if  (cJSON_GetObjectItem(data, "env")) {
        regist_key = cJSON_GetObjectItem(data, "env")->valuestring;
    }

    if (strlen(token) > MAX_LENGTH_TOKEN) {
        TY_LOGE("token length error");
        return;
    }

    if (strlen(region) > MAX_LENGTH_REGION) {
        TY_LOGE("region length error");
        return;
    }

    if (strlen(regist_key) > MAX_LENGTH_REGIST) {
        TY_LOGE("regist_key length error");
        return;
    }

    strcpy(binding->token, token);
    strcpy(binding->region, region);
    strcpy(binding->regist_key, regist_key);
}

int mqtt_bind_token_get(const tuya_iot_config_t* config, tuya_binding_info_t* binding)
{
    int ret = OPRT_OK;
    mqtt_bind_state_t mqtt_bind_state = STATE_MQTT_BIND_START;
    tuya_mqtt_context_t mqctx;

    while(mqtt_bind_state != STATE_MQTT_BIND_EXIT) {
        switch(mqtt_bind_state) {
        case STATE_MQTT_BIND_START: {
            /* mqtt init */
            const tuya_endpoint_t* endpoint = tuya_endpoint_get();
            ret = tuya_mqtt_init(&mqctx, &(const tuya_mqtt_config_t){
                .cacert = endpoint->mqtt.cert,
                .cacert_len =  endpoint->mqtt.cert_len,
                .host =  endpoint->mqtt.host,
                .port = endpoint->mqtt.port,
                .uuid = config->uuid,
                .authkey = config->authkey,
                .timeout = MQTT_BIND_TIMEOUT_MS_DEFAULT,
            });
            if (OPRT_OK != ret) {
                TY_LOGE("tuya mqtt init error:%d", ret);
                tuya_mqtt_destory(&mqctx);
                return OPRT_LINK_CORE_MQTT_GET_TOKEN_FAIL;
            }

            /* register token callback */
            tuya_mqtt_protocol_register(&mqctx, PRO_MQ_ACTIVE_TOKEN_ON,
                                    mqtt_bind_activate_token_on, binding);
            mqtt_bind_state = STATE_MQTT_BIND_CONNECT;
            break;
        }

        case STATE_MQTT_BIND_CONNECT:
            ret = tuya_mqtt_start(&mqctx);
            if (OPRT_OK != ret) {
                TY_LOGE("tuya mqtt connect fail:%d, retry..", ret);
                break;
            }
            mqtt_bind_state = STATE_MQTT_BIND_CONNECTED_WAIT;
            break;

        case STATE_MQTT_BIND_CONNECTED_WAIT:
            if (tuya_mqtt_connected(&mqctx)) {
                TY_LOGI("MQTT direct connected!");
                TY_LOGI("Wait Tuya APP scan the Device QR code...");
                mqtt_bind_state = STATE_MQTT_BIND_TOKEN_WAIT;
            }
            break;

        case STATE_MQTT_BIND_TOKEN_WAIT:
            tuya_mqtt_loop(&mqctx);
            if (strlen(binding->token) == 0) {
                break;
            }
            mqtt_bind_state = STATE_MQTT_BIND_COMPLETE;
            break;

        case STATE_MQTT_BIND_COMPLETE:
            TY_LOGD("STATE_MQTT_BIND_COMPLETE");
            tuya_mqtt_stop(&mqctx);
            tuya_mqtt_destory(&mqctx);
            mqtt_bind_state = STATE_MQTT_BIND_EXIT;
            break;

        default:
            TY_LOGE("state error:%d", mqtt_bind_state);
            break;
        }

    }

    return ret;
}
