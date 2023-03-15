#include "tuya_iot.h"
#include "tuya_cloud_types.h"
#include "tuya_ble_service.h"
#include "tuya_wifi_provisioning.h"
#include "system_interface.h"
#include "MultiTimer.h"
#include "tuya_log.h"

typedef struct{
    tuya_wifi_provisioning_mode_t mode;
    wifi_info_get_callback cb;
    tuya_binding_info_t binding_info;
    uint8_t get_token_flag;
}wifi_provisioning_params_t;

wifi_provisioning_params_t wifi_provisioning_params = {0};

static void ble_service_callback(wifi_info_t wifi_info, tuya_binding_info_t binding_info)
{
    if (wifi_provisioning_params.cb) {
        wifi_provisioning_params.cb(wifi_info);
    }

    memcpy(&wifi_provisioning_params.binding_info, &binding_info, sizeof(tuya_binding_info_t));
}

static int ble_bind_token_get(const tuya_iot_config_t* config, tuya_binding_info_t* binding)
{
    OPERATE_RET rt = OPRT_OK;
    tuya_ble_service_init_params_t init_params = {0};

    init_params.pid = (uint8_t *)config->productkey;
    init_params.uuid = (uint8_t *)config->uuid;
    init_params.auth_key = (uint8_t *)config->authkey;

    TUYA_CALL_ERR_RETURN(tuya_ble_service_start(&init_params, &ble_service_callback));

    for ( ;; ) {
        ble_service_loop();
        system_sleep(50);
        MultiTimerYield();
        if (ble_service_is_stop()) {
            PR_DEBUG("ble service stop");
            break;
        }
    }

    memcpy(binding, &wifi_provisioning_params.binding_info, sizeof(tuya_binding_info_t));

    if (0 == strlen(binding->region) || 0 == strlen(binding->regist_key) || 0 == strlen(binding->token)) {
        PR_DEBUG("token get fail");
        rt = OPRT_COM_ERROR;
    }

    return rt;
}

int tuya_wifi_provisioning(tuya_iot_client_t *client, tuya_wifi_provisioning_mode_t mode, wifi_info_get_callback cb)
{
    OPERATE_RET rt = OPRT_OK;

    memset(&wifi_provisioning_params, 0, sizeof(wifi_provisioning_params_t));

    if (WIFI_PROVISIONING_MODE_BLE == mode) {
        wifi_provisioning_params.mode = WIFI_PROVISIONING_MODE_BLE;
        wifi_provisioning_params.cb = cb;

        TUYA_CALL_ERR_RETURN(tuya_iot_token_get_port_register(client, ble_bind_token_get));
    }

    return OPRT_OK;
}

int tuya_wifi_provisioning_stop(tuya_iot_client_t *client)
{
    tuya_ble_service_stop();
}
