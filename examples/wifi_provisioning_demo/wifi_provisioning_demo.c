#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "cJSON.h"
#include "tuya_config.h"
#include "tuya_iot.h"
#include "tuya_log.h"

#include "tuya_wifi_provisioning.h"

#define SOFTWARE_VER "1.0.0"
#define SWITCH_DP_ID_KEY "1"

/* Tuya device handle */
tuya_iot_client_t client;

/* Hardware switch control function */
void hardware_switch_set(bool value)
{
    if (value == true) {
        TY_LOGI("Switch ON");
    } else {
        TY_LOGI("Switch OFF");
    }
}

/* DP data reception processing function */
void user_dp_download_on(tuya_iot_client_t* client, const char* json_dps)
{
    TY_LOGD("Data point download value:%s", json_dps);

    /* Parsing json string to cJSON object */
    cJSON* dps = cJSON_Parse(json_dps);
    if (dps == NULL) {
        TY_LOGE("JSON parsing error, exit!");
        return;
    }

    /* Process dp data */
    cJSON* switch_obj = cJSON_GetObjectItem(dps, SWITCH_DP_ID_KEY);
    if (cJSON_IsTrue(switch_obj)) {
        hardware_switch_set(true);

    } else if (cJSON_IsFalse(switch_obj)) {
        hardware_switch_set(false);
    }

    /* relese cJSON DPS object */
    cJSON_Delete(dps);

    /* Report the received data to synchronize the switch status. */
    tuya_iot_dp_report_json(client, json_dps);
}

/* Tuya OTA event callback */
void user_upgrade_notify_on(tuya_iot_client_t* client, cJSON* upgrade)
{
    TY_LOGI("----- Upgrade information -----");
    TY_LOGI("OTA Channel: %d", cJSON_GetObjectItem(upgrade, "type")->valueint);
    TY_LOGI("Version: %s", cJSON_GetObjectItem(upgrade, "version")->valuestring);
    TY_LOGI("Size: %s", cJSON_GetObjectItem(upgrade, "size")->valuestring);
    TY_LOGI("MD5: %s", cJSON_GetObjectItem(upgrade, "md5")->valuestring);
    TY_LOGI("HMAC: %s", cJSON_GetObjectItem(upgrade, "hmac")->valuestring);
    TY_LOGI("URL: %s", cJSON_GetObjectItem(upgrade, "url")->valuestring);
    TY_LOGI("HTTPS URL: %s", cJSON_GetObjectItem(upgrade, "httpsUrl")->valuestring);
}

/* Tuya SDK event callback */
static void user_event_handler_on(tuya_iot_client_t* client, tuya_event_msg_t* event)
{
    TY_LOGD("Tuya Event ID:%d(%s)", event->id, EVENT_ID2STR(event->id));
    switch (event->id) {
    case TUYA_EVENT_BIND_START:
        TY_LOGI("Device START BIND!");
        /* Print the QRCode for Tuya APP bind */
        break;

    case TUYA_EVENT_MQTT_CONNECTED:
        TY_LOGI("Device MQTT Connected!");
        break;

    case TUYA_EVENT_DP_RECEIVE:
        user_dp_download_on(client, (const char*)event->value.asString);
        break;

    case TUYA_EVENT_UPGRADE_NOTIFY:
        user_upgrade_notify_on(client, event->value.asJSON);
        break;

    case TUYA_EVENT_TIMESTAMP_SYNC:
        TY_LOGI("Sync timestamp:%d", event->value.asInteger);
        break;

    default:
        break;
    }
}

void wifi_info_cb(wifi_info_t wifi_info)
{
    PR_DEBUG("wifi ssid: %s", wifi_info.ssid);
    PR_DEBUG("wifi pwd: %s", wifi_info.pwd);
}

int main(int argc, char** argv)
{
    int ret = OPRT_OK;
    tuya_binding_info_t binding = {0};

    /* Initialize Tuya device configuration */
    ret = tuya_iot_init(&client, &(const tuya_iot_config_t) {
        .software_ver = SOFTWARE_VER,
        .productkey = TUYA_PRODUCT_KEY,
        .uuid = TUYA_DEVICE_UUID,
        .authkey = TUYA_DEVICE_AUTHKEY,
        .event_handler = user_event_handler_on
    });

    assert(ret == OPRT_OK);

    tuya_iot_start(&client);

    /* Start wifi provisioning, ble get wifi provisioning params */
    tuya_wifi_provisioning(&client, WIFI_PROVISIONING_MODE_BLE, &wifi_info_cb);

    for (;;) {
        /* Loop to receive packets, and handles client keepalive */
        tuya_iot_yield(&client);
    }

    return ret;
}
