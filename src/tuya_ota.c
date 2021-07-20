#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include "tuya_log.h"
#include "tuya_iot.h"
#include "tuya_ota.h"
#include "cJSON.h"
#include "tuya_error_code.h"
#include "system_interface.h"
#include "file_download.h"

#define DEFAULT_DOWNLOAD_TIMEOUT     5000
#define DEFAULT_DOWNLOAD_RANGESIZE   1024

static void file_download_event_cb(file_download_context_t* ctx, file_download_event_t* event)
{
    tuya_ota_handle_t* ota_handle = (tuya_ota_handle_t*)ctx->config.user_data;
    tuya_ota_event_cb_t event_cb = ota_handle->config.event_cb;

    switch(event->id) {
    case DL_EVENT_START:
        TY_LOGD("DL_EVENT_START");
        tuya_ota_upgrade_status_report(ota_handle, TUS_UPGRDING);
        break;

    case DL_EVENT_ON_FILESIZE:
        TY_LOGD("DL_EVENT_ON_FILESIZE");
        ota_handle->event.id = TUYA_OTA_EVENT_START;
        ota_handle->event.file_size = event->file_size;
        ota_handle->event.user_data = ota_handle->config.user_data;
        event_cb(ota_handle, &ota_handle->event);
        break;

    case DL_EVENT_ON_DATA:{
        TY_LOGD("DL_EVENT_ON_DATA:%d", event->data_len);
        ota_handle->event.id = TUYA_OTA_EVENT_ON_DATA;
        ota_handle->event.data = event->data;
        ota_handle->event.data_len = event->data_len;
        ota_handle->event.offset = event->offset;
        event_cb(ota_handle, &ota_handle->event);
        event->offset = ota_handle->event.offset;

        uint8_t percent = ota_handle->file_download.received_size * 100 / ota_handle->file_download.file_size;
        TY_LOGD("File Download Percent: %d%%", percent);
        if (percent - ota_handle->progress_percent > 2) {
            tuya_ota_upgrade_progress_report(ota_handle, percent);
            ota_handle->progress_percent = percent;
        }
        break;
    }

    case DL_EVENT_FINISH:
        TY_LOGD("DL_EVENT_FINISH");
        TY_LOGD("File Download Percent: %d%%", 100);
        tuya_ota_upgrade_progress_report(ota_handle, 100);
        ota_handle->event.id = TUYA_OTA_EVENT_FINISH;
        event_cb(ota_handle, &ota_handle->event);
        tuya_ota_upgrade_status_report(ota_handle, TUS_UPGRD_FINI);
        break;

    default:
        break;
    }
}

int tuya_ota_init(tuya_ota_handle_t* handle, const tuya_ota_config_t* config)
{
    int ret = OPRT_OK;
    handle->config = *config;
    return ret;
}

int tuya_ota_begin(tuya_ota_handle_t* handle, cJSON* upgrade)
{
    int ret = OPRT_OK;

    tuya_iot_client_t* client = handle->config.client;

    file_download_context_t* file_download = &handle->file_download;
    handle->channel = cJSON_GetObjectItem(upgrade, "type")->valueint;
    file_download_init(file_download, &(const file_download_config_t){
        .url = cJSON_GetObjectItem(upgrade, "url")->valuestring,
        .file_size = atol(cJSON_GetObjectItem(upgrade, "size")->valuestring),
        .timeout_ms = handle->config.timeout_ms ? handle->config.timeout_ms:DEFAULT_DOWNLOAD_TIMEOUT,
        .range_length = handle->config.range_size ? handle->config.range_size:DEFAULT_DOWNLOAD_RANGESIZE,
        .transport = &client->matop,
        .event_handler = file_download_event_cb,
        .user_data = handle,
    });

    file_download_start(file_download);

    return ret;
}

int tuya_ota_upgrade_status_report(tuya_ota_handle_t* handle, int status)
{
    int ret = OPRT_OK;
    tuya_iot_client_t* client = handle->config.client;
    ret = matop_service_upgrade_status_update(&client->matop, handle->channel, status);
    return ret;
}

int tuya_ota_upgrade_progress_report(tuya_ota_handle_t* handle, int percent)
{
    tuya_iot_client_t* client = handle->config.client;
    return tuya_mqtt_upgrade_progress_report(&client->mqctx, handle->channel, percent);
}
