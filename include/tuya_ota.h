#ifndef _TUYA_OTA_H_
#define _TUYA_OTA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "file_download.h"
#include "tuya_iot.h"

#define TUS_RD 1
#define TUS_UPGRDING 2
#define TUS_UPGRD_FINI 3
#define TUS_UPGRD_EXEC 4

#define TUS_DOWNLOAD_START 10
#define TUS_DOWNLOAD_COMPLETE 11
#define TUS_UPGRADE_START 12
#define TUS_UPGRADE_SUCCESS 3

#define TUS_DOWNLOAD_ERROR_UNKONW 40
#define TUS_DOWNLOAD_ERROR_LOW_BATTERY 41
#define TUS_DOWNLOAD_ERROR_STORAGE_NOT_ENOUGH 42
#define TUS_DOWNLOAD_ERROR_MALLOC_FAIL 43
#define TUS_DOWNLOAD_ERROR_TIMEOUT 44
#define TUS_DOWNLOAD_ERROR_HMAC 45
#define TUS_UPGRADE_ERROR_LOW_BATTERY 46
#define TUS_UPGRADE_ERROR_MALLOC_FAIL 47
#define TUS_UPGRADE_ERROR_VERSION 48
#define TUS_UPGRADE_ERROR_HMAC 49

typedef enum{
    TUYA_OTA_EVENT_START,
    TUYA_OTA_EVENT_ON_DATA,
    TUYA_OTA_EVENT_FINISH,
    TUYA_OTA_EVENT_FAULT
} tuya_ota_event_id_t;

typedef struct {
    tuya_ota_event_id_t id;
    void* data;
    size_t data_len;
    size_t offset;
    size_t file_size;
    void* user_data;
} tuya_ota_event_t;

typedef struct tuya_ota_handle tuya_ota_handle_t;

typedef void (*tuya_ota_event_cb_t)(tuya_ota_handle_t* handle, tuya_ota_event_t* event);

typedef struct {
    tuya_iot_client_t* client;
    tuya_ota_event_cb_t event_cb;
    size_t range_size;
    uint32_t timeout_ms;
    void* user_data;
} tuya_ota_config_t;


struct tuya_ota_handle {
    tuya_ota_config_t config;
    file_download_context_t file_download;
    tuya_ota_event_t event;
    uint8_t channel;
    uint8_t progress_percent;
};

int tuya_ota_init(tuya_ota_handle_t* handle, const tuya_ota_config_t* config);

int tuya_ota_begin(tuya_ota_handle_t* handle, cJSON* upgrade);

int tuya_ota_upgrade_status_report(tuya_ota_handle_t* handle, int status);

int tuya_ota_upgrade_progress_report(tuya_ota_handle_t* handle, int percent);

#ifdef __cplusplus
}
#endif
#endif