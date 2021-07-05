#ifndef _FILE_DOWNLOAD_H_
#define _FILE_DOWNLOAD_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "matop_service.h"
#include "MultiTimer.h"

typedef enum {
    DL_STATUS_SUCCESS,
    DL_STATUS_EAGAIN,
    DL_STATUS_URL_PARSER_ERROR,
    DL_STATUS_URL_NONSUPPORT,
    DL_STATUS_CONNECT_FAIL,
    DL_STATUS_REQUEST_FAIL,
    DL_STATUS_UNKNOW_FAIL,
} dl_status_t;

typedef enum {
    DL_EVENT_START,
    DL_EVENT_ON_FILESIZE,
    DL_EVENT_ON_DATA,
    DL_EVENT_FINISH,
    DL_EVENT_FAULT,
} file_downlad_event_id_t;

typedef struct {
    file_downlad_event_id_t id;
    void* data;
    size_t data_len;
    size_t offset;
    size_t file_size;
    void* user_data;
} file_download_event_t;

typedef struct file_download_context file_download_context_t;

typedef void (*file_download_event_cb_t)(file_download_context_t* ctx, file_download_event_t* event);

typedef struct {
    char* url;
    size_t file_size;
    size_t range_length;
    uint32_t timeout_ms;
    matop_context_t* transport;
    file_download_event_cb_t event_handler;
    void* user_data;
} file_download_config_t;

struct file_download_context {
    file_download_config_t config;
    file_download_event_t event;
    size_t file_size;
    size_t received_size;
    uint8_t retry;
    uint8_t state;
    uint8_t nextstate;
    MultiTimer timer;
};

int file_download_init(file_download_context_t* ctx, const file_download_config_t* config);

int file_download_start(file_download_context_t* ctx);

int file_download_stop(file_download_context_t* ctx);

int file_download_suspend(file_download_context_t* ctx);

int file_download_yield(file_download_context_t* ctx);

int file_download_free(file_download_context_t* ctx);


#ifdef __cplusplus
}
#endif
#endif