#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>

#include "tuya_log.h"
#include "tuya_error_code.h"

#include "system_interface.h"
#include "file_download.h"
#include "tuya_iot.h"
#include "MultiTimer.h"

typedef enum {
    DL_STATE_IDLE,
    DL_STATE_START,
    DL_STATE_FILESIZE_GET,
    DL_STATE_DATE_GET,
    DL_STATE_COMPLETE,
    DL_STATE_SUSPEND,
    DL_STATE_FAULT,
} file_download_state_t;

/*-----------------------------------------------------------*/
/**
 * @brief The size of the range of the file to download, with each request.
 *
 */
#define RANGE_REQUEST_LENGTH_DEFAULT      ( 1024 )

/**
 * @brief Retry requset times config.
 *
 */
#define MAX_DL_RETRY_TIMES  (8u)

/*-----------------------------------------------------------*/
static void file_download_data_on(const uint8_t* data, size_t len, void* user_data)
{
    file_download_context_t* ctx = (file_download_context_t*)user_data;

    if (ctx->config.event_handler) {
        ctx->event.id = DL_EVENT_ON_DATA;
        ctx->event.data = (uint8_t*)data;
        ctx->event.data_len = len;
        ctx->event.offset = ctx->received_size;
        ctx->config.event_handler(ctx, &ctx->event);
    }
    ctx->received_size = ctx->event.offset + len;
    ctx->retry = 0;
}

static void file_donwload_data_recv_cb(atop_base_response_t* response, void* user_data)
{
    file_download_context_t* ctx = (file_download_context_t*)user_data;

    if (response->success == false) {
        ctx->retry++;
        MultiTimerStart(&ctx->timer, 5000);
        return;
    }

    file_download_data_on(response->raw_data, response->raw_data_len, user_data);
    file_download_yield((file_download_context_t*)user_data);
}

static void file_size_result_recv_cb(atop_base_response_t* response, void* user_data)
{
    //TODO
    file_download_yield((file_download_context_t*)user_data);
}

static void file_download_retry_timer_cb(MultiTimer* timer, void* user_data)
{
    file_download_context_t* ctx = (file_download_context_t*)user_data;

    TY_LOGD("On timer retry:%d", ctx->retry);
    if (ctx->retry > MAX_DL_RETRY_TIMES) {
        ctx->state = DL_STATE_FAULT;
    }
    TY_LOGD("go retry request");
    file_download_yield((file_download_context_t*)user_data);
}

int file_download_init(file_download_context_t* ctx, const file_download_config_t* config)
{
    int ret = OPRT_OK;

    memset(ctx, 0, sizeof(file_download_context_t));

    ctx->config = *config;
    ctx->file_size = config->file_size;

    if (ctx->config.range_length == 0) {
        ctx->config.range_length = RANGE_REQUEST_LENGTH_DEFAULT;
    }

    ctx->config.url = system_malloc(strlen(config->url) + 1);
    sprintf(ctx->config.url, "%s", config->url);

    MultiTimerInit(&ctx->timer, 0, file_download_retry_timer_cb, ctx);

    ctx->state = DL_STATE_IDLE;
    ctx->nextstate = DL_STATE_START;

    return ret;
}

int file_download_start(file_download_context_t* ctx)
{
    int ret = OPRT_OK;
    ctx->state = ctx->nextstate;
    ret = file_download_yield(ctx);
    return ret;
}

int file_download_stop(file_download_context_t* ctx)
{
    int ret = OPRT_OK;
    ctx->nextstate = ctx->state;
    ctx->state = DL_STATE_IDLE;
    return ret;
}

int file_download_suspend(file_download_context_t* ctx)
{
    int ret = OPRT_OK;
    ctx->nextstate = ctx->state;
    ctx->state = DL_STATE_IDLE;
    return ret;
}

int file_download_yield(file_download_context_t* ctx)
{
    int ret = OPRT_OK;
    dl_status_t dl_status = DL_STATUS_EAGAIN;

    switch (ctx->state) {
    case DL_STATE_IDLE:
        break;

    case DL_STATE_START:
        if (ctx->config.event_handler) {
            ctx->event.id = DL_EVENT_START;
            ctx->event.user_data = ctx->config.user_data;
            ctx->config.event_handler(ctx, &ctx->event);
        }
        ctx->state = DL_STATE_FILESIZE_GET;

    case DL_STATE_FILESIZE_GET:
        if (ctx->file_size == 0) {
            TY_LOGD("start get the file size.");
            ret = matop_service_file_download_range(ctx->config.transport,
                                                    ctx->config.url,
                                                    0,
                                                    0,
                                                    ctx->config.timeout_ms,
                                                    file_size_result_recv_cb,
                                                    ctx);
            break;
        }
        TY_LOGI("file_size:%d", ctx->file_size);

        /* 如果文件体积小于单次 range 长度，那就调整 range 长度 */
        if (ctx->file_size < ctx->config.range_length) {
            ctx->config.range_length = ctx->file_size;
        }

        if (ctx->config.event_handler) {
            ctx->event.id = DL_EVENT_ON_FILESIZE;
            ctx->event.file_size = ctx->file_size;
            ctx->config.event_handler(ctx, &ctx->event);
        }
        ctx->retry = 0;
        ctx->state = DL_STATE_DATE_GET;
        // break;

    case DL_STATE_DATE_GET: {
        /* File download complete? */
        if (ctx->received_size < ctx->file_size) {
            size_t request_size = (ctx->file_size - ctx->received_size) > ctx->config.range_length?
                                    (ctx->config.range_length) : (ctx->file_size - ctx->received_size);

            ret = matop_service_file_download_range(ctx->config.transport,
                                                    ctx->config.url,
                                                    ctx->received_size,
                                                    ctx->received_size + request_size - 1,
                                                    ctx->config.timeout_ms,
                                                    file_donwload_data_recv_cb,
                                                    ctx);
            if (ret != OPRT_OK) {
                TY_LOGW("file download range get error:%d, goto retry", ret);
                ctx->retry++;
                MultiTimerStart(&ctx->timer, 5000);
                break;
            }

            return DL_STATUS_EAGAIN;
        }

        TY_LOGI("Download Complete!");
        ctx->state = DL_STATE_COMPLETE;
    }

    case DL_STATE_COMPLETE:
        if (ctx->config.event_handler) {
            ctx->event.id = DL_EVENT_FINISH;
            ctx->config.event_handler(ctx, &ctx->event);
        }
        dl_status = DL_STATUS_SUCCESS;
        break;

    case DL_STATE_SUSPEND:
        break;

    case DL_STATE_FAULT:
        TY_LOGE("Download Fault.");
        if (ctx->config.event_handler) {
            ctx->event.id = DL_EVENT_FAULT;
            ctx->config.event_handler(ctx, &ctx->event);
        }
        break;

    default:
        break;
    }

    return dl_status;
}

int file_download_free(file_download_context_t* ctx)
{
    system_free(ctx->config.url);
    return OPRT_OK;
}
