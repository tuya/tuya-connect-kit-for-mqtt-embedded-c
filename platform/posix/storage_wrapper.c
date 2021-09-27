#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "log.h"
#include "tuya_error_code.h"
#include "storage_interface.h"
#include "system_interface.h"


int local_storage_set(const char* key, const uint8_t* buffer, size_t length)
{
    if (NULL == key || NULL == buffer) {
        return OPRT_INVALID_PARM;
    }

    FILE* fptr = NULL;
    log_debug("key:%s", key);
    fptr = fopen(key, "wb+");
    if (NULL == fptr) {
        log_error("open file error");
        return OPRT_COM_ERROR;
    } else {
        log_debug("open file OK");
    }

    int file_len = fwrite(buffer, 1, length, fptr);
    fclose(fptr);
    if (file_len != length) {
        log_error("uf_kv_write fail %d", file_len);
        return OPRT_COM_ERROR;
    }
    return OPRT_OK;
}

int local_storage_get(const char* key, uint8_t* buffer, size_t* length)
{
    if (NULL == key || NULL == buffer || NULL == length) {
        return OPRT_INVALID_PARM;
    }

    log_debug("key:%s, len:%d", key, (int)*length);
    FILE* fptr = fopen(key, "rb");
    if (NULL == fptr) {
        *length = 0;
        log_warn("cannot open file");
        return OPRT_COM_ERROR;
    }

    int read_len = *length; // ?
    read_len = fread(buffer, 1, (size_t)read_len, fptr);
    fclose(fptr);
    if (read_len <= 0) {
        *length = 0;
        log_error("read error %d", read_len);
        return OPRT_COM_ERROR;
    }

    *length = read_len;
    return OPRT_OK;
}

int local_storage_del(const char* key)
{
    log_debug("key:%s", key);
    if (remove(key) == 0) {
        log_debug("Deleted successfully");
        return OPRT_OK;
    } else {
        log_error("Unable to delete the file");
        return OPRT_COM_ERROR;
    }
}

#ifdef __cplusplus
}
#endif
