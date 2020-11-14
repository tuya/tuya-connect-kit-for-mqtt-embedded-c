#ifndef __ATOP_BASE_H_
#define __ATOP_BASE_H_

#include <stdint.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* host;
    uint16_t    port;
    const char* path;
    const char* key;
    const char* header;
    const char* api;
    const char* version;
    const char* uuid;
    const char* devid;
    uint32_t timestamp;
    void* data;
    size_t datalen;
    size_t buflen_custom;
    const void* user_data;
} atop_base_request_t;

typedef struct {
    bool success;
    cJSON* result;
    void* errorCode;
    void* errorMsg;
    int32_t t;
    void* user_data;
} atop_base_response_t;

int atop_base_request(const atop_base_request_t* request, atop_base_response_t* response);

void atop_base_response_free(atop_base_response_t* response);

#ifdef __cplusplus
}
#endif
#endif
