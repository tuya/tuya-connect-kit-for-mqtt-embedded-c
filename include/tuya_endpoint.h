#ifndef __TUYA_ENDPOINT_H_
#define __TUYA_ENDPOINT_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LENGTH_REGION         (2)    // max string length of REGIN IN TOKEN
#define MAX_LENGTH_REGIST         (4)    // max string length of REGIST_KEY IN TOKEN
#define MAX_LENGTH_TUYA_HOST      (64)
#define MAX_LENGTH_ATOP_PATH      (16)

typedef struct {
    char region[MAX_LENGTH_REGION + 1]; // get from token
    struct {
        char host[MAX_LENGTH_TUYA_HOST + 1];
        uint16_t port;
        char path[MAX_LENGTH_ATOP_PATH + 1];
        uint8_t* cert;
        size_t cert_len;
    } atop;
    struct {
        char host[MAX_LENGTH_TUYA_HOST + 1];
        uint16_t port;
        uint8_t* cert;
        size_t cert_len;
    } mqtt;
} tuya_endpoint_t;

int tuya_endpoint_init(void);

int tuya_endpoint_region_regist_set(const char* region, const char* regist_key);

int tuya_endpoint_remove(void);

int tuya_endpoint_update(void);

const tuya_endpoint_t* tuya_endpoint_get(void);

#ifdef __cplusplus
}
#endif

#endif
