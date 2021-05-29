#ifndef __TUYA_URL_H_
#define __TUYA_URL_H_

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

int tuya_region_regist_key_set(const char* region, const char* regist_key);

int tuya_region_regist_key_remove(void);

int tuya_region_regist_key_load(void);

const char* tuya_atop_server_host_get(void);

uint16_t tuya_atop_server_port_get(void);

const uint8_t* tuya_atop_server_cacert_get();

size_t tuya_atop_server_cacert_length_get();

const char* tuya_mqtt_server_host_get(void);

uint16_t tuya_mqtt_server_port_get(void);

const uint8_t* tuya_mqtt_server_cacert_get(void);

size_t tuya_mqtt_server_cacert_length_get(void);

#ifdef __cplusplus
}
#endif

#endif
