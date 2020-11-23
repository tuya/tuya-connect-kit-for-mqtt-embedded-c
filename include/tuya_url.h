#ifndef __TUYA_URL_H_
#define __TUYA_URL_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const char* tuya_atop_server_host_get();

uint16_t tuya_atop_server_port_get();

const char* tuya_mqtt_server_host_get();

uint16_t tuya_mqtt_server_port_get();

#ifdef __cplusplus
}
#endif

#endif
