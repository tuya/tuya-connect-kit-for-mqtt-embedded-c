#ifndef __TUYA_URL_H_
#define __TUYA_URL_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TY_SMART_DOMAIN_AY "a2.tuyacn.com"		//线上环境
#define TY_SMART_DOMAIN_AZ "a2.tuyaus.com"		//American
#define TY_SMART_DOMAIN_EU "a2.tuyaeu.com"		//Europe

#define TY_MQTT_SERVER_HOST_AY "m2.tuyacn.com"
#define TY_MQTT_SERVER_HOST_AZ "m2.tuyaus.com"
#define TY_MQTT_SERVER_HOST_EU "m2.tuyaeu.com"

#define TUYA_MQTT_PORT (8883)
#define TUYA_ATOP_PORT (443)

const char* tuya_atop_http_url_get();

const char* tuya_mqtt_server_host_get();

#ifdef __cplusplus
}
#endif

#endif
