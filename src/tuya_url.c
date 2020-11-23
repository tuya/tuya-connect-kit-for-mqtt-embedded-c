#include <stdint.h>
#include "tuya_url.h"

#define TY_SMART_DOMAIN_AY "a2.tuyacn.com"		//线上环境
#define TY_SMART_DOMAIN_AZ "a2.tuyaus.com"		//American
#define TY_SMART_DOMAIN_EU "a2.tuyaeu.com"		//Europe

#define TY_MQTT_SERVER_HOST_AY "m2.tuyacn.com"
#define TY_MQTT_SERVER_HOST_AZ "m2.tuyaus.com"
#define TY_MQTT_SERVER_HOST_EU "m2.tuyaeu.com"

#define TUYA_ATOP_SERVER_PORT (443)
#define TUYA_MQTT_SERVER_PORT (8883)


const char* tuya_atop_server_host_get()
{
    return TY_SMART_DOMAIN_AY;
}

uint16_t tuya_atop_server_port_get()
{
    return (uint16_t)TUYA_ATOP_SERVER_PORT;
}

const char* tuya_mqtt_server_host_get()
{
    return TY_MQTT_SERVER_HOST_AY;
}

uint16_t tuya_mqtt_server_port_get()
{
    return (uint16_t)TUYA_MQTT_SERVER_PORT;
}