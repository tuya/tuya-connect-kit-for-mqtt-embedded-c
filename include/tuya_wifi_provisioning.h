#ifndef __TUYA_WIFI_PROVISIONING_H__
#define __TUYA_WIFI_PROVISIONING_H__

#include <stdint.h>
#include "tuya_cloud_types.h"
#include "tuya_iot.h"

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************
************************macro define************************
***********************************************************/
#define MAX_LENGTH_WIFI_SSID    32
#define MAX_LENGTH_WIFI_PWD     32

/***********************************************************
***********************typedef define***********************
***********************************************************/
typedef struct {
    uint8_t ssid[MAX_LENGTH_WIFI_SSID+1];
    uint8_t pwd[MAX_LENGTH_WIFI_PWD+1];
}wifi_info_t;

/* tuya netcfg mode select */
typedef enum {
    WIFI_PROVISIONING_MODE_BLE,
} tuya_wifi_provisioning_mode_t;

/***********************************************************
********************function declaration********************
***********************************************************/

typedef void (*wifi_info_get_callback)(wifi_info_t wifi_info);

int tuya_wifi_provisioning(tuya_iot_client_t *client, tuya_wifi_provisioning_mode_t mode, wifi_info_get_callback cb);

int tuya_wifi_provisioning_stop(tuya_iot_client_t *client);

#ifdef __cplusplus
}
#endif

#endif /* __TUYA_WIFI_PROVISIONING_H__ */
