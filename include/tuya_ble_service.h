#ifndef __TUYA_BLE_SERVICE_H__
#define __TUYA_BLE_SERVICE_H__

#include <stdint.h>
#include "tuya_cloud_types.h"
#include "tuya_wifi_provisioning.h"
#include "tuya_iot.h"

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************
************************macro define************************
***********************************************************/
typedef struct {
    uint8_t *pid;
    uint8_t *uuid;
    uint8_t *auth_key;
}tuya_ble_service_init_params_t;

/***********************************************************
***********************typedef define***********************
***********************************************************/


/***********************************************************
********************function declaration********************
***********************************************************/

typedef void (*ble_token_get_callback)(wifi_info_t wifi_info, tuya_binding_info_t binding_info);

int tuya_ble_service_start(tuya_ble_service_init_params_t *init_params, ble_token_get_callback cb);

void tuya_ble_service_stop(void);

int ble_service_loop(void);

int ble_service_is_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* __TUYA_BLE_SERVICE_H__ */

