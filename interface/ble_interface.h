#ifndef __BLE_INTERFACE_H__
#define __BLE_INTERFACE_H__

#include <stdint.h>

#include "tuya_cloud_types.h"
#include "tkl_bluetooth_def.h"

#ifdef __cplusplus
extern "C" {
#endif

OPERATE_RET tkl_ble_stack_init(uint8_t role);

OPERATE_RET tkl_ble_stack_deinit(uint8_t role);

OPERATE_RET tkl_ble_gap_disconnect(uint16_t conn_handle, uint8_t hci_reason);

OPERATE_RET tkl_ble_gap_callback_register(const TKL_BLE_GAP_EVT_FUNC_CB gap_evt);

OPERATE_RET tkl_ble_gap_adv_rsp_data_set(TKL_BLE_DATA_T const *p_adv, TKL_BLE_DATA_T const *p_scan_rsp);

OPERATE_RET tkl_ble_gap_adv_start(TKL_BLE_GAP_ADV_PARAMS_T const *p_adv_params);

OPERATE_RET tkl_ble_gap_adv_stop(void);

OPERATE_RET tkl_ble_gatt_callback_register(const TKL_BLE_GATT_EVT_FUNC_CB gatt_evt);

OPERATE_RET tkl_ble_gatts_service_add(TKL_BLE_GATTS_PARAMS_T *p_service);

OPERATE_RET tkl_ble_gatts_value_notify(uint16_t conn_handle, uint16_t char_handle, uint8_t *p_data, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif /* __BLE_INTERFACE_H__ */
