#ifdef __cplusplus
extern "C" {
#endif

#include "tuya_cloud_types.h"

#include "ble_interface.h"

OPERATE_RET tkl_ble_stack_init(uint8_t role)
{
    return OPRT_OK;
}

OPERATE_RET tkl_ble_stack_deinit(uint8_t role)
{
    return OPRT_OK;
}

OPERATE_RET tkl_ble_gap_callback_register(const TKL_BLE_GAP_EVT_FUNC_CB gap_evt)
{
    return OPRT_OK;
}

OPERATE_RET tkl_ble_gap_adv_rsp_data_set(TKL_BLE_DATA_T const *p_adv, TKL_BLE_DATA_T const *p_scan_rsp)
{
    return OPRT_OK;
}

OPERATE_RET tkl_ble_gap_adv_start(TKL_BLE_GAP_ADV_PARAMS_T const *p_adv_params)
{
    return OPRT_OK;
}

OPERATE_RET tkl_ble_gap_adv_stop(void)
{
    return OPRT_OK;
}

OPERATE_RET tkl_ble_gap_disconnect(uint16_t conn_handle, uint8_t hci_reason)
{
    return OPRT_OK;
}

OPERATE_RET tkl_ble_gatt_callback_register(const TKL_BLE_GATT_EVT_FUNC_CB gatt_evt)
{
    return OPRT_OK;
}

OPERATE_RET tkl_ble_gatts_service_add(TKL_BLE_GATTS_PARAMS_T *p_service)
{
    return OPRT_OK;
}

OPERATE_RET tkl_ble_gatts_value_notify(uint16_t conn_handle, uint16_t char_handle, uint8_t *p_data, uint16_t length)
{
    return OPRT_OK;
}

#ifdef __cplusplus
}
#endif
