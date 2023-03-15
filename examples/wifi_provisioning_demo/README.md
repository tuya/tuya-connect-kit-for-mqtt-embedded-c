[English](./README.md) | [中文](./README_ZH.md)

# WiFi provisioning - Low Power Bluetooth

> Note: This example requires the developer to adapt the low-power Bluetooth related interface (`platform/linux/ble_wrapper.c`) before it can be used. Except for the name in the Bluetooth scan response packet (`tuya_ble_service:266`, name up to 5 characters), none of the other fields in the broadcast packet and the scan response packet can be modified, otherwise the APP cannot use Bluetooth to discover the device.

## Interface description

The interface provided to the developer for WiFi provisioning is in the `tuya_wifi_provisioning.h` file.

1. Start the WiFi provisioning function with the following interface.

    ```c
    int tuya_wifi_provisioning(tuya_iot_client_t *client, tuya_wifi_provisioning_mode_t mode, wifi_info_get_callback cb);

    ```

    `client`: client object.

    `mode`: WiFi provisioning mode, currently only supports Bluetooth mode `WIFI_PROVISIONING_MODE_BLE`.

    `cb`: The WiFi configuration information will be passed out through this callback after it is obtained.

2. After starting the WiFi provisioning function, if the developer wants to stop the configuration manually, he can call this function to stop it. The function prototype is as follows.

    ```c
    int tuya_wifi_provisioning_stop(tuya_iot_client_t *client);
    ```

    `client`: Client object.
