[English](./README.md) | [中文](./README_ZH.md)

# 无线配置-低功耗蓝牙配网

> 注意：该示例需要开发者自行适配低功耗蓝牙相关接口（`platform/linux/ble_wrapper.c`）后才能使用。除了蓝牙扫描响应包中的名称外（`tuya_ble_service:266`，名称最多为 5 个字符），广播包和扫描响应包中的其他字段都不可以进行修改，否则 APP 无法通过蓝牙发现设备。

## 接口说明

无线配置提供给开发者使用的接口在 `tuya_wifi_provisioning.h` 文件中。

1. 启动无线网络配置功能，接口如下：

    ```c
    int tuya_wifi_provisioning(tuya_iot_client_t *client, tuya_wifi_provisioning_mode_t mode, wifi_info_get_callback cb);

    ```

    `client`: 客户端对象。

    `mode`: 无线配置模式，当前只支持蓝牙模式 `WIFI_PROVISIONING_MODE_BLE`。

    `cb`: 获取到无线配置信息后会通过该回调将无线配置信息传出。

2. 启动无线网络配置功能后，开发者想要手动停止配置，可调用该函数进行停止。函数原型如下：

    ```c
    int tuya_wifi_provisioning_stop(tuya_iot_client_t *client);
    ```

    `client`: 客户端对象。
