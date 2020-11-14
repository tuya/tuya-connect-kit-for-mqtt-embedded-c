## 概述
SDK 使用C语言实现，适用于开发者自主开发设备逻辑业务接入涂鸦云，提供设备激活、DP上下行和OTA等基础业务接口封装，
SDK不依赖具体设备平台及OS环境，仅需要支持TCP/IP协议栈及提供SDK必要的系统依赖接口即可完成接入。


## 平台移植说明
请参考 [SDK 接入移植指导](https://wiki.tuya-inc.com:7799/pages/viewpage.action?pageId=44729115)


## 快速开始

### 创建产品
登录涂鸦 IoT 平台，创建一个产品，获取 Product ID，具体创建详情参考 [涂鸦产品创建](https://developer.tuya.com/cn/docs/iot/configure-in-platform/create-product/create-product?id=K914jp1ijtsfe)。

### 产品功能定义
创建完产品后，根据产品功能需求，在 涂鸦 IoT 平台进行功能数据点（DP）定义，功能点是对产品功能的抽象表示，每种功能都可以通过不同功能类型定义。
目前平台提供：布尔型、数值型、枚举型、故障型、字符串型、透传型这 6 种功能类型，详细说明请参考 [功能定义](https://developer.tuya.com/cn/docs/iot/configure-in-platform/function-definition/define-product-features?id=K97vug7wgxpoq)。

### 获取设备授权信息
授权信息是设备接入涂鸦云的凭证，由 UUID 和 AUTHKEY 组成，授权信息申请请参考 [授权码申请流程]()。

### SDK 下载
~~git clone https://github.com/TuyaInc/tuya-iot-link-sdk-embedded-c.git --recurse-submodules
（暂未上传github）


### SDK 目录结构说明
|--`certs` (设备私钥，设备证书，服务端 CA 根证书) <br>
|--`docs` (开发文档) <br>
|--`libraries` (外部依赖库 - MQTT client, HTTP client, mbedTLS) <br>
|--`interface` (平台必要移植接口，SDK 功能接口) <br>
|--`include` (SDK 有文件，API接口) <br>
|--`src` (SDK 源代码) <br>
|--`platform` (平台移植接口适配)) <br>
|--`utils` (通用工具模块)) <br>
|--`examples` (例程) <br>


### 配置设备信息
将上文申请 Product ID 与授权信息写入 SDK *examples/linux/switch_demo/tuya_config.h* 
中定义的 **TUYA_PRODUCT_KEY**, **TUYA_DEVICE_UUID**, **TUYA_DEVICE_AUTHKEY** 完成基础信息配置。


### Ubuntu 环境下编译执行
#### 安装编译依赖
```bash
sudo apt-get install make cmake libqrencode-dev
```

#### 编译&执行
```bash
mkdir build && cd build
cmake ..
make
./bin/switch_demo
```

### 绑定设备
打开涂鸦智能 APP，可以扫描在 Linux 终端例程程序输出的二维码绑定设备测试。


### 绑定静态二维码生成规则
通过二维码生成工具生成如下 URL 二维码
```url
https://smartapp.tuya.com/s/p?p=<PRODUCT_KEY>&uuid=<UUID>&v=2.0
```
<PRODUCT_KEY> 为你的在 IoT 平台创建产品 ID，<UUID>待绑定设备的 uuid，如下：
```url
https://smartapp.tuya.com/s/p?p=U0fxNCEnZptKnQZy&uuid=f2ef8b136911f4b0&v=2.0
```

## 应用开发快速开始
实例化一个设备对象 tuya_iot_client_t client 并初始化它，tuya_iot_config_t 为初始化PRODUCT ID，授权信息等配置参数：
```c
/* instantiate the client */
tuya_iot_client_t client; 

/* instantiate the config */
tuya_iot_config_t config = {
    .productkey = <Product ID>,
    .uuid = <UUID>,
    .authkey = <AUTHKEY>,
    .event_handler = user_event_handler_cb
};

/* initialize the client */
tuya_iot_init(&client, &config);
```

定义应用层事件回调，回调函数用于应用层接收 SDK 事件通知，如数据功能点(DP)下发，云端连接状态通知：
```c
/* Tuya SDK event callback */
void user_event_handler_on(tuya_iot_client_t* client, tuya_event_msg_t* event)
{
    switch(event->id){
    case TUYA_EVENT_DP_RECEIVE:
        TY_LOGI("DP recv:%s", (const char*)event->data);
        /* 接收到 DP 下发，需要将处理后的状态 DP 数据上报，
        同步 APP 面板状态 */
        break;

    case TUYA_EVENT_MQTT_CONNECTED:
        TY_LOGI("Device MQTT Connected!");
        break;
    ...

    default:
        break;
    }
}
```

启动 Tuya IoT SDK 服务：
```c
tuya_iot_start(&client);
```

Tuya IoT SDK 服务任务，数据接收处理，设备在线保活等任务处理：
```c
tuya_iot_yield(&client);
```

功能点(DP)主动上报：
```c
/* 布尔型数据上报 */
const char bool_value[] = {"{\"101\":true}"};
tuya_iot_dp_report_json(&client, bool_value);

/* 数值型数据上报 */
const char int_value[] = {"{\"102\":123}"};
tuya_iot_dp_report_json(&client, int_value);

/* 字符型数据上报 */
const char string_value[] = {"{\"103\":\"helloworld\"}"};
tuya_iot_dp_report_json(&client, string_value);

/* 枚举型数据上报 */
const char enum_value[] = {"{\"104\":\"auto\"}"};
tuya_iot_dp_report_json(&client, enum_value);

/* RAW 型数据上报 */
const char raw_value[] = {"{\"105\":\"aGVsZA==\"}"};
tuya_iot_dp_report_json(&client, raw_value);

/* 多DP类型数据组合上报 */
const char multiple_value[] = {"{\"101\":true,\"102\":123,\"103\":\"hellowrold\",\"104\":\"auto\",\"105\":\"aGVsZA==\"}"};
tuya_iot_dp_report_json(&client, multiple_value);
```

## Demo 设备例程

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "tuya_log.h"
#include "tuya_config.h"
#include "tuya_iot.h"
#include "cJSON.h"

/* for APP QRCode scan test */
extern void example_qrcode_print(char* productkey, char* uuid);

/* Tuya device handle */
tuya_iot_client_t client;

#define SWITCH_DP_ID_KEY "1"

/* Hardware switch control function */
void hardware_switch_set(bool value)
{
    if (value == true) {
        TY_LOGI("Switch ON");
    } else {
        TY_LOGI("Switch OFF");
    }
}

/* DP data reception processing function */
void tuya_iot_dp_download(tuya_iot_client_t* client, const char* json_dps)
{
    TY_LOGD("Data point download value:%s", json_dps);

    /* Parsing json string to cJSON object */
    cJSON* dps = cJSON_Parse(json_dps);
    if (dps == NULL) {
        TY_LOGE("JSON parsing error, exit!");
        return;
    }

    /* Process dp data */
    cJSON* switch_obj = cJSON_GetObjectItem(dps, SWITCH_DP_ID_KEY);
    if (cJSON_IsTrue(switch_obj)) {
        hardware_switch_set(true);

    } else if (cJSON_IsFalse(switch_obj)) {
        hardware_switch_set(false);
    }

    /* relese cJSON DPS object */
    cJSON_Delete(dps);

    /* Report the received data to synchronize the switch status. */
    tuya_iot_dp_report_json(client, json_dps);
}

/* Tuya SDK event callback */
static void user_event_handler_on(tuya_iot_client_t* client, tuya_event_msg_t* event)
{
    switch(event->id){
    case TUYA_EVENT_DP_RECEIVE:
        tuya_iot_dp_download(client, (const char*)event->data);
        break;

    case TUYA_EVENT_WAIT_ACTIVATE:
        /* Print the QRCode for Tuya APP bind */
        example_qrcode_print(client->productkey, client->uuid);
        break;

    case TUYA_EVENT_MQTT_CONNECTED:
        TY_LOGI("Device MQTT Connected!");
        break;

    default:
        break;
    }
}

int main(int argc, char **argv)
{
    int ret = OPRT_OK;

    /* Initialize Tuya device configuration */
	ret = tuya_iot_init(&client, &(const tuya_iot_config_t){
        .productkey = TUYA_PRODUCT_KEY,
        .uuid = TUYA_DEVICE_UUID,
        .authkey = TUYA_DEVICE_AUTHKEY,
        .event_handler = user_event_handler_on
    });

    assert(ret == OPRT_OK);

    /* Start tuya iot task */
    tuya_iot_start(&client);

	for(;;) {
        /* Loop to receive packets, and handles client keepalive */
		tuya_iot_yield(&client);
	}

	return ret;
}
```