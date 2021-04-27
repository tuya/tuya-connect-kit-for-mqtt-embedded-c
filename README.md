# Tuya IoT Link SDK for Embedded C(beta)
## Table of Contents

- [Tuya IoT Link SDK for Embedded C(beta)](#tuya-iot-link-sdk-for-embedded-cbeta)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Clone the repository](#clone-the-repository)
    - [Compiling](#compiling)
    - [Run the demo](#run-the-demo)
  - [Usage example](#usage-example)
  - [License](#license)


## Introduction
Tuya IoTOS Link SDK
provide core capabilities like device connection, uplink and downlink communication and OTA across platforms and operating systems.
The SDK is implemented in C language and does not depend on the specific device platform and OS environment. It only needs to support the TCP/IP protocol stack and provide the necessary system-dependent interfaces of the SDK to complete the integration.


## Getting Started

### Prerequisites

Ubuntu & Debian
```sh
sudo apt-get install make cmake libqrencode-dev
```

### Clone the repository
```sh
git clone https://github.com/tuya/tuya-iot-link-sdk-embedded-c.git --recurse-submodules
```

### Compiling
```sh
mkdir build && cd build
cmake ..
make
```

### Run the demo
```sh
./bin/switch_demo
```

## Usage example

1. Initialize a client object tuya_iot_client_t client and initialize it, tuya_iot_config_t is to initialize PRODUCT ID, authorization information and other configuration parameters:
```c
/* instantiate the client */
tuya_iot_client_t client; 

/* instantiate the config */
tuya_iot_config_t config = {
    .software_ver = "1.0.0",
    .productkey = <Product ID>,
    .uuid = <UUID>,
    .authkey = <AUTHKEY>,
    .event_handler = user_event_handler_on
};

/* initialize the client */
tuya_iot_init(&client, &config);
```

2. Define application layer event callbacks. The callback function is used for the application layer to receive SDK event notifications, such as data point (DP) delivery and cloud connection status notifications:
```c
/* Tuya SDK event callback */
void user_event_handler_on(tuya_iot_client_t* client, tuya_event_msg_t* event)
{
    switch(event->id){
    case TUYA_EVENT_DP_RECEIVE:
        TY_LOGI("DP recv:%s", (const char*)event->data);
        /* After receiving the DP distribution, 
        the DP data needs to be reported to synchronize the APP status. */
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

3. Start the Tuya Link SDK service:
```c
tuya_iot_start(&client);
```

4. Loop called to yield the current thread to the underlying Tuya Link SDK client:
```c
tuya_iot_yield(&client);
```

Report example:
```c
/* Boolean */
const char bool_value[] = {"{\"101\":true}"};
tuya_iot_dp_report_json(&client, bool_value);

/* Integer */
const char int_value[] = {"{\"102\":123}"};
tuya_iot_dp_report_json(&client, int_value);

/* String*/
const char string_value[] = {"{\"103\":\"helloworld\"}"};
tuya_iot_dp_report_json(&client, string_value);

/* Enum */
const char enum_value[] = {"{\"104\":\"auto\"}"};
tuya_iot_dp_report_json(&client, enum_value);

/* RAW */
const char raw_value[] = {"{\"105\":\"aGVsZA==\"}"};
tuya_iot_dp_report_json(&client, raw_value);

/* Multiple combinations */
const char multiple_value[] = {"{\"101\":true,\"102\":123,\"103\":\"hellowrold\",\"104\":\"auto\",\"105\":\"aGVsZA==\"}"};
tuya_iot_dp_report_json(&client, multiple_value);
```

## License

Distributed under the MIT License. See `LICENSE` for more information.
