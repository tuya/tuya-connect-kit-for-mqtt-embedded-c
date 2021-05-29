# SDK 接入移植指导

## 文档概要
本文档的范围是提供修改此 SDK 中提供的源文件和功能的说明，以使其在各种基于嵌入式C的环境（例如 RTOS，嵌入式Linux）中运行，并进行调整以使用特定的 TLS 和特定硬件平台接口适配，最终使设备连接上涂鸦云，承载业务应用开发需求。


## SDK 包含的内容

该SDK的C代码文件通过以下目录结构提供（请参见文件夹名称后面的注释以获取其内容说明）。

当前 SDK 的目录结构
|--`docs` (开发文档) <br>
|--`libraries` (外部依赖库 - MQTT client, HTTP client, mbedTLS) <br>
|--`middleware` (中间层目录，包含涂鸦需要的 MQTT 和 HTTP 接口适配实现，如果你基于 TLS 层适配，无需修改该目录) <br>
|--`interface` (平台必要移植接口，SDK 功能接口) <br>
|--`include` (SDK 有文件，API接口) <br>
|--`src` (SDK 源代码) <br>
|--`platform` (平台移植接口适配)) <br>
|--`utils` (通用工具模块)) <br>
|--`examples` (例程) <br>

此SDK中的所有 makefile 都是使用上面记录的文件夹结构配置的，因此移动或重命名文件夹将需要对 makefile 进行修改。


## 将SDK集成到你的平台中

本节介绍了为了使 Device SDK 在您的平台上运行而需要实现的 API 调用。SDK 接口遵循驱动程序模型，其中只有原型由 Device SDK 本身定义，而实现则委派给 SDK 的用户以将其调整为所使用的平台。 以下各节列出了设备SDK在任何给定平台上成功运行所需的功能。


### 系统

`void* system_malloc(size_t n);`
分配所需的内存空间，并返回一个指向它的指针。

`void* system_calloc(size_t n, size_t size);`
分配所需的内存空间，并返回一个指向它的指针, 设置分配的内存初始化为零。

`void  system_free(void *ptr);`
释放之前调用 system_malloc，system_calloc 或 system_realloc 所分配的内存空间。

`uint32_t system_ticks();`
系统毫秒滴答计数器。

`uint32_t system_timestamp();`
获取时间戳。


### 网络

SDK 需要通过 MQTT 和 HTTP 协议与服务端交互，所有通信需要基于 TLS 连接，需要你的平台具备 TCP/IP 协议栈实现以下 API，SDK 中包含了 Linux环境下基于 mbedTLS 库作为依赖实现的以下接口的示例，如果您平台已基础 mbedTLS，可使用 Linux 平台下的 platform/linux/mbedtls/network_mbedtls_wrapper.c 接口封装适配快速接入；
如果您的平台没有 mbedTLS 可以参考 [mbedtls 移植指导](https://tls.mbed.org/kb/how-to/how-do-i-port-mbed-tls-to-a-new-environment-OS) 完成移植。

`int network_tls_init(Network *pNetwork, const TLSConnectParams *TLSParams);`
初始化 TLS Network 网络连接管理结构对象。

`int network_tls_connect(Network *pNetwork, const TLSConnectParams *TLSParams);`
建立 TLS 连接，TLSParams 参数为可选参数，如果传入参数为 NULL，默认使用初始化的连接参数。

`int network_tls_write(Network*, unsigned char*, size_t);`
Write to the TLS network buffer.

`int network_tls_read(Network*, unsigned char*,  size_t);`
Read from the TLS network buffer.

`int network_tls_disconnect(Network *pNetwork);`
断开 TLS 连接。

`int network_tls_destroy(Network *pNetwork);`
释放 TLS 连接上下文。


### 数据持久化

SDK 在运行过程中需要持久化储存一些配置信息在你的设备中，需要平台提供持久化的 KV 接口。

`int local_storage_set(const char* key, const uint8_t* buffer, size_t length);`
写入数据到kv系统中。

`int local_storage_get(const char* key, uint8_t* buffer, size_t* length);`
从kv系统中读取数据。

`int local_storage_del(const char* key);`
从kv系统中删除数据。