/*******************************************************************
*  File: tuya_error_code.h
*  Author: auto generate by tuya code gen system
*  Date: 2020-11-06
*  Description:this file defined the error code of tuya IOT 
*  you can change it manully if needed
*  Copyright(C),2018-2020, tuya inc, www.tuya.comm
*******************************************************************/

#ifndef TUYA_ERROR_CODE_H
#define TUYA_ERROR_CODE_H

#ifdef __cplusplus
extern "C" {
#endif


typedef int OPERATE_RET;


/****************************************************************************
            the error code marco define for module GLOBAL 
****************************************************************************/
#define OPRT_OK                                            (-0x0000)  //执行成功
#define OPRT_COM_ERROR                                     (-0x0001)  //通用错误
#define OPRT_INVALID_PARM                                  (-0x0002)  //无效的入参
#define OPRT_MALLOC_FAILED                                 (-0x0003)  //内存分配失败
#define OPRT_NOT_SUPPORTED                                 (-0x0004)  //不支持
#define OPRT_NETWORK_ERROR                                 (-0x0005)  //网络错误
#define OPRT_NOT_FOUND                                     (-0x0006)  //没有找到对象
#define OPRT_CR_CJSON_ERR                                  (-0x0007)  //创建json对象失败
#define OPRT_CJSON_PARSE_ERR                               (-0x0008)  //json解析失败
#define OPRT_CJSON_GET_ERR                                 (-0x0009)  //获取json对象失败
#define OPRT_CR_MUTEX_ERR                                  (-0x000a)  //创建信号量失败
#define OPRT_SOCK_ERR                                      (-0x000b)  //创建socket失败
#define OPRT_SET_SOCK_ERR                                  (-0x000c)  //socket设置失败
#define OPRT_SOCK_CONN_ERR                                 (-0x000d)  //socket连接失败
#define OPRT_SEND_ERR                                      (-0x000e)  //发送失败
#define OPRT_RECV_ERR                                      (-0x000f)  //接收失败
#define OPRT_RECV_DA_NOT_ENOUGH                            (-0x0010)  //接收数据不完整
#define OPRT_KVS_WR_FAIL                                   (-0x0011)  //KV写失败
#define OPRT_KVS_RD_FAIL                                   (-0x0012)  //KV读失败
#define OPRT_CRC32_FAILED                                  (-0x0013)  //CRC校验失败
#define OPRT_TIMEOUT                                       (-0x0014)  //超时
#define OPRT_INIT_MORE_THAN_ONCE                           (-0x0015)  //初始化超过一次
#define OPRT_INDEX_OUT_OF_BOUND                            (-0x0016)  //索引越界
#define OPRT_RESOURCE_NOT_READY                            (-0x0017)  //资源未完善
#define OPRT_EXCEED_UPPER_LIMIT                            (-0x0018)  //超过上限
#define OPRT_FILE_NOT_FIND                                 (-0x0019)  //文件未找到
#define OPRT_GLOBAL_ERRCODE_MAX_CNT 26


/****************************************************************************
            the error code marco define for module BASE_OS_ADAPTER 
****************************************************************************/
#define OPRT_BASE_OS_ADAPTER_REG_NULL_ERROR                (-0x0100)  //系统适配注册失败
#define OPRT_BASE_OS_ADAPTER_INIT_MUTEX_ATTR_FAILED        (-0x0101)  //初始化同步属性失败
#define OPRT_BASE_OS_ADAPTER_SET_MUTEX_ATTR_FAILED         (-0x0102)  //设置同步属性失败
#define OPRT_BASE_OS_ADAPTER_DESTROY_MUTEX_ATTR_FAILED     (-0x0103)  //销毁同步属性失败
#define OPRT_BASE_OS_ADAPTER_INIT_MUTEX_FAILED             (-0x0104)  //初始化互斥量失败
#define OPRT_BASE_OS_ADAPTER_MUTEX_LOCK_FAILED             (-0x0105)  //互斥量加锁失败
#define OPRT_BASE_OS_ADAPTER_MUTEX_TRYLOCK_FAILED          (-0x0106)  //互斥量尝试加锁失败
#define OPRT_BASE_OS_ADAPTER_MUTEX_LOCK_BUSY               (-0x0107)  //互斥量忙
#define OPRT_BASE_OS_ADAPTER_MUTEX_UNLOCK_FAILED           (-0x0108)  //互斥量解锁失败
#define OPRT_BASE_OS_ADAPTER_MUTEX_RELEASE_FAILED          (-0x0109)  //互斥量释放失败
#define OPRT_BASE_OS_ADAPTER_CR_MUTEX_ERR                  (-0x010a)  //互斥量创建失败
#define OPRT_BASE_OS_ADAPTER_MEM_PARTITION_EMPTY           (-0x010b)  //内存分区空
#define OPRT_BASE_OS_ADAPTER_MEM_PARTITION_FULL            (-0x010c)  //内存分区满
#define OPRT_BASE_OS_ADAPTER_MEM_PARTITION_NOT_FOUND       (-0x010d)  //内存分区不存在
#define OPRT_BASE_OS_ADAPTER_INIT_SEM_FAILED               (-0x010e)  //初始化信号量失败
#define OPRT_BASE_OS_ADAPTER_WAIT_SEM_FAILED               (-0x010f)  //等待信号量失败
#define OPRT_BASE_OS_ADAPTER_POST_SEM_FAILED               (-0x0110)  //释放信号量失败
#define OPRT_BASE_OS_ADAPTER_THRD_STA_UNVALID              (-0x0111)  //线程状态非法
#define OPRT_BASE_OS_ADAPTER_THRD_CR_FAILED                (-0x0112)  //线程创建失败
#define OPRT_BASE_OS_ADAPTER_THRD_JOIN_FAILED              (-0x0113)  //线程JOIN函数调用失败
#define OPRT_BASE_OS_ADAPTER_THRD_SELF_CAN_NOT_JOIN        (-0x0114)  //自身线程不能调用JOIN函数
#define OPRT_BASE_OS_ADAPTER_ERRCODE_MAX_CNT 21


/****************************************************************************
            the error code marco define for module BASE_UTILITIES 
****************************************************************************/
#define OPRT_BASE_UTILITIES_PARTITION_EMPTY                (-0x0200)  //无空闲链表
#define OPRT_BASE_UTILITIES_PARTITION_FULL                 (-0x0201)  //链表已满
#define OPRT_BASE_UTILITIES_PARTITION_NOT_FOUND            (-0x0202)  //链表未遍历到
#define OPRT_BASE_UTILITIES_ERRCODE_MAX_CNT 3


/****************************************************************************
            the error code marco define for module BASE_SECURITY 
****************************************************************************/
#define OPRT_BASE_SECURITY_CRC32_FAILED                    (-0x0300)  //CRC32错误
#define OPRT_BASE_SECURITY_ERRCODE_MAX_CNT 1


/****************************************************************************
            the error code marco define for module MID_TLS 
****************************************************************************/
#define OPRT_MID_TLS_NET_SOCKET_ERROR                      (-0x0a00)  //Failed to open a socket
#define OPRT_MID_TLS_NET_CONNECT_ERROR                     (-0x0a01)  //The connection to the given server / port failed.
#define OPRT_MID_TLS_UNKNOWN_HOST_ERROR                    (-0x0a02)  //Failed to get an IP address for the given hostname.
#define OPRT_MID_TLS_CONNECTION_ERROR                      (-0x0a03)  //TLS连接失败
#define OPRT_MID_TLS_DRBG_ENTROPY_ERROR                    (-0x0a04)  //mbedtls随机种子生成失败
#define OPRT_MID_TLS_X509_ROOT_CRT_PARSE_ERROR             (-0x0a05)  //X509根证书解析失败
#define OPRT_MID_TLS_X509_DEVICE_CRT_PARSE_ERROR           (-0x0a06)  //X509设备证书解析失败
#define OPRT_MID_TLS_CTR_DRBG_ENTROPY_SOURCE_ERROR         (-0x0a07)  //The entropy source failed
#define OPRT_MID_TLS_PK_PRIVATE_KEY_PARSE_ERROR            (-0x0a08)  //秘钥解析失败
#define OPRT_MID_TLS_ERRCODE_MAX_CNT 9


/****************************************************************************
            the error code marco define for module LINK_CORE 
****************************************************************************/
#define OPRT_LINK_CORE_NET_SOCKET_ERROR                    (-0x1e00)  //Failed to open a socket
#define OPRT_LINK_CORE_NET_CONNECT_ERROR                   (-0x1e01)  //The connection to the given server / port failed.
#define OPRT_LINK_CORE_UNKNOWN_HOST_ERROR                  (-0x1e02)  //Failed to get an IP address for the given hostname.
#define OPRT_LINK_CORE_TLS_CONNECTION_ERROR                (-0x1e03)  //TLS连接失败
#define OPRT_LINK_CORE_DRBG_ENTROPY_ERROR                  (-0x1e04)  //mbedtls随机种子生成失败
#define OPRT_LINK_CORE_X509_ROOT_CRT_PARSE_ERROR           (-0x1e05)  //X509根证书解析失败
#define OPRT_LINK_CORE_X509_DEVICE_CRT_PARSE_ERROR         (-0x1e06)  //X509设备证书解析失败
#define OPRT_LINK_CORE_PK_PRIVATE_KEY_PARSE_ERROR          (-0x1e07)  //秘钥解析失败
#define OPRT_LINK_CORE_HTTP_CLIENT_HEADER_ERROR            (-0x1e08)
#define OPRT_LINK_CORE_HTTP_CLIENT_SEND_ERROR              (-0x1e09)
#define OPRT_LINK_CORE_HTTP_RESPONSE_BUFFER_EMPTY          (-0x1e0a)
#define OPRT_LINK_CORE_HTTP_GW_NOT_EXIST                   (-0x1e0b)
#define OPRT_LINK_CORE_MQTT_NOT_AUTHORIZED                 (-0x1e0c)
#define OPRT_LINK_CORE_MQTT_GET_TOKEN_FAIL                 (-0x1e0d)
#define OPRT_LINK_CORE_MQTT_CONNECT_ERROR                  (-0x1e0e)
#define OPRT_LINK_CORE_MQTT_PUBLISH_ERROR                  (-0x1e0f)
#define OPRT_LINK_CORE_ERRCODE_MAX_CNT 16


#define TUYA_CHECK_NULL_RETURN(x, y)\
do{\
    if (NULL == (x)){\
        PR_ERR("%s null", #x);\
        return (y);\
    }\
}while(0)


#define TUYA_CHECK_NULL_GOTO(x, label)\
do{\
    if (NULL == (x)){\
        PR_ERR("%s null", #x);\
        goto label;\
    }\
}while(0)


#define TUYA_CALL_ERR_LOG(func)\
do{\
    rt = (func);\
    if (OPRT_OK != (rt))\
        PR_ERR("ret:%d", rt);\
}while(0)


#define TUYA_CALL_ERR_GOTO(func, label)\
do{\
    rt = (func);\
    if (OPRT_OK != (rt)){\
        PR_ERR("ret:%d", rt);\
        goto label;\
    }\
}while(0)


#define TUYA_CALL_ERR_RETURN(func)\
do{\
    rt = (func);\
    if (OPRT_OK != (rt)){\
       PR_ERR("ret:%d", rt);\
       return (rt);\
    }\
}while(0)


#define TUYA_CALL_ERR_RETURN_VAL(func, y)\
do{\
    rt = (func);\
    if (OPRT_OK != (rt)){\
        PR_ERR("ret:%d", rt);\
        return (y);\
    }\
}while(0)


#define TUYA_CALL_ERR_LOG_SEQ_RETURN_VAL(func, y, point)\
do{\
    rt = (func);\
    if (OPRT_OK != (rt)){\
        PR_ERR("ret:%d", rt);\
        INSERT_ERROR_LOG_SEQ_DEC((point), rt);\
        return (y);\
    }\
}while(0)


#define TUYA_CALL_ERR_LOG_SEQ_RETURN(func, point)\
do{\
    rt = (func);\
    if (OPRT_OK != (rt)){\
        PR_ERR("ret:%d", rt);\
        INSERT_ERROR_LOG_SEQ_DEC((point), rt);\
        return (rt);\
    }\
}while(0)


#define TUYA_CALL_ERR_LOG_SEQ_GOTO(func, label)\
do{\
    rt = (func);\
    if (OPRT_OK != (rt)){\
        PR_ERR("ret:%d", rt);\
        INSERT_ERROR_LOG_SEQ_DEC((point), rt);\
        goto label;\
    }\
}while(0)


#define TUYA_CALL_ERR_LOG_SEQ(func)\
do{\
    rt = (func);\
    if (OPRT_OK != (rt)) {\
        PR_ERR("ret:%d", rt);\
        INSERT_ERROR_LOG_SEQ_DEC((point), rt);\
    }\
}while(0)


#define TUYA_CHECK_NULL_LOG_SEQ_RETURN(x, y, point)\
do{\
    if (NULL == (x)){\
        PR_ERR("%s null", #x);\
        INSERT_ERROR_LOG_SEQ_DEC((point), y);\
        return (y);\
    }\
}while(0)


#define TUYA_CHECK_NULL_LOG_SEQ_GOTO(x, point, label)\
do{\
    if (NULL == (x)){\
        PR_ERR("%s null", #x);\
        INSERT_ERROR_LOG_SEQ_NULL((point));\
        goto label;\
    }\
}while(0)


#ifdef __cplusplus
}
#endif
#endif
