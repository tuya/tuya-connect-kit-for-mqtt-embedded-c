#ifndef __TKL_BLUETOOTH_DEF_H__
#define __TKL_BLUETOOTH_DEF_H__

#include "tuya_cloud_types.h"
#include "tuya_error_code.h"

#define TKL_BLE_ROLE_SERVER                                                 (0x01)  /**< Gatt Server Role, for ble peripheral.*/
#define TKL_BLE_ROLE_CLIENT                                                 (0x02)  /**< Gatt Client Role, for ble central. */

#define TKL_BLE_GAP_ADDR_TYPE_PUBLIC                                        (0x00)  /**< Public (identity) address.*/
#define TKL_BLE_GAP_ADDR_TYPE_RANDOM                                        (0x01)  /**< Random (identity) address. */

#define TKL_BLE_SCAN_TYPE_ACTIVE                                            (0x00)  /**< active scanning, we can scan the respond data, tuya default value */
#define TKL_BLE_SCAN_TYPE_PASSIVE                                           (0x01)  /**< passive scanning */

#define TKL_BLE_GAP_ADV_SET_DATA_SIZE_MAX                                   (31)    /**< Maximum data length for an advertising set.
                                                                                        If more advertising data is required, use extended advertising instead. */
#define TKL_BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_MAX_SUPPORTED                (255)   /**< Maximum supported data length for an extended advertising set. */

/**
 * Advertising types defined in Bluetooth Core Specification v5.0, Vol 6, Part B, Section 4.4.2.
 * */
#define TKL_BLE_GAP_ADV_TYPE_CONN_SCANNABLE_UNDIRECTED                      (0x01)  /**< CONN and scannable undirected
                                                                                        advertising events. */
#define TKL_BLE_GAP_ADV_TYPE_CONN_NONSCANNABLE_DIR_HIGHDUTY_CYCLE           (0x02)  /**< CONN non-scannable directed advertising
                                                                                        events. Advertising interval is less that 3.75 ms.
                                                                                        Use this type for fast reconnections.
                                                                                        @note Advertising data is not supported. */
#define TKL_BLE_GAP_ADV_TYPE_CONN_NONSCANNABLE_DIRECTED                     (0x03)  /**< CONN non-scannable directed advertising
                                                                                        events.
                                                                                        @note Advertising data is not supported. */
#define TKL_BLE_GAP_ADV_TYPE_NONCONN_SCANNABLE_UNDIRECTED                   (0x04)  /**< Non-CONN scannable undirected
                                                                                        advertising events. */
#define TKL_BLE_GAP_ADV_TYPE_NONCONN_NONSCANNABLE_UNDIRECTED                (0x05)  /**< Non-CONN non-scannable undirected
                                                                                        advertising events. */
#define TKL_BLE_GAP_ADV_TYPE_EXTENDED_CONN_NONSCANNABLE_UNDIRECTED          (0x06)  /**< CONN non-scannable undirected advertising
                                                                                        events using extended advertising PDUs. */
#define TKL_BLE_GAP_ADV_TYPE_EXTENDED_CONN_NONSCANNABLE_DIRECTED            (0x07)  /**< CONN non-scannable directed advertising
                                                                                        events using extended advertising PDUs. */
#define TKL_BLE_GAP_ADV_TYPE_EXTENDED_NONCONN_SCANNABLE_UNDIRECTED          (0x08)  /**< Non-CONN scannable undirected advertising
                                                                                        events using extended advertising PDUs.
                                                                                        @note Only scan response data is supported. */
#define TKL_BLE_GAP_ADV_TYPE_EXTENDED_NONCONN_SCANNABLE_DIRECTED            (0x09)  /**< Non-CONN scannable directed advertising
                                                                                        events using extended advertising PDUs.
                                                                                        @note Only scan response data is supported. */
#define TKL_BLE_GAP_ADV_TYPE_EXTENDED_NONCONN_NONSCANNABLE_UNDIRECTED       (0x0A)  /**< Non-CONN non-scannable undirected advertising
                                                                                        events using extended advertising PDUs. */
#define TKL_BLE_GAP_ADV_TYPE_EXTENDED_NONCONN_NONSCANNABLE_DIRECTED         (0x0B)  /**< Non-CONN non-scannable directed advertising
                                                                                        events using extended advertising PDUs. */

#define TKL_BLE_GAP_PHY_AUTO                                                (0x00)  /**< Automatic PHY selection.*/
#define TKL_BLE_GAP_PHY_1MBPS                                               (0x01)  /**< 1 Mbps PHY. */
#define TKL_BLE_GAP_PHY_2MBPS                                               (0x02)  /**< 2 Mbps PHY. */
#define TKL_BLE_GAP_PHY_CODED                                               (0x04)  /**< Coded PHY. */

#define TKL_BLE_GAP_ADV_STATE_IDLE                                          (0x00)  /**< Idle, no advertising */
#define TKL_BLE_GAP_ADV_STATE_START                                         (0x01)  /**< Start Advertising. A temporary state, haven't received the result.*/
#define TKL_BLE_GAP_ADV_STATE_ADVERTISING                                   (0x02)  /**< Advertising State */
#define TKL_BLE_GAP_ADV_STATE_STOP                                          (0x04)  /**< Stop Advertising. A temporary state, haven't received the result.*/

#define TKL_BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION                       (0x13)  /**< Remote User Terminated Connection. */
#define TKL_BLE_HCI_REMOTE_DEV_TERMINATION_DUE_TO_LOW_RESOURCES             (0x14)  /**< Remote Device Terminated Connection due to low resources.*/
#define TKL_BLE_HCI_REMOTE_DEV_TERMINATION_DUE_TO_POWER_OFF                 (0x15)  /**< Remote Device Terminated Connection due to power off. */
#define TKL_BLE_HCI_LOCAL_HOST_TERMINATED_CONNECTION                        (0x16)  /**< Local Host Terminated Connection. */
            
#define TKL_BLE_GATT_SERVICE_MAX_NUM                                        (6)     /**< [20220614] Increase maximum service into 6 */
#define TKL_BLE_GATT_CHAR_MAX_NUM                                           (6)

#define TKL_BLE_GATT_INVALID_HANDLE                                         (0xFFFF) /**< Invalid Connect Handle */
                    
/**@brief GAP address parameters. */
typedef struct {
    UCHAR_T     type;                                   /**< Mac Address Type, Refer to @ TKL_BLE_GAP_ADDR_TYPE_PUBLIC or TKL_BLE_GAP_ADDR_TYPE_RANDOM*/
    UCHAR_T     addr[6];                                /**< Mac Address, Address size, 6 bytes */
} TKL_BLE_GAP_ADDR_T;

typedef struct {
    USHORT_T    length;                                 /**< Ble Data Len */
    UCHAR_T     *p_data;                                /**< Ble Data Pointer */
} TKL_BLE_DATA_T;

 typedef enum {
    TKL_BLE_ADV_DATA,                                   /**< Adv Data - Only */
    TKL_BLE_RSP_DATA,                                   /**< Scan Response Data - Only */
    TKL_BLE_ADV_RSP_DATA,                               /**< Adv Data + Scan Response Data */
    TKL_BLE_NONCONN_ADV_DATA,                           /**< None-Connectable Adv Data - Only */
    TKL_BLE_EXTENDED_ADV_DATA,                          /**< [Bluetooth 5.0]Extended Adv Data - Only */
} TKL_BLE_GAP_ADV_TYPE_E;

/**@brief GAP advertising parameters. */
typedef struct {
    UCHAR_T                 adv_type;                   /**< Adv Type. Refer to TKL_BLE_GAP_ADV_TYPE_CONN_SCANNABLE_UNDIRECTED etc.*/
    TKL_BLE_GAP_ADDR_T      direct_addr;                /**< For Directed Advertising, you can fill in direct address */
    
    USHORT_T                adv_interval_min;           /**< Range: 0x0020 to 0x4000  Time = N * 0.625 msec Time Range: 20 ms to 10.24 sec */
    USHORT_T                adv_interval_max;           /**< Range: 0x0020 to 0x4000  Time = N * 0.625 msec Time Range: 20 ms to 10.24 sec */
    UCHAR_T                 adv_channel_map;            /**< Advertising Channel Map, 0x01 = adv channel index 37,  0x02 = adv channel index 38,
                                                                0x04 = adv channel index 39. Default Value: 0x07*/
} TKL_BLE_GAP_ADV_PARAMS_T;

/**@brief GAP adv report parameters. */
typedef struct {
    TKL_BLE_GAP_ADV_TYPE_E  adv_type;                   /**< Advertising report type. Refer to @TKL_BLE_GAP_ADV_TYPE_E */
    TKL_BLE_GAP_ADDR_T      peer_addr;                  /**< Bluetooth address of the peer device. */
    CHAR_T                  rssi;                       /**< Received Signal Strength Indication in dBm of the last packet received. */
    UCHAR_T                 channel_index;              /**< Channel Index on which the last advertising packet is received (37-39).channel index = 37, it means that we do advertisement in channel 37. */
    TKL_BLE_DATA_T          data;                       /**< Received advertising or scan response data.  */
} TKL_BLE_GAP_ADV_REPORT_T;

/**@brief GAP scanning parameters. */
typedef struct {
    UCHAR_T                 extended;                   /**< If 1, the scanner will accept extended advertising packets.
                                                            If set to 0, the scanner will not receive advertising packets
                                                            on secondary advertising channels, and will not be able
                                                            to receive long advertising PDUs. */
    UCHAR_T                 active : 1;                 /**< [Tuya Need]!!!! If 1, perform active scanning by sending scan requests.
                                                            This parameter is ignored when used with @ref tkl_ble_gap_connect. */
    UCHAR_T                 scan_phys;                  /**< Refer to @TKL_BLE_GAP_PHY_1MBPS. TKL_BLE_GAP_PHY_2MBPS*/
    USHORT_T                interval;                   /**< Scan interval in 625 us units. */
    USHORT_T                window;                     /**< Scan window in 625 us units. */
    USHORT_T                timeout;                    /**< Scan timeout in 10 ms units. */
    UCHAR_T                 scan_channel_map;           /**< Scan Channel Index, refer to @TKL_BLE_GAP_ADV_PARAMS_T*/
} TKL_BLE_GAP_SCAN_PARAMS_T;

/** @brief  Definition of LE connection request parameter.*/
typedef struct {
    USHORT_T                conn_interval_min;          /**< Minimum value for the connection interval.  */
    USHORT_T                conn_interval_max;          /**< Maximum value for the connection interval. */
    USHORT_T                conn_latency;               /**< Slave latency for the connection in number of connection events.*/
    USHORT_T                conn_sup_timeout;           /**< Supervision timeout for the LE Link.*/
    
    USHORT_T                connection_timeout;
} TKL_BLE_GAP_CONN_PARAMS_T;

typedef enum {
    TKL_BLE_UUID_TYPE_16,                               /**< UUID 16 bit */
    TKL_BLE_UUID_TYPE_32,                               /**< UUID 32 bit */
    TKL_BLE_UUID_TYPE_128,                              /**< UUID 128 bit */
} TKL_BLE_UUID_TYPE_E;

/** @brief  Bluetooth Low Energy UUID type, encapsulates both 16-bit and 128-bit UUIDs. */
typedef struct {
    TKL_BLE_UUID_TYPE_E     uuid_type;                  /**< UUID Type, Refer to @TKL_BLE_UUID_TYPE_E */

    union {
        USHORT_T            uuid16;                     /**< 16-bit UUID value  */
        UINT_T              uuid32;                     /**< 32-bit UUID value */
        UCHAR_T             uuid128[16];                /**< Little-Endian UUID bytes. 128bit uuid*/
    }uuid;
} TKL_BLE_UUID_T;

/**< GATT characteristic property bit field values */
typedef enum {
    TKL_BLE_GATT_CHAR_PROP_BROADCAST            = 0x01, /**< If set, permits broadcasts of the Characteristic Value using Server Characteristic Configuration Descriptor. */
    TKL_BLE_GATT_CHAR_PROP_READ                 = 0x02, /**< If set, permits reads of the Characteristic Value */
    TKL_BLE_GATT_CHAR_PROP_WRITE_NO_RSP         = 0x04, /**< If set, permit writes of the Characteristic Value without response */
    TKL_BLE_GATT_CHAR_PROP_WRITE                = 0x08, /**< If set, permits writes of the Characteristic Value with response */
    TKL_BLE_GATT_CHAR_PROP_NOTIFY               = 0x10, /**< If set, permits notifications of a Characteristic Value without acknowledgment */
    TKL_BLE_GATT_CHAR_PROP_INDICATE             = 0x20, /**< If set, permits indications of a Characteristic Value with acknowledgment */
    TKL_BLE_GATT_CHAR_PROP_WRITE_AUTHEN_SIGNED  = 0x40, /**< If set, permits signed writes to the Characteristic Value */
    TKL_BLE_GATT_CHAR_PROP_EXT_PROP             = 0x80, /**< If set, additional characteristic properties are defined in the Characteristic */
}TKL_BLE_CHAR_PROP_TYPE_E;

/**< GATT attribute permission bit field values */
typedef enum {
    TKL_BLE_GATT_PERM_NONE                      = 0x01, /**< No operations supported, e.g. for notify-only */
    TKL_BLE_GATT_PERM_READ                      = 0x02, /**< Attribute read permission. */
    TKL_BLE_GATT_PERM_WRITE                     = 0x04, /**< Attribute write permission. */
    TKL_BLE_GATT_PERM_READ_ENCRYPT              = 0x08, /**< Attribute read permission with encryption. */
    TKL_BLE_GATT_PERM_WRITE_ENCRYPT             = 0x10, /**< Attribute write permission with encryption. */
    TKL_BLE_GATT_PERM_READ_AUTHEN               = 0x20, /**< Attribute read permission with authentication. */
    TKL_BLE_GATT_PERM_WRITE_AUTHEN              = 0x40, /**< Attribute write permission with authentication. */
    TKL_BLE_GATT_PERM_PREPARE_WRITE             = 0x80, /**< Attribute prepare write permission. */
} TKL_BLE_ATTR_PERM_E;

typedef struct {
    USHORT_T        handle;                             /**< [Output] After init the characteristic, we will get the char-handle, we need to restore it */

    TKL_BLE_UUID_T  char_uuid;                          /**< Characteristics UUID */
    UCHAR_T         property;                           /**< Characteristics property , Refer to TKL_BLE_CHAR_PROP_TYPE_E */
    UCHAR_T         permission;                         /**< Characteristics value attribute permission */
    UCHAR_T         value_len;                          /**< Characteristics value length */
} TKL_BLE_CHAR_PARAMS_T;

typedef enum {
    TKL_BLE_UUID_UNKNOWN                    = 0x0000,   /**< Reserved UUID. */
    TKL_BLE_UUID_SERVICE_PRIMARY            = 0x2800,   /**< Primary Service. */
    TKL_BLE_UUID_SERVICE_SECONDARY          = 0x2801,   /**< Secondary Service. */
    TKL_BLE_UUID_SERVICE_INCLUDE            = 0x2802,   /**< Include. */
    TKL_BLE_UUID_CHARACTERISTIC             = 0x2803,   /**< Characteristic. */
} TKL_BLE_SERVICE_TYPE_E;

typedef struct {
    USHORT_T                    handle;                 /**< After init the service, we will get the svc-handle */

    TKL_BLE_UUID_T              svc_uuid;               /**< Service UUID */
    TKL_BLE_SERVICE_TYPE_E      type;                   /**< Service Type */
    
    UCHAR_T                     char_num;               /**< Number of characteristic */
    TKL_BLE_CHAR_PARAMS_T       *p_char;                /**< Pointer of characteristic */
} TKL_BLE_SERVICE_PARAMS_T;

typedef struct {
    UCHAR_T                     svc_num;                /**< If we only use service(0xFD50), the svc_num will be set into 1 */
    TKL_BLE_SERVICE_PARAMS_T    *p_service;
} TKL_BLE_GATTS_PARAMS_T;

typedef enum {
    TKL_BLE_EVT_STACK_INIT = 0x01,                      /**< Init Bluetooth Stack, return  refer@TKL_BLE_GAP_PARAMS_EVT_T.result */
    
    TKL_BLE_EVT_STACK_DEINIT,                           /**< Deinit Bluetooth Stack, Requirements from Tuyaos ZT*/

    TKL_BLE_EVT_STACK_RESET,                            /**< Reset Bluetooth Stack, Requirements from Bluetooth Gateway */

    TKL_BLE_GAP_EVT_CONNECT,                            /**< Connected as peripheral role */

    TKL_BLE_GAP_EVT_DISCONNECT,                         /**< Disconnected */

    TKL_BLE_GAP_EVT_ADV_STATE,                          /**< Advertising State */

    TKL_BLE_GAP_EVT_ADV_REPORT,                         /**< Scan result report */

    TKL_BLE_GAP_EVT_CONN_PARAM_REQ,                     /**< Parameter update request */

    TKL_BLE_GAP_EVT_CONN_PARAM_UPDATE,                  /**< Parameter update successfully */
    
    TKL_BLE_GAP_EVT_CONN_RSSI,                          /**< Got RSSI value of link peer device */
} TKL_BLE_GAP_EVT_TYPE_E;

typedef enum {      
    TKL_BLE_GATT_EVT_MTU_REQUEST = 0x01 ,               /**< MTU exchange request event, For Ble peripheral, we need to do reply*/

    TKL_BLE_GATT_EVT_MTU_RSP,                           /**< MTU exchange respond event, For Ble Central, the ble central has finished the MTU-Request */

    TKL_BLE_GATT_EVT_PRIM_SEV_DISCOVERY,                /**< [Ble Central] Discovery Service */

    TKL_BLE_GATT_EVT_CHAR_DISCOVERY,                    /**< [Ble Central] Discovery Characteristics*/

    TKL_BLE_GATT_EVT_CHAR_DESC_DISCOVERY,               /**< [Ble Central] Discovery descriptors */

    TKL_BLE_GATT_EVT_NOTIFY_TX,                         /**< [Ble peripheral] Transfer data Callback, only report Result */

    TKL_BLE_GATT_EVT_WRITE_REQ,                         /**< [Ble Peripheral] Get Client-Write Char Request*/

    TKL_BLE_GATT_EVT_NOTIFY_INDICATE_RX,                /**< [Ble Central] Get Notification or Indification data */

    TKL_BLE_GATT_EVT_READ_RX,                           /**< [Ble Central] Get Char-Read Data */

    TKL_BLE_GATT_EVT_SUBSCRIBE,                         /**< [Ble Peripheral] Subscribe Request*/

    TKL_BLE_GATT_EVT_READ_CHAR_VALUE,                   /**< [Ble Peripheral] read char value event*/

} TKL_BLE_GATT_EVT_TYPE_E;

typedef struct {
    UCHAR_T                         role;               /**< BLE role for this connection, see @ref TKL_BLE_ROLE_SERVER, or TKL_BLE_ROLE_CLIENT */
    TKL_BLE_GAP_ADDR_T              peer_addr;          /**< Reserved, [Ble Central],For some platform, we will get the peer address after connect one device */
    TKL_BLE_GAP_CONN_PARAMS_T       conn_params;        /**< Report Connection Parameters */
} TKL_BLE_GAP_CONNECT_EVT_T;

typedef struct {
    UCHAR_T                         role;               /**< BLE role for this disconnection */
    INT_T                           reason;             /**< Report Disconnection Reason */
} TKL_BLE_GAP_DISCONNECT_EVT_T;

typedef struct {
    USHORT_T                        char_handle;        /**< Notify Characteristic Handle */
    INT_T                           result;             /**< Notify Result */
} TKL_BLE_NOTIFY_RESULT_EVT_T;

typedef struct {
    UCHAR_T                         svc_num;            /**< Number of Services */

    struct {
        TKL_BLE_UUID_T              uuid;               /**< Discovery Service UUID */
        USHORT_T                    start_handle;       /**< Discovery Start Handle */
        USHORT_T                    end_handle;         /**< Discovery End Handle */
    }services[TKL_BLE_GATT_SERVICE_MAX_NUM];

} TKL_BLE_GATT_SVC_DISC_TYPE_T;

typedef struct {
    UCHAR_T                         char_num;           /**< Number of Characteristics */

    struct {
        TKL_BLE_UUID_T              uuid;               /**< Discovery Service UUID */
        USHORT_T                    handle;             /**< Discovery Char Handle */
    }characteristics[TKL_BLE_GATT_CHAR_MAX_NUM];
} TKL_BLE_GATT_CHAR_DISC_TYPE_T;

typedef struct {
    USHORT_T                        cccd_handle;        /**< Discovery Descriptor Handle, Return CCCD Handle */
} TKL_BLE_GATT_DESC_DISC_TYPE_T;

typedef struct {
    USHORT_T                        char_handle;        /**< Specify one characteristic handle */
    TKL_BLE_DATA_T                  report;             /**< Report Data, Refer to @ TKL_BLE_DATA_T */
} TKL_BLE_DATA_REPORT_T;

typedef struct {
    TKL_BLE_GAP_EVT_TYPE_E              type;           /**< Gap Event */
    USHORT_T                            conn_handle;    /**< Connection Handle */
    INT_T                               result;         /**< Will Refer to HOST STACK Error Code */

    union {
        TKL_BLE_GAP_CONNECT_EVT_T       connect;        /**< Receive connect callback, This value can be used with TKL_BLE_EVT_PERIPHERAL_CONNECT and TKL_BLE_EVT_CENTRAL_CONNECT_DISCOVERY*/
        TKL_BLE_GAP_DISCONNECT_EVT_T    disconnect;     /**< Receive disconnect callback*/
        TKL_BLE_GAP_ADV_REPORT_T        adv_report;     /**< Receive Adv and Respond report*/
        TKL_BLE_GAP_CONN_PARAMS_T       conn_param;     /**< We will update connect parameters.This value can be used with TKL_BLE_EVT_CONN_PARAM_REQ and TKL_BLE_EVT_CONN_PARAM_UPDATE*/
        CHAR_T                          link_rssi;      /**< Peer device RSSI value */
    }gap_event;
} TKL_BLE_GAP_PARAMS_EVT_T;
typedef struct {
    USHORT_T                        char_handle;                /**< Specify one characteristic handle */
    UCHAR_T                         reason;
    UCHAR_T                         prev_notify     :    1;     /**< previously subscribed */
    UCHAR_T                         cur_notify      :    1;     /** currently notifications. */
    UCHAR_T                         prev_indicate   :    1;     /** previously indications. */
    UCHAR_T                         cur_indicate    :    1;     /** currently subscribed to indications. */
} TKL_BLE_SUBSCRBE_EVT_T;
typedef struct {
    USHORT_T                        char_handle;                /**< Specify one characteristic handle */
    USHORT_T                        offset;
} TKL_BLE_READ_CHAR_EVT_T;

typedef struct {
    TKL_BLE_GATT_EVT_TYPE_E             type;           /**< Gatt Event */
    USHORT_T                            conn_handle;    /**< Connection Handle */
    INT_T                               result;         /**< Will Refer to HOST STACK Error Code */

    union {
        USHORT_T                        exchange_mtu;   /**< This value can be used with TKL_BLE_GATT_EVT_MTU_REQUEST and TKL_BLE_GATT_EVT_MTU_RSP*/
        TKL_BLE_GATT_SVC_DISC_TYPE_T    svc_disc;       /**< Discovery All Service */
        TKL_BLE_GATT_CHAR_DISC_TYPE_T   char_disc;      /**< Discovery Specific Characteristic */
        TKL_BLE_GATT_DESC_DISC_TYPE_T   desc_disc;      /**< Discovery Specific Descriptors*/
        TKL_BLE_NOTIFY_RESULT_EVT_T     notify_result;  /**< This value can be used with TKL_BLE_GATT_EVT_NOTIFY_TX*/
        TKL_BLE_DATA_REPORT_T           write_report;   /**< This value can be used with TKL_BLE_GATT_EVT_WRITE_REQ*/
        TKL_BLE_DATA_REPORT_T           data_report;    /**< This value can be used with TKL_BLE_GATT_EVT_NOTIFY_INDICATE_RX*/
        TKL_BLE_DATA_REPORT_T           data_read;      /**< After we do read attr in central mode, we will get the callback*/
        TKL_BLE_SUBSCRBE_EVT_T          subscribe;      /**< ccc callback event, used with TKL_BLE_GATT_EVT_SUBSCRIBE*/
        TKL_BLE_READ_CHAR_EVT_T         char_read;      /**< read char event, used with TKL_BLE_GATT_EVT_READ_CHAR_VALUE*/
    }gatt_event;
} TKL_BLE_GATT_PARAMS_EVT_T;

/**< GAP Callback Register function definition */
typedef VOID(*TKL_BLE_GAP_EVT_FUNC_CB)(TKL_BLE_GAP_PARAMS_EVT_T *p_event);

/**< GATT Callback Register function definition */
typedef VOID(*TKL_BLE_GATT_EVT_FUNC_CB)(TKL_BLE_GATT_PARAMS_EVT_T *p_event);

#endif

