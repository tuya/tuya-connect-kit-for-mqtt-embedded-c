#ifndef TUYA_CONFIG_DEFAULTS_H_
#define TUYA_CONFIG_DEFAULTS_H_

/**
 * @brief The buffer pre-allocated during activation, 
 * the more function points, the larger the buffer needed.
 * 
 */
#ifndef ACTIVATE_BUFFER_LENGTH
    #define ACTIVATE_BUFFER_LENGTH (8192U)
#endif

/**
 * @brief MQTT socket recv blocking time.
 * 
 */
#ifndef MQTT_RECV_BLOCK_TIME_MS
    #define MQTT_RECV_BLOCK_TIME_MS (2000U)
#endif

/**
 * @brief MQTT keep alive period.
 * 
 */
#ifndef MQTT_KEEPALIVE_INTERVALIN
    #define MQTT_KEEPALIVE_INTERVALIN (120)
#endif

/**
 * @brief MQTT buffer size.
 * 
 */
#ifndef MQTT_BUFFER_SIZE
    #define MQTT_BUFFER_SIZE (1024U*2)
#endif

/**
 * @brief Defaults HTTP response timeout.
 * 
 */
#ifndef DEFAULT_HTTP_TIMEOUT
    #define DEFAULT_HTTP_TIMEOUT (5000U)
#endif

/**
 * @brief Defaults auto check upgrade interval.
 * 
 */
#ifndef AUTO_UPGRADE_CHECK_INTERVAL
    #define AUTO_UPGRADE_CHECK_INTERVAL (1000U*60*60*24) // 24 hours
#endif

#endif /* ifndef TUYA_CONFIG_DEFAULTS_H_ */
