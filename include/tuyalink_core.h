#ifndef TUYA_LINK_CORE_H_
#define TUYA_LINK_CORE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "cJSON.h"
#include "mqtt_client_interface.h"

// data max len
#define TUYA_MQTT_CLIENTID_MAXLEN (128U)
#define TUYA_MQTT_USERNAME_MAXLEN (128U)
#define TUYA_MQTT_PASSWORD_MAXLEN (96U)
#define TUYA_MQTT_DEVICE_ID_MAXLEN (32U)
#define TUYA_MQTT_TOPIC_MAXLEN (64U)
#define TUYA_MQTT_TOPIC_MAXLEN (64U)

typedef struct tuya_mqtt_context tuya_mqtt_context_t;

typedef enum {
    THING_TYPE_MODEL_GET,
    THING_TYPE_MODEL_RSP,
    THING_TYPE_PROPERTY_REPORT,
    THING_TYPE_PROPERTY_REPORT_RSP,
    THING_TYPE_PROPERTY_SET,
    THING_TYPE_PROPERTY_SET_RSP,
    THING_TYPE_PROPERTY_DESIRED_GET,
    THING_TYPE_PROPERTY_DESIRED_GET_RSP,
    THING_TYPE_PROPERTY_DESIRED_DEL,
    THING_TYPE_PROPERTY_DESIRED_DEL_RSP,
    THING_TYPE_EVENT_TRIGGER,
    THING_TYPE_EVENT_TRIGGER_RSP,
    THING_TYPE_ACTION_EXECUTE,
    THING_TYPE_ACTION_EXECUTE_RSP,
    THING_TYPE_BATCH_REPORT,
    THING_TYPE_BATCH_REPORT_RSP,
	THING_TYPE_DEVICE_SUB_BIND,
	THING_TYPE_DEVICE_SUB_BIND_RSP,
	THING_TYPE_DEVICE_SUB_LOGIN,
	THING_TYPE_DEVICE_SUB_LOGOUT,
	THING_TYPE_DEVICE_TOPO_ADD,
	THING_TYPE_DEVICE_TOPO_ADD_RSP,
	THING_TYPE_DEVICE_TOPO_DEL,
	THING_TYPE_DEVICE_TOPO_DEL_RSP,
	THING_TYPE_DEVICE_TOPO_GET,
	THING_TYPE_DEVICE_TOPO_GET_RSP,
    THING_TYPE_MAX,
    THING_TYPE_UNKNOWN,
} tuyalink_thing_type_t;

#define THING_TYPE_ID2STR(S)\
    ((S) == THING_TYPE_MODEL_GET ? "THING_TYPE_MODEL_GET":\
    ((S) == THING_TYPE_MODEL_RSP ? "THING_TYPE_MODEL_RSP":\
    ((S) == THING_TYPE_PROPERTY_REPORT ? "THING_TYPE_PROPERTY_REPORT":\
    ((S) == THING_TYPE_PROPERTY_REPORT_RSP ? "THING_TYPE_PROPERTY_REPORT_RSP":\
    ((S) == THING_TYPE_PROPERTY_SET ? "THING_TYPE_PROPERTY_SET":\
    ((S) == THING_TYPE_PROPERTY_SET_RSP ? "THING_TYPE_PROPERTY_SET_RSP":\
    ((S) == THING_TYPE_PROPERTY_DESIRED_GET ? "THING_TYPE_PROPERTY_DESIRED_GET":\
    ((S) == THING_TYPE_PROPERTY_DESIRED_GET_RSP ? "THING_TYPE_PROPERTY_DESIRED_GET_RSP":\
    ((S) == THING_TYPE_PROPERTY_DESIRED_DEL ? "THING_TYPE_PROPERTY_DESIRED_DEL":\
    ((S) == THING_TYPE_PROPERTY_DESIRED_DEL_RSP ? "THING_TYPE_PROPERTY_DESIRED_DEL_RSP":\
    ((S) == THING_TYPE_EVENT_TRIGGER ? "THING_TYPE_EVENT_TRIGGER":\
    ((S) == THING_TYPE_EVENT_TRIGGER_RSP ? "THING_TYPE_EVENT_TRIGGER_RSP":\
    ((S) == THING_TYPE_ACTION_EXECUTE ? "THING_TYPE_ACTION_EXECUTE":\
    ((S) == THING_TYPE_ACTION_EXECUTE_RSP ? "THING_TYPE_ACTION_EXECUTE_RSP":\
    ((S) == THING_TYPE_BATCH_REPORT ? "THING_TYPE_BATCH_REPORT":\
    ((S) == THING_TYPE_BATCH_REPORT_RSP ? "THING_TYPE_BATCH_REPORT_RSP":\
    ((S) == THING_TYPE_DEVICE_SUB_BIND ? "THING_TYPE_DEVICE_SUB_BIND":\
    ((S) == THING_TYPE_DEVICE_SUB_BIND_RSP ? "THING_TYPE_DEVICE_SUB_BIND_RSP":\
    ((S) == THING_TYPE_DEVICE_SUB_LOGIN ? "THING_TYPE_DEVICE_SUB_LOGIN":\
    ((S) == THING_TYPE_DEVICE_SUB_LOGOUT ? "THING_TYPE_DEVICE_SUB_LOGOUT":\
    ((S) == THING_TYPE_DEVICE_TOPO_ADD ? "THING_TYPE_DEVICE_TOPO_ADD":\
    ((S) == THING_TYPE_DEVICE_TOPO_ADD_RSP ? "THING_TYPE_DEVICE_TOPO_ADD_RSP":\
    ((S) == THING_TYPE_DEVICE_TOPO_DEL ? "THING_TYPE_DEVICE_TOPO_DEL":\
    ((S) == THING_TYPE_DEVICE_TOPO_DEL_RSP ? "THING_TYPE_DEVICE_TOPO_DEL_RSP":\
    ((S) == THING_TYPE_DEVICE_TOPO_GET ? "THING_TYPE_DEVICE_TOPO_GET":\
    ((S) == THING_TYPE_DEVICE_TOPO_GET_RSP ? "THING_TYPE_DEVICE_TOPO_GET_RSP":\
"Unknown"))))))))))))))))))))))))))

typedef struct {
    tuyalink_thing_type_t type;
    char*    device_id;
    char*    msgid;
    uint64_t time;
    uint32_t code;
    cJSON*   data_json;
    char*    data_string;
    bool     ack;
} tuyalink_message_t;

typedef struct {
    const uint8_t* cacert;
    size_t         cacert_len;
    const char*    host;
    uint16_t       port;
    uint32_t       timeout_ms;
    uint32_t       keepalive;
    const char*    device_id;
    const char*    device_secret;
    void*          user_data;
    void           (*on_connected)(tuya_mqtt_context_t* context, void* user_data);
    void           (*on_disconnect)(tuya_mqtt_context_t* context, void* user_data);
    void           (*on_messages)(tuya_mqtt_context_t* context, void* user_data, const tuyalink_message_t* msg);
} tuya_mqtt_config_t;

typedef struct {
    char clientid[TUYA_MQTT_CLIENTID_MAXLEN];
    char username[TUYA_MQTT_USERNAME_MAXLEN];
    char password[TUYA_MQTT_PASSWORD_MAXLEN];
} tuya_mqtt_auth_t;

typedef void(*mqtt_subscribe_message_cb_t)(uint16_t msgid, const mqtt_client_message_t* msg, void* userdata);

typedef struct mqtt_subscribe_handle {
	struct mqtt_subscribe_handle* next;
	char* topic;
    size_t topic_length;
	mqtt_subscribe_message_cb_t cb;
	void* userdata;
} mqtt_subscribe_handle_t;

struct tuya_mqtt_context {
    void* mqtt_client;
    tuya_mqtt_config_t config;
    tuya_mqtt_auth_t mqtt_auth;
    mqtt_subscribe_handle_t* subscribe_list;
    void* user_data;
    uint32_t msgid_inc;
    uint16_t auto_subscribe_id;
    uint8_t state;
    bool manual_disconnect : 1;
    bool is_connected : 1;
    bool auto_subscribe_enabled : 1;
};

int tuya_mqtt_init(tuya_mqtt_context_t* context, const tuya_mqtt_config_t* config);

int tuya_mqtt_init(tuya_mqtt_context_t* context, const tuya_mqtt_config_t* config);

int tuya_mqtt_connect(tuya_mqtt_context_t* context);

int tuya_mqtt_disconnect(tuya_mqtt_context_t* context);

int tuya_mqtt_loop(tuya_mqtt_context_t* context);

int tuya_mqtt_deinit(tuya_mqtt_context_t* context);

bool tuya_mqtt_connected(tuya_mqtt_context_t* context);

int tuyalink_thing_data_model_get(tuya_mqtt_context_t* context, const char* device_id);

int tuyalink_thing_property_report(tuya_mqtt_context_t* context, const char* device_id, const char* data);

int tuyalink_thing_property_report_with_ack(tuya_mqtt_context_t* context, const char* device_id, const char* data);

int tuyalink_thing_event_trigger(tuya_mqtt_context_t* context, const char* device_id, const char* data);

int tuyalink_thing_desired_get(tuya_mqtt_context_t* context, const char* device_id, const char* data);

int tuyalink_thing_batch_report(tuya_mqtt_context_t* context, const char* data);

int tuyalink_subdevice_bind(tuya_mqtt_context_t* context, const char* data);

int tuyalink_subdevice_bind_login(tuya_mqtt_context_t* context, const char* data);

int tuyalink_subdevice_bind_logout(tuya_mqtt_context_t* context, const char* data);

int tuyalink_subdevice_topo_add(tuya_mqtt_context_t* context, const char* data);

int tuyalink_subdevice_topo_delete(tuya_mqtt_context_t* context, const char* data);

int tuyalink_subdevice_topo_get(tuya_mqtt_context_t* context);

#ifdef __cplusplus
}
#endif
#endif
