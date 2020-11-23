#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "tuya_error_code.h"
#include "tuya_iot.h"
#include "tuya_log.h"
#include "tuya_url.h"

#include "system_interface.h"
#include "storage_interface.h"
#include "atop_base.h"
#include "atop_service.h"
#include "cJSON.h"

#define ACTIVATE_MAXLEN             (255)
#define SCHEMA_MAXLEN               (4096)
#define TOKEN_LEN_MIN               (8)
#define MQTT_NETCFG_TIMEOUT         (5000)
#define MQTT_RECV_TIMEOUT           (2000)
#define MAX_LENGTH_ACTIVATE_BUFFER  (1024*8)

extern const char tuya_rootCA_pem[];
static int run_state_netcfg_mode(tuya_iot_client_t* client);

typedef enum {
    STATE_INIT,
    STATE_IDLE,
    STATE_START,
    STATE_READY_WAITING,
    STATE_STARTUP,
    STATE_RESTART,
    STATE_RESET,
    STATE_STOP,
    STATE_EXIT,

    STATE_NETCFG_MODE,
    STATE_NETCFG_START,
    STATE_NETCFG_WIFI_CONNECTING,
    STATE_NETCFG_ACTIVATE_START,
    STATE_NETCFG_ACTIVATE_PENDING,
    STATE_NETCFG_COMPLETE,
    STATE_NETCFG_TIMEOUT,
    STATE_NETCFG_FAILED,

    STATE_NETCFG_CONNECTED_WAIT,
    STATE_NETCFG_TOKEN_WAIT,
    STATE_NETCFG_DISCONNECT_WAIT,

    STATE_OTA_MODE,
    STATE_OTA_MODE_START,
    STATE_OTA_MODE_RUNING,
    STATE_OTA_MODE_EXIT,

    STATE_DYNAMIC_CFG_GET,
    STATE_NTP_TIME_SYNC,

    STATE_MQTT_CONNECT_START,
    STATE_MQTT_CONNECTING,
} tuya_run_state_t;


static int iot_dispatch_event(tuya_iot_client_t* client)
{
    if (client->config.event_handler) {
        client->config.event_handler(client, &client->event);
    }
    return OPRT_OK;
}

static int activate_json_string_parse(const char* str, activated_params_t* out)
{
    cJSON* root = cJSON_Parse(str);
    if (NULL == root) {
        cJSON_Delete(root);
        return OPRT_CJSON_PARSE_ERR;
    }

    if (cJSON_GetObjectItem(root, "devId") == NULL || \
        cJSON_GetObjectItem(root, "secKey") == NULL || \
        cJSON_GetObjectItem(root, "localKey") == NULL || \
        cJSON_GetObjectItem(root, "schemaId") == NULL) {
        cJSON_Delete(root);
        return OPRT_CJSON_GET_ERR;
    }
    
    strcpy(out->devid, cJSON_GetObjectItem(root, "devId")->valuestring);
    strcpy(out->seckey, cJSON_GetObjectItem(root, "secKey")->valuestring);
    strcpy(out->localkey, cJSON_GetObjectItem(root, "localKey")->valuestring);
    strcpy(out->schemaId, cJSON_GetObjectItem(root, "schemaId")->valuestring);
    cJSON_Delete(root);
    return OPRT_OK;
}

static int activated_data_read(const char* storage_key, activated_params_t* out)
{
    int rt = OPRT_OK;
    size_t readlen = ACTIVATE_MAXLEN;
    char* readbuf = system_calloc(sizeof(char), ACTIVATE_MAXLEN);
    if (NULL == readbuf) {
        TY_LOGE("activate_string malloc fail.");
        return rt;
    }

    /* Try read activate config data */
    rt = local_storage_get((const char*)storage_key, (uint8_t*)readbuf, &readlen);
    if (OPRT_OK != rt) {
        TY_LOGW("activate config not found:%d", rt);
        system_free(readbuf);
        return rt;
    }

    /* Parse activate json string */
    rt = activate_json_string_parse((const char*)readbuf, out);
    system_free(readbuf);
    if (OPRT_OK != rt) {
        TY_LOGE("activate_json_string_parse fail:%d", rt);
        return rt;
    }

    return rt;
}

static int run_state_startup(tuya_iot_client_t* client)
{
    int rt = OPRT_OK;

    /* loading activated info */
    const char* activate_data_key = client->config.uuid;
    rt = activated_data_read(activate_data_key, &client->activate);
    if (OPRT_OK != rt) {
        TY_LOGW("activated data read fail:%d", rt);
        TY_LOGI("go reactivate..");
        client->state = STATE_NETCFG_MODE;
        client->netfcg_state = STATE_NETCFG_START;
        return rt;
    }

    /* Dump info */
    TY_LOGD("devId: %s", client->activate.devid);
    TY_LOGD("secKey: %s", client->activate.seckey);
    TY_LOGD("localKey: %s", client->activate.localkey);

    /* client activated, go mqtt connect */
    client->state = STATE_MQTT_CONNECT_START;
    return rt;
}

static void mqtt_dp_receive_on(tuya_mqtt_event_t* ev)
{
    tuya_iot_client_t* client = ev->user_data;
    cJSON* data = (cJSON*)(ev->data);
    if (NULL == cJSON_GetObjectItem(data, "dps")) {
        TY_LOGE("not found dps");
        return;
    }

    /* Get dps string json */
    char* dps_string = cJSON_PrintUnformatted(cJSON_GetObjectItem(data, "dps"));
	TY_LOGV("dps: \r\n%s", dps_string);

    /* Send DP string format event*/
    client->event.id = TUYA_EVENT_DP_RECEIVE;
    client->event.data = dps_string;
    client->event.length = strlen(dps_string);
    iot_dispatch_event(client);
    system_free(dps_string);

    /* Send DP cJSON format event*/
    client->event.id = TUYA_EVENT_DP_RECEIVE_CJSON;
    client->event.data = cJSON_GetObjectItem(data, "dps");
    client->event.length = 0;
    iot_dispatch_event(client);
}

static void mqtt_reset_cmd_on(tuya_mqtt_event_t* ev)
{
    tuya_iot_client_t* client = ev->user_data;
    cJSON* data = (cJSON*)(ev->data);

    if (NULL == cJSON_GetObjectItem(data, "gwId")) {
        TY_LOGE("not found gwId");
    }

    TY_LOGW("Reset id:%s", cJSON_GetObjectItem(data, "gwId")->valuestring);

    /* DP event send */
    client->event.id = TUYA_EVENT_RESET;

    if (cJSON_GetObjectItem(data, "type") && \
        strcmp(cJSON_GetObjectItem(data, "type")->valuestring, "reset_factory") == 0)  {
        TY_LOGD("cmd is reset factory, ungister");
        client->event.data = (void*)GW_REMOTE_RESET_FACTORY;
    } else {
        TY_LOGD("unactive");
        client->event.data = (void*)GW_REMOTE_UNACTIVE;
    }
    iot_dispatch_event(client);

    client->state = STATE_RESET;
    TY_LOGI("STATE_RESET...");
}

static int run_state_mqtt_connect_start(tuya_iot_client_t* client)
{
    int rt = OPRT_OK;

    /* mqtt init */
    rt = tuya_mqtt_init(&client->mqctx, &(const tuya_mqtt_config_t){
        .rootCA = tuya_rootCA_pem,
        .host = tuya_mqtt_server_host_get(),
        .port = tuya_mqtt_server_port_get(),
        .devid = client->activate.devid,
        .seckey = client->activate.seckey,
        .localkey = client->activate.localkey,
        .timeout = MQTT_RECV_TIMEOUT,
    });
    if (OPRT_OK != rt) {
        TY_LOGE("tuya mqtt init error:%d", rt);
        return rt;
    }

    rt = tuya_mqtt_start(&client->mqctx);
    if (OPRT_OK != rt) {
        TY_LOGE("tuya mqtt start error:%d", rt);
        tuya_mqtt_destory(&client->mqctx);
        client->state = STATE_RESTART;
        return rt;
    }

    /* callback register */
    tuya_mqtt_protocol_register(&client->mqctx, PRO_CMD, mqtt_dp_receive_on, client);
    tuya_mqtt_protocol_register(&client->mqctx, PRO_GW_RESET, mqtt_reset_cmd_on, client);

    client->state = STATE_MQTT_CONNECTING;
    return rt;
}

static int run_state_restart(tuya_iot_client_t* client)
{
    TY_LOGW("SYSTEM REBOOT!");
    system_reboot();
    return OPRT_OK;
}

static int run_state_reset(tuya_iot_client_t* client)
{
    // reset call
    tuya_mqtt_stop(&client->mqctx);

    local_storage_del((const char*)(client->activate.schemaId));
    local_storage_del((const char*)(client->config.uuid));

    client->state = STATE_RESTART;
    return OPRT_OK;
}

int tuya_iot_init(tuya_iot_client_t* client, const tuya_iot_config_t* config)
{
    int ret = OPRT_OK;
    TY_LOGI("tuya_iot_init");
    if (NULL == client || NULL == config) {
        return OPRT_INVALID_PARM;
    }

    /* config params check */
    if (NULL == config->productkey || NULL == config->uuid || NULL == config->authkey) {
        return OPRT_INVALID_PARM;
    }

    /* Initialize all tuya_iot_client_t structs to 0. */
    memset(client, 0, sizeof(tuya_iot_client_t));

    /* Save the client config */
    client->config = *config;

    /* Config param dump */
    TY_LOGD("software_ver:%s", client->config.software_ver);
    TY_LOGD("productkey:%s", client->config.productkey);
    TY_LOGD("uuid:%s", client->config.uuid);
    TY_LOGD("authkey:%s", client->config.authkey);

    /* cJSON init */
    cJSON_Hooks hooks = {
        .malloc_fn = system_malloc,
        .free_fn = system_free
    };
    cJSON_InitHooks(&hooks);

    client->state = STATE_INIT;
    return ret;
}

int tuya_iot_start(tuya_iot_client_t *client)
{
    client->state = STATE_START;
    return OPRT_OK;
}

int tuya_iot_stop(tuya_iot_client_t *client)
{
    client->state = STATE_STOP;
    return OPRT_OK;
}

int tuya_iot_reset(tuya_iot_client_t *client)
{
    int ret = OPRT_OK;
    if (tuya_iot_activated(client)) {
        atop_base_response_t response = {0};
        ret = atop_service_client_reset(
                client->activate.devid, 
                client->activate.seckey, 
                &response);
        atop_base_response_free(&response);
    }

    client->event.id = TUYA_EVENT_RESET;
    client->event.data = (void*)GW_LOCAL_RESET_FACTORY;
    iot_dispatch_event(client);
    client->state = STATE_RESET;
    return ret;
}

int tuya_iot_destroy(tuya_iot_client_t* client)
{
    return OPRT_OK;
}

int tuya_iot_yield(tuya_iot_client_t* client)
{
    int ret = OPRT_OK;
    switch (client->state) {
    case STATE_IDLE:
        break;

    case STATE_START:
        TY_LOGD("STATE_START");
        client->state = STATE_STARTUP;
        break;

    case STATE_STARTUP:
        run_state_startup(client);
        break;

    case STATE_NETCFG_MODE:
        run_state_netcfg_mode(client);
        break;

    case STATE_MQTT_CONNECT_START:
        run_state_mqtt_connect_start(client);
        break;

    case STATE_MQTT_CONNECTING:
        if (tuya_mqtt_connected(&client->mqctx)) {
            TY_LOGI("Tuya MQTT connected.");

            /* DP event send */
            client->event.id = TUYA_EVENT_MQTT_CONNECTED;
            iot_dispatch_event(client);

            client->state = STATE_IDLE;
        }
        break;

    case STATE_RESTART:
        run_state_restart(client);
        break;

    case STATE_RESET:
        run_state_reset(client);
        break;

    case STATE_STOP:
        tuya_mqtt_stop(&client->mqctx);
        client->state = STATE_IDLE;
        break;

    case STATE_INIT:
        break;

    default:
        break;
    }

    /* background processing */
    tuya_mqtt_loop(&client->mqctx);

    return ret;
}

bool tuya_iot_activated(tuya_iot_client_t* client)
{
    if (client->state != STATE_INIT && client->state != STATE_NETCFG_MODE) {
        return true;
    } else {
        return false;
    }
}

int tuya_iot_dp_report_json(tuya_iot_client_t* client, const char* dps)
{
    if (client == NULL || dps == NULL) {
        TY_LOGE("param error");
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;
    int printlen = 0;
    char* buffer = NULL;

    /* Package JSON format */
    {
        buffer = system_malloc(strlen(dps) + 64);
        if (NULL == buffer) {
            return OPRT_MALLOC_FAILED;
        }
        printlen = sprintf(buffer, "{\"devId\":\"%s\",\"dps\":%s}", client->activate.devid, dps);
    }

    /* Report buffer */
    rt = tuya_mqtt_report_data(&client->mqctx, PRO_DATA_PUSH, (uint8_t*)buffer, printlen);
    system_free(buffer);

    return rt;
}

static void token_activate_response_parse(atop_base_response_t* response)
{
    if (response->success != true || response->result == NULL) {
        // client->netfcg_state = STATE_NETCFG_ACTIVATE_START; // retry activate
        return;
    }

    int ret = OPRT_OK;
    tuya_iot_client_t* client = (tuya_iot_client_t*)response->user_data;
    cJSON* result_root = response->result;

    if (!cJSON_HasObjectItem(result_root, "schema") || 
        !cJSON_HasObjectItem(result_root, "schemaId")) {
        TY_LOGE("not found schema");
        client->netfcg_state = STATE_NETCFG_FAILED;
        cJSON_Delete(result_root);
        return;
    }

    // cJSON object to string
    // schema save
    char* schemaId = cJSON_GetObjectItem(result_root, "schemaId")->valuestring;
    cJSON* schema_obj = cJSON_DetachItemFromObject(result_root, "schema");
    ret = local_storage_set(schemaId, (const uint8_t*)schema_obj->valuestring, strlen(schema_obj->valuestring));
    cJSON_Delete(schema_obj);
    if (ret != OPRT_OK) {
        TY_LOGE("activate data save error:%d", ret);
        client->netfcg_state = STATE_NETCFG_FAILED;
        return;
    }

    // activate info save
    char* result_string = cJSON_PrintUnformatted(result_root);
    const char* activate_data_key = client->config.uuid;
    TY_LOGD("result len %d :%s", (int)strlen(result_string), result_string);
    ret = local_storage_set(activate_data_key, (const uint8_t*)result_string, strlen(result_string));
    system_free(result_string);
    if (ret != OPRT_OK) {
        TY_LOGE("activate data save error:%d", ret);
        client->netfcg_state = STATE_NETCFG_FAILED;
        return;
    }

    if(cJSON_GetObjectItem(result_root,"resetFactory") != NULL) {
        BOOL_T cloud_reset_factory = (cJSON_GetObjectItem(result_root,"resetFactory")->type == cJSON_True)? TRUE:FALSE;
        TY_LOGD("cloud_reset:%d", cloud_reset_factory);
        //目前只有判断APP恢复出厂模式,但是本地简单移除配网信息,那么告知用户
        if(cloud_reset_factory == TRUE) {
            TY_LOGD("remote is reset factory and local is not,reset factory again.");
            client->event.data = (void*)GW_RESET_DATA_FACTORY;
            client->event.id = TUYA_EVENT_RESET;
            iot_dispatch_event(client);
        }
    }

    client->event.id = TUYA_EVENT_ACTIVATE_SUCCESSED;
    iot_dispatch_event(client);

    // netfcg_state switch to complete;
    client->netfcg_state = STATE_NETCFG_COMPLETE;
}

static void mqtt_register_activate_token_on(tuya_mqtt_event_t* ev)
{
    tuya_iot_client_t* client = (tuya_iot_client_t*)ev->user_data;
    cJSON* data = (cJSON*)(ev->data);

    if (NULL == cJSON_GetObjectItem(data, "token")) {
        TY_LOGE("not found token");
        client->state = STATE_RESTART;
        return;
    }

    /* get token from cJSON object */
    char* token = cJSON_GetObjectItem(data, "token")->valuestring;
    TY_LOGI("token:%s", token);

    /* acvitive request instantiate construct */
    device_activite_params_t activite_request = {
        .token = (const char*)token,
        .product_key = client->config.productkey,
        .uuid = client->config.uuid,
        .authkey = client->config.authkey,
        .sw_ver = client->config.software_ver,
        .bv = BS_VERSION,
        .pv = PV_VERSION,
        .buflen_custom = MAX_LENGTH_ACTIVATE_BUFFER,
        .user_data = client
    };

    /* atop response instantiate construct */
    atop_base_response_t response;

    /* start activate request send */
    int rt = tuya_device_activate_request(&activite_request, &response);
    if (OPRT_OK != rt) {
        TY_LOGE("http active error:%d", rt);
        client->state = STATE_RESTART;
        return;
    }

    /* Parse activate response json data */
    token_activate_response_parse(&response);

    /* relese response object */
    atop_base_response_free(&response);

    // Disconnect the driect MQTT connect
    tuya_mqtt_stop(&client->mqctx);
    client->netfcg_state = STATE_NETCFG_DISCONNECT_WAIT;
}

static int run_state_netcfg_mode_start(tuya_iot_client_t* client)
{
    int rt = OPRT_OK;

    /* mqtt init */
    rt = tuya_mqtt_init(&client->mqctx, &(const tuya_mqtt_config_t){
        .rootCA = tuya_rootCA_pem,
        .host = tuya_mqtt_server_host_get(),
        .port = tuya_mqtt_server_port_get(),
        .uuid = client->config.uuid,
        .authkey = client->config.authkey,
        .timeout = MQTT_NETCFG_TIMEOUT,
    });
    if (OPRT_OK != rt) {
        TY_LOGE("tuya mqtt init error:%d", rt);
        return rt;
    }

    rt = tuya_mqtt_start(&client->mqctx);
    if (OPRT_OK != rt) {
        TY_LOGE("tuya_mqtt_start error:%d", rt);
        client->state = STATE_RESTART;
        return rt;
    }

    /* register token callback */
    tuya_mqtt_protocol_register(&client->mqctx, PRO_MQ_ACTIVE_TOKEN_ON, mqtt_register_activate_token_on, client);
    client->netfcg_state = STATE_NETCFG_CONNECTED_WAIT;

    return rt;
}

static int run_state_netcfg_mode(tuya_iot_client_t* client)
{
    switch(client->netfcg_state) {
    case STATE_NETCFG_START:
        run_state_netcfg_mode_start(client);
        break;

    case STATE_NETCFG_CONNECTED_WAIT:
        if (tuya_mqtt_connected(&client->mqctx)) {
            TY_LOGI("MQTT direct connected!");
            TY_LOGI("Wait Tuya APP scan the Device QR code...");
            client->event.id = TUYA_EVENT_WAIT_ACTIVATE;
            iot_dispatch_event(client);
            client->netfcg_state = STATE_NETCFG_TOKEN_WAIT;
        }
        break;
    
    case STATE_NETCFG_TOKEN_WAIT:
        break;

    case STATE_NETCFG_DISCONNECT_WAIT:
        if (tuya_mqtt_connected(&client->mqctx) == false) {
            if (tuya_mqtt_destory(&client->mqctx) == OPRT_OK) {
                client->netfcg_state = STATE_NETCFG_COMPLETE;
            }
        }
        break;

    case STATE_NETCFG_COMPLETE:
        client->state = STATE_STARTUP;
        break;
    }

    return 0;
}