#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "tuya_config_defaults.h"
#include "tuya_error_code.h"
#include "tuya_iot.h"
#include "tuya_log.h"
#include "tuya_endpoint.h"

#include "system_interface.h"
#include "storage_interface.h"
#include "atop_base.h"
#include "atop_service.h"
#include "mqtt_bind.h"
#include "cJSON.h"
#include "MultiTimer.h"

typedef enum {
    STATE_IDLE,
    STATE_START,
    STATE_DATA_LOAD,
    STATE_TOKEN_PENDING,
    STATE_ACTIVATING,
    STATE_STARTUP_UPDATE,
    STATE_MQTT_CONNECT_START,
    STATE_MQTT_CONNECTING,
    STATE_MQTT_YIELD,
    STATE_RESTART,
    STATE_RESET,
    STATE_STOP,
    STATE_EXIT,
} tuya_run_state_t;


/* -------------------------------------------------------------------------- */
/*                          Internal utils functions                          */
/* -------------------------------------------------------------------------- */

static int iot_dispatch_event(tuya_iot_client_t* client)
{
    if (client->config.event_handler) {
        client->config.event_handler(client, &client->event);
    }
    return OPRT_OK;
}

/* -------------------------------------------------------------------------- */
/*                            Activate data process                           */
/* -------------------------------------------------------------------------- */

static int activate_json_string_parse(const char* str, tuya_activated_data_t* out)
{
    cJSON* root = cJSON_Parse(str);
    if (NULL == root) {
        cJSON_Delete(root);
        return OPRT_CJSON_PARSE_ERR;
    }

    if (cJSON_GetObjectItem(root, "devId") == NULL || \
        cJSON_GetObjectItem(root, "secKey") == NULL || \
        cJSON_GetObjectItem(root, "localKey") == NULL || \
        cJSON_GetObjectItem(root, "schemaId") == NULL || \
        cJSON_GetObjectItem(root, "stdTimeZone") == NULL) {
        cJSON_Delete(root);
        return OPRT_CJSON_GET_ERR;
    }

    strcpy(out->devid, cJSON_GetObjectItem(root, "devId")->valuestring);
    strcpy(out->seckey, cJSON_GetObjectItem(root, "secKey")->valuestring);
    strcpy(out->localkey, cJSON_GetObjectItem(root, "localKey")->valuestring);
    strcpy(out->schemaId, cJSON_GetObjectItem(root, "schemaId")->valuestring);
    strcpy(out->timezone, cJSON_GetObjectItem(root, "stdTimeZone")->valuestring);
    cJSON_Delete(root);
    return OPRT_OK;
}

static int activated_data_read(const char* storage_key, tuya_activated_data_t* out)
{
    int rt = OPRT_OK;
    size_t readlen = ACTIVATE_KV_BUFFER_MAX;
    char* readbuf = system_calloc(sizeof(char), ACTIVATE_KV_BUFFER_MAX);
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

    /* Dump info */
    TY_LOGV("devId: %s", out->devid);
    TY_LOGV("secKey: %s", out->seckey);
    TY_LOGV("localKey: %s", out->localkey);

    return rt;
}

static int activate_response_parse(atop_base_response_t* response)
{
    if (response->success != true || response->result == NULL) {
        return OPRT_INVALID_PARM;
    }

    int ret = OPRT_OK;
    tuya_iot_client_t* client = (tuya_iot_client_t*)response->user_data;
    cJSON* result_root = response->result;

    if (!cJSON_HasObjectItem(result_root, "schema") ||
        !cJSON_HasObjectItem(result_root, "schemaId")) {
        TY_LOGE("not found schema");
        cJSON_Delete(result_root);
        return OPRT_CJSON_GET_ERR;
    }

    // cJSON object to string save
    char* schemaId = cJSON_GetObjectItem(result_root, "schemaId")->valuestring;
    cJSON* schema_obj = cJSON_DetachItemFromObject(result_root, "schema");
    ret = local_storage_set(schemaId, (const uint8_t*)schema_obj->valuestring, strlen(schema_obj->valuestring));
    cJSON_Delete(schema_obj);
    if (ret != OPRT_OK) {
        TY_LOGE("activate data save error:%d", ret);
        return OPRT_KVS_WR_FAIL;
    }

    // activate info save
    char* result_string = cJSON_PrintUnformatted(result_root);
    const char* activate_data_key = client->config.storage_namespace;
    TY_LOGD("result len %d :%s", (int)strlen(result_string), result_string);
    ret = local_storage_set(activate_data_key, (const uint8_t*)result_string, strlen(result_string));
    system_free(result_string);
    if (ret != OPRT_OK) {
        TY_LOGE("activate data save error:%d", ret);
        return OPRT_KVS_WR_FAIL;
    }

    if(cJSON_GetObjectItem(result_root,"resetFactory") != NULL) {
        BOOL_T cloud_reset_factory = (cJSON_GetObjectItem(result_root,"resetFactory")->type == cJSON_True)? TRUE:FALSE;
        TY_LOGD("cloud_reset:%d", cloud_reset_factory);
        //目前只有判断APP恢复出厂模式,但是本地简单移除配网信息,那么告知用户
        if(cloud_reset_factory == TRUE) {
            TY_LOGD("remote is reset factory and local is not,reset factory again.");
            client->event.id = TUYA_EVENT_RESET;
            client->event.value.asInteger = TUYA_RESET_TYPE_DATA_FACTORY;
            iot_dispatch_event(client);
        }
    }

    return OPRT_OK;
}

static int client_activate_process(tuya_iot_client_t* client, const char* token)
{
    /* Try to read the already exist devId */
    char devid_key[MAX_LENGTH_UUID + 7];
    char devid_cache[MAX_LENGTH_DEVICE_ID] = {0};
    size_t devid_len = MAX_LENGTH_DEVICE_ID;
    bool exist_devid = false;

    snprintf(devid_key, sizeof devid_key, "%s.devid", client->config.storage_namespace);
    if (local_storage_get(devid_key, (uint8_t*)devid_cache, &devid_len) == OPRT_OK) {
        if (devid_len > 0 && strlen(devid_cache) > 0) {
            exist_devid = true;
        }
    }

    /* acvitive request instantiate construct */
    tuya_activite_request_t activite_request = {
        .token = (const char*)token,
        .product_key = client->config.productkey,
        .uuid = client->config.uuid,
        .devid = exist_devid ? devid_cache : NULL,
        .authkey = client->config.authkey,
        .sw_ver = client->config.software_ver,
        .modules = client->config.modules,
        .skill_param = client->config.skill_param,
        .firmware_key = client->config.firmware_key,
        .bv = BS_VERSION,
        .pv = PV_VERSION,
        .buflen_custom = ACTIVATE_BUFFER_LENGTH,
        .user_data = client
    };

    /* atop response instantiate construct */
    atop_base_response_t response = {0};

    /* start activate request send */
    int rt = atop_service_activate_request(&activite_request, &response);
    if (OPRT_OK != rt) {
        TY_LOGE("http active error:%d", rt);
        client->nextstate = STATE_RESTART;
        return rt;
    }

    /* Send timestamp sync event*/
    client->event.id = TUYA_EVENT_TIMESTAMP_SYNC;
    client->event.type = TUYA_DATE_TYPE_INTEGER;
    client->event.value.asInteger = response.t;
    iot_dispatch_event(client);

    /* Parse activate response json data */
    rt = activate_response_parse(&response);

    /* relese response object */
    atop_base_response_free(&response);

    if (OPRT_OK != rt) {
        TY_LOGE("activate_response_parse error:%d", rt);
        return rt;
    }

    return OPRT_OK;
}

/* -------------------------------------------------------------------------- */
/*                         Tuya MQTT service callback                         */
/* -------------------------------------------------------------------------- */

static void mqtt_service_dp_receive_on(tuya_protocol_event_t* ev)
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
    client->event.type = TUYA_DATE_TYPE_STRING;
    client->event.value.asString = dps_string;
    iot_dispatch_event(client);
    system_free(dps_string);

    /* Send DP cJSON format event*/
    client->event.id = TUYA_EVENT_DP_RECEIVE_CJSON;
    client->event.type = TUYA_DATE_TYPE_JSON;
    client->event.value.asJSON = cJSON_GetObjectItem(data, "dps");
    iot_dispatch_event(client);
}

static void mqtt_service_reset_cmd_on(tuya_protocol_event_t* ev)
{
    tuya_iot_client_t* client = ev->user_data;
    cJSON* data = (cJSON*)(ev->data);

    if (NULL == cJSON_GetObjectItem(data, "gwId")) {
        TY_LOGE("not found gwId");
    }

    TY_LOGW("Reset id:%s", cJSON_GetObjectItem(data, "gwId")->valuestring);

    /* DP event send */
    client->event.id = TUYA_EVENT_RESET;
    client->event.type = TUYA_DATE_TYPE_INTEGER;

    if (cJSON_GetObjectItem(ev->root_json, "type") && \
        strcmp(cJSON_GetObjectItem(ev->root_json, "type")->valuestring, "reset_factory") == 0)  {
        TY_LOGD("cmd is reset factory, ungister");
        client->event.value.asInteger = TUYA_RESET_TYPE_REMOTE_FACTORY;
    } else {
        TY_LOGD("unactive");
        client->event.value.asInteger = TUYA_RESET_TYPE_REMOTE_UNACTIVE;
    }
    iot_dispatch_event(client);

    client->nextstate = STATE_RESET;
    TY_LOGI("STATE_RESET...");
}

static void mqtt_atop_upgrade_info_notify_cb(atop_base_response_t* response, void* user_data)
{
    tuya_iot_client_t* client = (tuya_iot_client_t*)user_data;

    /* response error, abort upgrade */
    if (response->success == false) {
        matop_service_upgrade_status_update(&client->matop, 0, 4);
        return;
    }

    /* Send timestamp sync event*/
    client->event.id = TUYA_EVENT_TIMESTAMP_SYNC;
    client->event.type = TUYA_DATE_TYPE_INTEGER;
    client->event.value.asInteger = response->t;
    iot_dispatch_event(client);

    /* Param verify */
    if (response->result == NULL) {
        return;
    }

    /* Send DP cJSON format event*/
    client->event.id = TUYA_EVENT_UPGRADE_NOTIFY;
    client->event.type = TUYA_DATE_TYPE_JSON;
    client->event.value.asJSON = response->result;
    iot_dispatch_event(client);
}

static void mqtt_service_upgrade_notify_on(tuya_mqtt_event_t* ev)
{
    tuya_iot_client_t* client = ev->user_data;
    cJSON* data = (cJSON*)(ev->data);
    int ota_channel = 0;

    if (cJSON_GetObjectItem(data, "firmwareType")) {
        ota_channel = cJSON_GetObjectItem(data, "firmwareType")->valueint;
    }

    int rt = matop_service_upgrade_info_get(&client->matop, ota_channel, 
                                        mqtt_atop_upgrade_info_notify_cb, client);
    if (rt != OPRT_OK) {
        TY_LOGE("upgrade info get error:%d", rt);
        return;
    }
}

static void mqtt_client_connected_on(void* context, void* user_data)
{
    tuya_iot_client_t* client = (tuya_iot_client_t*)user_data;

    /* MATOP Init */
    matop_serice_init(&client->matop, &(const matop_config_t){
        .mqctx = &client->mqctx,
        .devid = client->activate.devid
    });

    /* Auto check upgrade timer start */
    MultiTimerStart(&client->check_upgrade_timer, 1000 * 1);

    /* Send connected event*/
    client->event.id = TUYA_EVENT_MQTT_CONNECTED;
    client->event.type = TUYA_DATE_TYPE_UNDEFINED;
    iot_dispatch_event(client);
}

static void mqtt_client_disconnect_on(void* context, void* user_data)
{
    tuya_iot_client_t* client = (tuya_iot_client_t*)user_data;

    /* Stop check upgrade timer. */
    MultiTimerStop(&client->check_upgrade_timer);

    /* Send disconnect event*/
    client->event.id = TUYA_EVENT_MQTT_DISCONNECT;
    client->event.type = TUYA_DATE_TYPE_UNDEFINED;
    iot_dispatch_event(client);
}

static void mqtt_client_unbind_on(void* context, void* user_data)
{
    tuya_iot_client_t* client = (tuya_iot_client_t*)user_data;
    TY_LOGI("MQTT unbind callback.");

    /* Reset activated data */
    client->nextstate = STATE_RESET;

    /* DP event send */
    client->event.id = TUYA_EVENT_RESET;
    client->event.type = TUYA_DATE_TYPE_INTEGER;
    client->event.value.asInteger = TUYA_RESET_TYPE_REMOTE_UNACTIVE;
    iot_dispatch_event(client);
}

static void check_auto_upgrade_timeout_on(MultiTimer* timer, void* user_data)
{
    tuya_iot_client_t* client = (tuya_iot_client_t*)user_data;

    matop_service_auto_upgrade_info_get(&client->matop, mqtt_atop_upgrade_info_notify_cb, client);
}

/* -------------------------------------------------------------------------- */
/*                       Internal machine state process                       */
/* -------------------------------------------------------------------------- */

static int run_state_startup_update(tuya_iot_client_t* client)
{
    int rt = OPRT_OK;

    /* Update client version */
    tuya_iot_version_update_sync(client);

    /* MQTT Client Init */
    const tuya_endpoint_t* endpoint = tuya_endpoint_get();
    rt = tuya_mqtt_init(&client->mqctx, &(const tuya_mqtt_config_t){
        .cacert = endpoint->mqtt.cert,
        .cacert_len = endpoint->mqtt.cert_len,
        .host = endpoint->mqtt.host,
        .port = endpoint->mqtt.port,
        .devid = client->activate.devid,
        .seckey = client->activate.seckey,
        .localkey = client->activate.localkey,
        .timeout = MQTT_RECV_BLOCK_TIME_MS,
        .user_data = client,
        .on_connected = mqtt_client_connected_on,
        .on_disconnect = mqtt_client_disconnect_on,
        .on_unbind = mqtt_client_unbind_on,
    });

    return rt;
}

static int run_state_mqtt_connect_start(tuya_iot_client_t* client)
{    
    int rt = tuya_mqtt_start(&client->mqctx);
    if (OPRT_OK != rt) {
        TY_LOGE("tuya mqtt start error:%d", rt);
        return rt;
    }

    /* callback register */
    tuya_mqtt_protocol_register(&client->mqctx, PRO_CMD, mqtt_service_dp_receive_on, client);
    tuya_mqtt_protocol_register(&client->mqctx, PRO_GW_RESET, mqtt_service_reset_cmd_on, client);
    tuya_mqtt_protocol_register(&client->mqctx, PRO_UPGD_REQ, mqtt_service_upgrade_notify_on, client);

    return rt;
}

static int run_state_restart(tuya_iot_client_t* client)
{
    TY_LOGW("CLIENT RESTART!");
    return OPRT_OK;
}

static int run_state_reset(tuya_iot_client_t* client)
{
    TY_LOGW("CLIENT RESET...");

    /* Stop MQTT service */
    if (client->is_activated && tuya_mqtt_connected(&client->mqctx)) {
        tuya_mqtt_stop(&client->mqctx);
    }

    /* Save devId */
    char devid_key[32];
    snprintf(devid_key, sizeof devid_key, "%s.devid", client->config.storage_namespace);
    local_storage_set((const char*)devid_key,
                      (const uint8_t*)client->activate.devid,
                      strlen(client->activate.devid));

    /* Clean client local data */
    return tuya_iot_activated_data_remove(client);
}

/* -------------------------------------------------------------------------- */
/*                                Tuya IoT API                                */
/* -------------------------------------------------------------------------- */

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

    /* Default storage namespace */
    if (client->config.storage_namespace == NULL) {
        client->config.storage_namespace = client->config.uuid;
    }

    /* Software timer Init */
    MultiTimerInstall(system_ticks);

    /* cJSON init */
    cJSON_Hooks hooks = {
        .malloc_fn = system_malloc,
        .free_fn = system_free
    };
    cJSON_InitHooks(&hooks);

    /* Load Tuya cloud endpoint config */
    tuya_endpoint_init();

    /* Try to read the local activation data.
    * If the reading is successful, the device has been activated. */
    if (activated_data_read(client->config.storage_namespace, &client->activate) == OPRT_OK) {
        client->is_activated = true;
    }

    /* Auto check upgrade timer init */
    MultiTimerInit(&client->check_upgrade_timer, AUTO_UPGRADE_CHECK_INTERVAL, check_auto_upgrade_timeout_on, client);

    client->state = STATE_IDLE;
    client->nextstate = STATE_IDLE;
    return ret;
}

int tuya_iot_start(tuya_iot_client_t *client)
{
    if (client->state != STATE_IDLE) {
        return OPRT_COM_ERROR;
    }
    client->nextstate = STATE_START;
    return OPRT_OK;
}

int tuya_iot_stop(tuya_iot_client_t *client)
{
    client->nextstate = STATE_STOP;
    return OPRT_OK;
}

int tuya_iot_reset(tuya_iot_client_t *client)
{
    int ret = OPRT_OK;
    if (tuya_iot_activated(client)) {
        ret = matop_service_client_reset(&client->matop);
    }

    client->event.id = TUYA_EVENT_RESET;
    client->event.type = TUYA_DATE_TYPE_INTEGER;
    client->event.value.asInteger = TUYA_RESET_TYPE_FACTORY;
    iot_dispatch_event(client);
    client->nextstate = STATE_RESET;
    return ret;
}

int tuya_iot_destroy(tuya_iot_client_t* client)
{
    return OPRT_OK;
}

int tuya_iot_yield(tuya_iot_client_t* client)
{
    if (client == NULL) {
        return OPRT_INVALID_PARM;
    }

    int ret = OPRT_OK;
    client->state = client->nextstate;

    switch (client->state) {
    case STATE_MQTT_YIELD:
        tuya_mqtt_loop(&client->mqctx);
        matop_serice_yield(&client->matop);
        break;

    case STATE_IDLE:
        system_sleep(500);
        break;

    case STATE_START:
        TY_LOGD("STATE_START");
        client->nextstate = STATE_DATA_LOAD;
        break;

    case STATE_DATA_LOAD:
        /* Try to read the local activation data.
         * If the reading is successful, the device has been activated. */
        if (client->is_activated) {
            tuya_endpoint_update();
            client->nextstate = STATE_STARTUP_UPDATE;
            break;
        }

        /* If the reading fails, enter the pending activation mode. */
        TY_LOGI("Activation data read fail, go activation mode...");
        client->binding = system_calloc(1, sizeof(tuya_binding_info_t));
        if (client->binding == NULL) {
            TY_LOGE("binding calloc error");
            break;
        }
        client->nextstate = STATE_TOKEN_PENDING;
        break;

    case STATE_TOKEN_PENDING:
        /* If token_get port no preset, Use default mqtt bind mode */
        if (client->token_get == NULL) {
            tuya_iot_token_get_port_register(client, mqtt_bind_token_get);
        }

        /* Send Bind event to user program */
        client->event.id = TUYA_EVENT_BIND_START;
        client->event.type = TUYA_DATE_TYPE_UNDEFINED;
        iot_dispatch_event(client);

        if (client->token_get(&client->config, client->binding) != OPRT_OK) {
            TY_LOGE("Get token fail, retry..");
            break;
        }

        TY_LOGI("token: %s", client->binding->token);
        TY_LOGI("region: %s", client->binding->region);
        TY_LOGI("regist_key: %s", client->binding->regist_key);

        /* set binding.region, binding.regist_key to tuya dns server */
        tuya_endpoint_region_regist_set(client->binding->region, client->binding->regist_key);
        tuya_endpoint_update();

        /* DP event send */
        client->event.id = TUYA_EVENT_BIND_TOKEN_ON;
        client->event.type = TUYA_DATE_TYPE_STRING;
        client->event.value.asString = client->binding->token;
        iot_dispatch_event(client);

        /* Take token go to activate */
        client->nextstate = STATE_ACTIVATING;
        break;

    case STATE_ACTIVATING:
        ret = client_activate_process(client, client->binding->token);
        if (ret != OPRT_OK) {
            system_sleep(1000);
            break;
        }

        system_free(client->binding);
        client->binding = NULL;

        /* Read and parse activate data */
        if (activated_data_read(client->config.storage_namespace, &client->activate) != OPRT_OK) {
            client->nextstate = STATE_RESET;
            break;
        }
        client->is_activated = true;

        /* Retry to load activate */
        client->nextstate = STATE_STARTUP_UPDATE;

        /* DP event send */
        client->event.id = TUYA_EVENT_ACTIVATE_SUCCESSED;
        client->event.type = TUYA_DATE_TYPE_UNDEFINED;
        iot_dispatch_event(client);
        break;

    case STATE_STARTUP_UPDATE:
        run_state_startup_update(client);
        client->nextstate = STATE_MQTT_CONNECT_START;
        break;

    case STATE_MQTT_CONNECT_START:
        if (run_state_mqtt_connect_start(client) == OPRT_OK) {
            client->nextstate = STATE_MQTT_CONNECTING;
        }
        break;

    case STATE_MQTT_CONNECTING:
        if (tuya_mqtt_connected(&client->mqctx)) {
            TY_LOGI("Tuya MQTT connected.");
            client->nextstate = STATE_MQTT_YIELD;
        }
        break;

    case STATE_RESTART:
        run_state_restart(client);
        client->nextstate = STATE_START;
        break;

    case STATE_RESET:
        run_state_reset(client);
        client->nextstate = STATE_RESTART;
        break;

    case STATE_STOP:
        tuya_mqtt_stop(&client->mqctx);
        client->nextstate = STATE_IDLE;
        break;

    default:
        break;
    }

    /* software timer background processing */
    MultiTimerYield();

    return ret;
}

bool tuya_iot_activated(tuya_iot_client_t* client)
{
    if (client == NULL) {
        return false;
    }

    return client->is_activated;
}

int tuya_iot_activated_data_remove(tuya_iot_client_t* client)
{
    TY_LOGW("Activated data remove...");

    if (client->is_activated != true) {
        return OPRT_COM_ERROR;
    }

    /* Clean client local data */
    local_storage_del((const char*)(client->activate.schemaId));
    local_storage_del((const char*)(client->config.storage_namespace));
    tuya_endpoint_remove();
    client->is_activated = false;
    TY_LOGI("Activated data remove successed");

    client->event.id = TUYA_EVENT_RESET_COMPLETE;
    client->event.type = TUYA_DATE_TYPE_UNDEFINED;
    iot_dispatch_event(client);

    return OPRT_OK;
}

static int tuya_iot_dp_report_json_common(tuya_iot_client_t* client, const char* dps, const char* time, tuya_dp_notify_cb_t cb, void* user_data, int timeout_ms, bool async)
{
    if (client == NULL || dps == NULL) {
        TY_LOGE("param error");
        return OPRT_INVALID_PARM;
    }

    int ret;
    int printlen = 0;
    char* buffer = NULL;

    /* Package JSON format */
    if (time) {
        buffer = system_malloc(strlen(dps) + strlen(time) + 64);
        TUYA_CHECK_NULL_RETURN(buffer, OPRT_MALLOC_FAILED);
        printlen = sprintf(buffer, "{\"devId\":\"%s\",\"dps\":%s,\"t\":%s}", client->activate.devid, dps, time);
    } else {
        buffer = system_malloc(strlen(dps) + 64);
        TUYA_CHECK_NULL_RETURN(buffer, OPRT_MALLOC_FAILED);
        printlen = sprintf(buffer, "{\"devId\":\"%s\",\"dps\":%s}", client->activate.devid, dps);
    }

    /* Report buffer */
    ret = tuya_mqtt_protocol_data_publish_common(&client->mqctx, PRO_DATA_PUSH,
                                                (const uint8_t*)buffer, (uint16_t)printlen,
                                                (mqtt_publish_notify_cb_t)cb, user_data,
                                                timeout_ms, async);
    system_free(buffer);
    return ret;
}

int tuya_iot_dp_report_json_async(tuya_iot_client_t* client, const char* dps, const char* time, tuya_dp_notify_cb_t cb, void* user_data, int timeout_ms)
{
    return tuya_iot_dp_report_json_common(client, dps, time, cb, user_data, timeout_ms, true);
}

int tuya_iot_dp_report_json_with_notify(tuya_iot_client_t* client, const char* dps, const char* time, tuya_dp_notify_cb_t cb, void* user_data, int timeout_ms)
{
    return tuya_iot_dp_report_json_common(client, dps, time, cb, user_data, timeout_ms, false);
}

int tuya_iot_dp_report_json_with_time(tuya_iot_client_t* client, const char* dps, const char* time)
{
    return tuya_iot_dp_report_json_common(client, dps, time, NULL, NULL, 0, false);
}

int tuya_iot_dp_report_json(tuya_iot_client_t* client, const char* dps)
{
    return tuya_iot_dp_report_json_with_time(client,dps,NULL);
}

int tuya_iot_token_get_port_register(tuya_iot_client_t* client, tuya_activate_token_get_t token_get_func)
{
    if (client == NULL || token_get_func == NULL) {
        return OPRT_INVALID_PARM;
    }
    client->token_get = token_get_func;
    return OPRT_OK;
}

int tuya_iot_version_update_sync(tuya_iot_client_t* client)
{
    if (client == NULL) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    #define VERSION_BUFFER_MAX (128)
    size_t prealloc_size = VERSION_BUFFER_MAX;
    if (client->config.modules) {
        prealloc_size += strlen(client->config.modules) + 10;
    }

    char* version_buffer = system_malloc(prealloc_size);
    if (version_buffer == NULL) {
        return OPRT_INVALID_PARM;
    }

    /* Format version JSON buffer */
    size_t version_len = 0;
    if (client->config.modules) {
        /* extension modules version */
        version_len += sprintf(version_buffer + version_len, "%s", client->config.modules);
        version_len -= 1; // remove ']'
        version_len += sprintf(version_buffer + version_len, ",");
    } else {
        version_len += sprintf(version_buffer + version_len, "[");
    }

    /* Main firmware information */
    version_len += sprintf(version_buffer + version_len,
        "{\\\"otaChannel\\\":%d,\\\"protocolVer\\\":\\\"%s\\\",\\\"baselineVer\\\":\\\"%s\\\",\\\"softVer\\\":\\\"%s\\\"}",
        0, PV_VERSION, BS_VERSION, client->config.software_ver);

    version_len += sprintf(version_buffer + version_len, "]");
    TY_LOGD("%s", version_buffer);

    /* local storage read buffer*/
    size_t readlen = prealloc_size;
    char* readbuf = system_calloc(sizeof(char), prealloc_size);
    if (NULL == readbuf) {
        TY_LOGE("activate_string malloc fail.");
        system_free(version_buffer);
        return rt;
    }

    /* Try read activate config data */
    char version_key[32];
    snprintf(version_key, sizeof version_key, "%s.ver", client->config.storage_namespace);
    rt = local_storage_get((const char*)version_key, (uint8_t*)readbuf, &readlen);
    if (OPRT_OK != rt) {
        TY_LOGW("version save info not found:%d", rt);
    }

    /* Compare the version info changed? */
    if (memcmp(version_buffer, readbuf, version_len) == 0) {
        TY_LOGD("The verison unchanged, dont need sync.");
        system_free(readbuf);
        system_free(version_buffer);
        return OPRT_OK;
    }

    /* Post version info to ATOP service */
    rt = atop_service_version_update_v41(client->activate.devid, client->activate.seckey,
                                        (const char*)version_buffer);
    system_free(readbuf);
    if (rt != OPRT_OK) {
        system_free(version_buffer);
        return rt;
    }

    /* Save version info */
    rt = local_storage_set((const char*)version_key, (const uint8_t*)version_buffer, version_len);
    system_free(version_buffer);

    return rt;
}

int tuya_iot_extension_modules_version_update(tuya_iot_client_t* client, const char* version)
{
    client->config.modules = version;
    return tuya_iot_version_update_sync(client);
}

const char* tuya_iot_devid_get(tuya_iot_client_t* client)
{
    return (const char*)(client->activate.devid);
}

const char* tuya_iot_localkey_get(tuya_iot_client_t* client)
{
    return (const char*)(client->activate.localkey);
}

const char* tuya_iot_seckey_get(tuya_iot_client_t* client)
{
    return (const char*)(client->activate.seckey);
}

const char* tuya_iot_timezone_get(tuya_iot_client_t* client)
{
    return (const char*)(client->activate.timezone);
}
