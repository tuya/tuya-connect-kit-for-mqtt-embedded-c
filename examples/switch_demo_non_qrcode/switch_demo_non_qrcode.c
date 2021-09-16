#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "tuya_log.h"
#include "tuya_config.h"
#include "tuya_iot.h"
#include "cJSON.h"

#define SOFTWARE_VER     "1.0.0"

/* Tuya device handle */
tuya_iot_client_t client;

#define SWITCH_DP_ID_KEY "1"

void example_qrcode_print(const char* productkey, const char* uuid)
{
	TY_LOGI("https://smartapp.tuya.com/s/p?p=%s&uuid=%s&v=2.0", productkey, uuid);
	TY_LOGI("(Use this URL to generate a static QR code for the Tuya APP scan code binding)");
}

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


static void cache_dp_response_parse(atop_base_response_t* response)
{
    if (response->success != true || response->result == NULL) {
        return ;
    }
    int iCount=0,i = 0;
    int ret = OPRT_OK;

    cJSON* result_root = response->result;
    if (result_root == NULL) {
        TY_LOGE("response->result is NULL");
    }
    cJSON *item = NULL;
    cJSON *c = result_root->child;
    TY_LOGI("cache dp=%s\n",cJSON_Print(c));
    while(c) {
        item = c;
        c = c->next;
        item = cJSON_DetachItemFromObject(result_root, item->string);
        TY_LOGI("dpid=%s value=%d",item->string,item->valueint);
        // TODO user prcess the dp cache
    }
    return;
}


void user_cache_dp_reuest(tuya_iot_client_t* client)
{

    atop_base_response_t response = {0};
    int rt = atop_service_cache_dp_get(client->activate.devid,client->activate.seckey,0,&response);
    if (OPRT_OK != rt) {
        TY_LOGE("atop_service_cache_dp_get error:%d", rt);
        return;
    }
    /* Parse activate response json data */
    cache_dp_response_parse(&response);

    /* relese response object */
    atop_base_response_free(&response);
}

/* Tuya SDK event callback */
static void user_event_handler_on(tuya_iot_client_t* client, tuya_event_msg_t* event)
{
    switch(event->id){
    case TUYA_EVENT_BIND_START:
        example_qrcode_print(client->config.productkey, client->config.uuid);
        break;

    case TUYA_EVENT_MQTT_CONNECTED:
        TY_LOGI("Device MQTT Connected!");
        user_cache_dp_reuest(client);
        break;

    case TUYA_EVENT_DP_RECEIVE:
        tuya_iot_dp_download(client, (const char*)event->value.asString);
        break;
    case TUYA_EVENT_DPCACHE_NOTIFY:
        TY_LOGI("Receive the dp cache notify");
        user_cache_dp_reuest(client);
    default:
        break;
    }
}

int main(int argc, char **argv)
{
    int ret = OPRT_OK;

    /* Initialize Tuya device configuration */
    ret = tuya_iot_init(&client, &(const tuya_iot_config_t){
        .software_ver = SOFTWARE_VER,
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
