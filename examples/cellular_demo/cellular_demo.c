#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "cJSON.h"
#include "system_interface.h"
#include "tuya_config.h"
#include "tuya_iot.h"
#include "tuya_log.h"

#define SOFTWARE_VER "1.0.0"
#define SWITCH_DP_ID_KEY "1"


typedef struct{
    unsigned char  dp_num;
    unsigned char  *dp_arr;
}DP_CACHE_STATE_S;

/* for APP QRCode scan test */
extern void example_qrcode_print(const char* productkey, const char* uuid);

/* Tuya device handle */
tuya_iot_client_t client;

static DP_CACHE_STATE_S s_cache_dp;
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
void user_dp_download_on(tuya_iot_client_t* client, const char* json_dps)
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

/* Tuya OTA event callback */
void user_upgrade_notify_on(tuya_iot_client_t* client, cJSON* upgrade)
{
    TY_LOGI("----- Upgrade information -----");
    TY_LOGI("OTA Channel: %d", cJSON_GetObjectItem(upgrade, "type")->valueint);
    TY_LOGI("Version: %s", cJSON_GetObjectItem(upgrade, "version")->valuestring);
    TY_LOGI("Size: %s", cJSON_GetObjectItem(upgrade, "size")->valuestring);
    TY_LOGI("MD5: %s", cJSON_GetObjectItem(upgrade, "md5")->valuestring);
    TY_LOGI("HMAC: %s", cJSON_GetObjectItem(upgrade, "hmac")->valuestring);
    TY_LOGI("URL: %s", cJSON_GetObjectItem(upgrade, "url")->valuestring);
    TY_LOGI("HTTPS URL: %s", cJSON_GetObjectItem(upgrade, "httpsUrl")->valuestring);
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


static void user_proc_dp_cache_state(cJSON *result)
{
    unsigned int arr_sz, i;
    cJSON *item = NULL, *root = NULL,*temp = NULL; 


    if(NULL == result) {
        TY_LOGE("result  failed ");
    }

    arr_sz = cJSON_GetArraySize(result);
    TY_LOGD("arr_sz=%d",arr_sz);
    for(i = 0; i < arr_sz; i++) {
        TY_LOGD("***********************************");

        item = cJSON_GetArrayItem(result, i);
        if (NULL == item) {
             TY_LOGE("cJSON_GetArrayItem:%d failed", i);
             continue;
        }
        root = cJSON_Parse(item->valuestring);
        if (NULL == root) {
            TY_LOGE("cJSON_Parse:%s failed", item->valuestring);
            continue;
        }
        TY_LOGD("item->valuestring:%s ", item->valuestring);

        temp = cJSON_GetObjectItem(root, SWITCH_DP_ID_KEY);
        if (NULL != temp) {
            TY_LOGD("temp->valueint:%d ", temp->valueint);
        }
        TY_LOGD("***********************************");
        cJSON_Delete(root);
    }

    return ;
}


void user_cache_dp_reuest(tuya_iot_client_t* client,DP_CACHE_STATE_S *dp_state)
{

    atop_base_response_t response = {0};
    if(NULL == dp_state) {
        return ;
    }
    char* out,i;

    TY_LOGI("dp_state->dp_num = %d",dp_state->dp_num);
 
    out = (char*)system_malloc(256);
    memset(out,0,256);
    int offset = 0;
    for (i = 0;i < dp_state->dp_num; i ++) {
        if (i) {
            snprintf(out+offset,256,",%d",dp_state->dp_arr[i]);
        }
        else {
            snprintf(out+offset,256,"%d",dp_state->dp_arr[i]);
        }
        offset = strlen(out);
    }
    TY_LOGI("reqest dp data %s",out);
    int rt = atop_service_cache_dp_get(client->activate.devid,client->activate.seckey,out,&response);
    if (OPRT_OK != rt) {
        TY_LOGE("atop_service_cache_dp_get error:%d", rt);
        return;
    }
    /* Parse activate response json data */
    user_proc_dp_cache_state(response.result);
    system_free(out);
    /* relese response object */
    atop_base_response_free(&response);
}

/* Tuya SDK event callback */
static void user_event_handler_on(tuya_iot_client_t* client, tuya_event_msg_t* event)
{
    TY_LOGD("Tuya Event ID:%d(%s)", event->id, EVENT_ID2STR(event->id));
    switch (event->id) {
    case TUYA_EVENT_BIND_START:
        /* Print the QRCode for Tuya APP bind */
        example_qrcode_print(client->config.productkey, client->config.uuid);
        break;

    case TUYA_EVENT_MQTT_CONNECTED:
        atop_service_iccid_upload(client->activate.devid,client->activate.seckey,"12345678901234567890");
        user_cache_dp_reuest(client,&s_cache_dp);
        TY_LOGI("Device MQTT Connected!");
        break;

    case TUYA_EVENT_DP_RECEIVE:
        user_dp_download_on(client, (const char*)event->value.asString);
        break;

    case TUYA_EVENT_UPGRADE_NOTIFY:
        user_upgrade_notify_on(client, event->value.asJSON);
        break;

    case TUYA_EVENT_TIMESTAMP_SYNC:
        TY_LOGI("Sync timestamp:%d", event->value.asInteger);
        break;
    case TUYA_EVENT_DPCACHE_NOTIFY:
        TY_LOGI("Recv TUYA_EVENT_DPCACHE_NOTIFY");
        user_cache_dp_reuest(client,&s_cache_dp);
    default:
        break;
    }
}

static user_dpcache_request_init(void)
{
    s_cache_dp.dp_num = 2;
    s_cache_dp.dp_arr = system_malloc(32);   
    s_cache_dp.dp_arr[0]=atoi(SWITCH_DP_ID_KEY);    
}


int main(int argc, char** argv)
{
    int ret = OPRT_OK;

    TY_LOGI("main start 1 s_cache_dp.dp_arr=%p",s_cache_dp.dp_arr);  

    user_dpcache_request_init(); 
    /* Initialize Tuya device configuration */
    ret = tuya_iot_init(&client, &(const tuya_iot_config_t) {
        .software_ver = SOFTWARE_VER,
        .productkey = TUYA_PRODUCT_KEY,
        .uuid = TUYA_DEVICE_UUID,
        .authkey = TUYA_DEVICE_AUTHKEY,
        .event_handler = user_event_handler_on
    });

    assert(ret == OPRT_OK);
    tuya_endpoint_region_regist_set("AY", "pr_0");
    /* Start tuya iot task */
    tuya_iot_start(&client);

    for (;;) {
        /* Loop to receive packets, and handles client keepalive */
        tuya_iot_yield(&client);
    }

    return ret;
}
