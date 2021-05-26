#include <stdint.h>
#include "tuya_url.h"
#include "tuya_log.h"
#include "tuya_error_code.h"
#include "storage_interface.h"

#define MAX_LENGTH_REGION         (2)    // max string length of REGIN IN TOKEN
#define MAX_LENGTH_REGIST         (4)    // max string length of REGIST_KEY IN TOKEN
#define MAX_LENGTH_TUYA_HOST      (64)

typedef struct {
    char region[MAX_LENGTH_REGION + 1]; // get from token
    struct {
        char host[MAX_LENGTH_TUYA_HOST + 1];
        uint16_t port;
        char* cert;
    } atop;
    struct {
        char host[MAX_LENGTH_TUYA_HOST + 1];
        uint16_t port;
        char* cert;
    } mqtt;
} tuya_endpoint_t;

typedef struct {
    char regist[MAX_LENGTH_REGIST + 1];
    const tuya_endpoint_t* endpoint;
    int endpoint_num;
} tuya_cloud_environment_t;

typedef struct {
    char region[MAX_LENGTH_REGION + 1];
    char regist_key[MAX_LENGTH_REGIST + 1];
    tuya_endpoint_t endpoint;
} endpoint_management_t;


const tuya_endpoint_t default_endpint_pro[] = {
    {.region = "AY", .atop = {"a2.tuyacn.com", 443}, .mqtt = {"m2.tuyacn.com", 8883}},
    {.region = "AZ", .atop = {"a2.tuyaus.com", 443}, .mqtt = {"m2.tuyaus.com", 8883}},
    {.region = "EU", .atop = {"a2.tuyaeu.com", 443}, .mqtt = {"m2.tuyaeu.com", 8883}},
    {.region = "IN", .atop = {"a2.tuyain.com", 443}, .mqtt = {"m2.tuyain.com", 8883}},
    {.region = "UE", .atop = {"a2-ueaz.tuyaus.com", 443}, .mqtt = {"m2-ueaz.tuyaus.com", 8883}},
};

const tuya_endpoint_t default_endpint_pr_0[] = {
    {.region = "AY", .atop = {"a2-cn.wgine.com", 443}, .mqtt = {"m2-cn.wgine.com", 8883}},
    {.region = "AZ", .atop = {"a2-us.wgine.com", 443}, .mqtt = {"m2-us.wgine.com", 8883}},
    {.region = "EU", .atop = {"a2-eu.wgine.com", 443}, .mqtt = {"m2-eu.wgine.com", 8883}},
    {.region = "IN", .atop = {"a2-ind.wgine.com", 443}, .mqtt = {"m2-ind.wgine.com", 8883}},
    {.region = "UE", .atop = {"a2-ueaz.wgine.com", 443}, .mqtt = {"m2-ueaz.wgine.com", 8883}},
};

const tuya_cloud_environment_t default_env_list[] = {
    {.regist = "pro",  .endpoint = default_endpint_pro,  .endpoint_num = sizeof(default_endpint_pro)/sizeof(tuya_endpoint_t)},
    {.regist = "pr_0", .endpoint = default_endpint_pr_0, .endpoint_num = sizeof(default_endpint_pr_0)/sizeof(tuya_endpoint_t)},
};
 
static endpoint_management_t endpoint_mgr;


static int tuya_region_regist_key_write( const char* region, const char* regist_key )
{
    if ( NULL == region || NULL == regist_key ) {
        TY_LOGE( "Invalid param" );
        return OPRT_INVALID_PARM;
    }

    /* Write kv storage */
    local_storage_set("binding.region", region, strlen(region) + 1);
    local_storage_set("binding.regist_key", regist_key, strlen(regist_key) + 1);

    return OPRT_OK;
}

static int tuya_region_regist_key_read( char* region, char* regist_key )
{
    if ( NULL == region || NULL == regist_key ) {
        TY_LOGE( "Invalid param" );
        return OPRT_INVALID_PARM;
    }

    /* Read the region&env from kv storage */
    size_t len = 0;
    len = MAX_LENGTH_REGION;
    if (local_storage_get("binding.region", region, &len) != OPRT_OK) {
        return OPRT_KVS_RD_FAIL;
    }
    
    len = MAX_LENGTH_REGIST;
    if (local_storage_get("binding.regist_key", regist_key, &len) != OPRT_OK) {
        return OPRT_KVS_RD_FAIL;
    }

    return OPRT_OK;
}

int tuya_region_regist_key_remove()
{
    local_storage_del("binding.region");
    local_storage_del("binding.regist_key");
    return OPRT_OK;
}

int tuya_region_regist_key_set( const char* region, const char* regist_key )
{
    if (tuya_region_regist_key_write( region, regist_key ) != OPRT_OK) {
        return OPRT_KVS_WR_FAIL;
    }
    return tuya_region_regist_key_load();
}

int tuya_region_regist_key_load()
{
    int ret;
    ret = tuya_region_regist_key_read(endpoint_mgr.region, endpoint_mgr.regist_key);

    /* Load default domain */
    int i;

    /* find the defalut regist key */
    tuya_cloud_environment_t* env = (tuya_cloud_environment_t*)&default_env_list[0]; // defalut
    for (i = 0; i < sizeof(default_env_list)/sizeof(tuya_cloud_environment_t); i++) {
        if (memcmp(endpoint_mgr.regist_key, default_env_list[i].regist, sizeof(endpoint_mgr.regist_key)) == 0) {
            env = (tuya_cloud_environment_t*)&default_env_list[i];
            TY_LOGI("Environment:%s", default_env_list[i].regist);
            break;
        }
    }

    /* find the default region */
    tuya_endpoint_t* endpoint = (tuya_endpoint_t*)&env->endpoint[0]; // defalut
    for (i = 0; i < env->endpoint_num; i++) {
        if (memcmp(endpoint_mgr.region, env->endpoint[i].region, sizeof(endpoint_mgr.region)) == 0) {
            endpoint = (tuya_endpoint_t*)&env->endpoint[i];
            TY_LOGI("Host region:%s", env->endpoint[i].region);
            break;
        }
    }

    endpoint_mgr.endpoint = *endpoint;
    return OPRT_OK;
}

const char* tuya_atop_server_host_get()
{
    return endpoint_mgr.endpoint.atop.host;
}

uint16_t tuya_atop_server_port_get()
{
    return endpoint_mgr.endpoint.atop.port;
}

const char* tuya_mqtt_server_host_get()
{
    return endpoint_mgr.endpoint.mqtt.host;
}

uint16_t tuya_mqtt_server_port_get()
{
    return endpoint_mgr.endpoint.mqtt.port;
}