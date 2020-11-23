#ifndef __ATOP_SERVICE_H_
#define __ATOP_SERVICE_H_

#include <stdint.h>
#include "atop_base.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    const char* token;
    const char* product_key;
    const char* uuid;
    const char* authkey;
    const char* sw_ver;
    const char* pv;
    const char* bv;
    size_t buflen_custom;
    const void* user_data;
} device_activite_params_t;

typedef enum {
    HTTP_DYNAMIC_CFG_ALL,//all
    HTTP_DYNAMIC_CFG_TZ, //time zone
    HTTP_DYNAMIC_CFG_RATERULE,//rate rule for dp
} HTTP_DYNAMIC_CFG_TYPE;

int tuya_device_activate_request(const device_activite_params_t* request, 
                                        atop_base_response_t* response);

int atop_service_client_reset(const char* id, const char* key, 
                                atop_base_response_t* response);

int atop_service_dynamic_cfg_get_v20(const char* id, const char* key, 
                                        HTTP_DYNAMIC_CFG_TYPE type, 
                                        atop_base_response_t* response);

#ifdef __cplusplus
}
#endif
#endif
