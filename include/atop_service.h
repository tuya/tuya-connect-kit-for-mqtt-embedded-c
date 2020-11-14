#ifndef __ATOP_SERVICE_H_
#define __ATOP_SERVICE_H_

#include <stdint.h>
#include "atop_base.h"

#ifdef __cplusplus
extern "C" {
#endif


// HTTP/HTTPS  POST 1.1
#define TI_GET_REGION_CFG_GET "tuya.device.region.config.get"

//强制HTTPS POST 4.2
#define TI_GW_GET_URL_CFG "tuya.device.config.get"
//强制HTTPS POST 4.4
#define TI_GW_ACTIVE_44 "tuya.device.active"
//强制HTTPS POST 2.1
#define TI_GW_WX_ACTIVE_21 "s.gw.dev.pk.active.wx"

//HTTP/HTTPS  POST 1.0
#define TI_GW_DEVICE_TOKEN_CREATE  "tuya.device.token.create"

// HTTP/HTTPS  POST 4.0
//#define TI_GW_IS_EXIST "tuya.device.exist"
// HTTP/HTTPS  POST 4.0
#define TI_GW_RESET "tuya.device.reset"
// HTTP/HTTPS  POST 1.0
#define TI_UG_RST_LOG "atop.online.debug.log"
// HTTP/HTTPS  POST 4.1
#define TI_GW_IF_UPDATE_V41 "tuya.device.versions.update"
// HTTP/HTTPS  POST 4.2
#define TI_GW_GET_UPGRADE_IF_V43 "tuya.device.upgrade.get"
// HTTP/HTTPS  POST 4.1
#define TI_GW_UPGRD_STAT_UPDATE_V41 "tuya.device.upgrade.status.update"
// HTTP/HTTPS  POST 4.1
#define TI_DEV_UPGRADE_STAT_UPDATE_V41 "tuya.device.upgrade.status.update"
//// HTTP/HTTPS  POST 4.1  data含t 加密
//#define TI_DEV_IF_UPDATE_V41 "tuya.device.version.update"
// HTTP/HTTPS  POST 4.4
#define TI_DEV_BIND_V44 "tuya.device.sub.bind"
// HTTP/HTTPS  POST 4.1
#define TI_DEV_UNBIND "tuya.device.sub.unbind"
// HTTP/HTTPS  POST 4.0
#define TI_GET_GW_DEV_TIMER_COUNT "tuya.device.timer.count"
// HTTP/HTTPS  POST 4.0
#define TI_GET_GW_DEV_TIMER "tuya.device.timer.get"

#define TI_GET_DEV_LIST_V30 "tuya.device.sub.list"
#define TI_GET_DEV_SIGMESH_INFO_V10 "tuya.device.sub.detail.get"
#define TI_GET_DEV_SIGMESH_FREE_NODE_LIST_V10 "tuya.device.sig.mesh.node.alloc.batch"
#define TI_GET_DEV_SIGMESH_SOURCE_NODE "tuya.device.sig.mesh.source.id.alloc"

#define TI_DEV_SIGMESH_JOIN_V10 "tuya.device.sig.mesh.join"
#define TI_DEV_SIGMESH_GATEWAY_CREATE_V10 "tuya.device.sig.mesh.create"
// HTTP/HTTPS  POST 2.0
#define TI_GET_DEV_LIST "tuya.device.sub.list"
// HTTP/HTTPS  POST 4.2
#define TI_FW_SELF_UG_INFO_V43 "tuya.device.upgrade.silent.get"
// HTTP/HTTPS  POST 1.0
#define TI_GW_DYN_CFG_GET "tuya.device.dynamic.config.get"
// HTTP/HTTPS  POST 1.0
#define TI_GW_DYN_CFG_ACK "tuya.device.dynamic.config.ack"
// HTTP/HTTPS  POST 1.0
#define TI_DEV_SKILL_UPDATE "tuya.device.skill.update"

#define TI_GW_CERTIFICATE_GET	"tuya.device.domain.certificate.get"
#define TI_STORAGE_CONFIG_GET  "tuya.device.storage.config.get"
#define TI_FILE_UPLOAD_COMPLETE  "tuya.device.common.file.upload.complete"
// HTTP/HTTPS  POST 1.0
#define TI_GET_GW_LINKAGE_CONTENT "tuya.device.linkage.rule.query"

#if defined(ENABLE_LAN_LINKAGE_MASTER) && (ENABLE_LAN_LINKAGE_MASTER==1)
#define TI_LAN_NODE_REPORT "tuya.device.lan.node.report"
#endif

//#define TI_UPLOAD_TIMER_LOG "tuya.device.timer.log.upload"

#define TI_DEV_CONSTRUCTION_UPLOAD "tuya.device.construction.config.upload"

// HTTP/HTTPS  POST 1.0
#define TI_GET_GW_DELETE_STATUS_GET "tuya.device.delete.status.get"

#define TI_GW_SECURITY_VERIFY_V20 "tuya.device.dbauth"
// secure verify (with security chip)

#define TI_UPDATE_LINKAGE_RULE_LOCALIZE "tuya.device.linkage.rule.localize"

#define TI_DEV_RESET "tuya.device.sub.reset" //sub device reset

// HTTP/HTTPS  POST 1.0
#define TI_CUSTOM_CFG_GET "tuya.device.custom.config.get"

#define TI_LOCATION_INFO_GET "tuya.device.location.info.get"

#define TI_PROPERTY_SAVE "tuya.device.property.save"

#define TI_GET_DEV_TOKEN_CREATE "tuya.device.token.create"

#define TI_GET_ENABLE_DELAY_DEF_TIME  "tuya.device.h.s.boot.config.get"

#define TI_IPC_STORAGE_KEY_GET	"tuya.device.ipc.storage.secret.get"
#define TI_GW_PSKKEY_GET	"tuya.device.uuid.pskkey.get"

#define TI_DEV_INFO_SYNC "tuya.device.info.sync"

#define TI_IPC_STORAGE_KEY_GET	"tuya.device.ipc.storage.secret.get"
#define TI_DEV_INFO_SYNC "tuya.device.info.sync"

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

int tuya_device_activate_request(const device_activite_params_t* request, 
                                        atop_base_response_t* response);

#ifdef __cplusplus
}
#endif
#endif
