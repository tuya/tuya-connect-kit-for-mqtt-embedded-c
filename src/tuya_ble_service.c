#include <stdint.h>
#include "tuya_cloud_types.h"

#include "tuya_log.h"
#include "MultiTimer.h"
#include "tuya_iot.h"
#include "ble_interface.h"
#include "system_interface.h"
#include "aes_inf.h"
#include "uni_md5.h"

#include "cJSON.h"
#include "queue.h"
#include "tuya_ble_service.h"

/* BLE server */
#define BLE_NETCFG_SERVICE_NUM          (1)
#define BLE_NETCFG_SERVICE_UUID         (0xFD50)

/* BLE characteristic */
#define BLE_NETCFG_CHAR_NUM             (2)

#define BLE_NETCFG_WRITE_INDEX          (0)
#define BLE_NETCFG_WRITE_CHAR_UUID      (0x0001)
static const uint8_t BLE_NETCFG_WRITE_CHAR_UUID128[] = {0xD0, 0x07, 0x9B, 0x5F, 0x80, 0x00, 0x01, 0x80, 0x01, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

#define BLE_NETCFG_NOTIFY_INDEX         (1)
#define BLE_NETCFG_NOTIFY_CHAR_UUID     (0x0002)
static const uint8_t BLE_NETCFG_NOTIFY_CHAR_UUID128[] = {0xD0, 0x07, 0x9B, 0x5F, 0x80, 0x00, 0x01, 0x80, 0x01, 0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};

/* BLE device disconnection time */
#define BLE_DISCONNECT_TIME_MS          (1000U * 30)

#define APP_PACK_DATA_MAX               (0x00FF)

/* length of plaintext frame data */
#define FRAME_ENCRYPT_MODE_SIZE         (1)
#define FRAME_IV_SIZE                   (16)
#define FRAME_SN_SIZE                   (4)
#define FRAME_ACK_SN_SIZE               (4)
#define FRAME_CMD_SIZE                  (2)
#define FRAME_DATA_LEN_SIZE             (2)
#define FRAME_CRC16_SIZE                (2)

/* app command */
#define APP_CMD_DEV_INFO                (0x0000)
#define APP_CMD_PAIR_REQ                (0x0001)
#define APP_CMD_GET_TOKEN               (0x0021)

/* device information */
#define FIREWARE_VERSION_1              (0x0000)
#define HARDWARE_VERSION_1              (0x0000)
#define FIREWARE_VERSION_2              (0x000000)
#define HARDWARE_VERSION_2              (0x000000)
#define MCU_FIREWARE_VERSION            (0x000000)
#define MCU_HARDWARE_VERSION            (0x000000)
#define TUYA_BLE_PROTOCOL_VERSION       (0x0404) // v4.4

#pragma pack(1)
typedef struct {
    uint32_t sn;
    uint32_t ack_sn;
    uint16_t cmd;
    uint16_t len;
    uint8_t data[0]; // data + crc16
}tuya_ble_frame_plain_s;
#pragma pack()

#pragma pack(1)
typedef struct {
    uint8_t encrypt_mode;
    uint8_t iv[16];
    uint8_t ciphertext[0];
}tuya_ble_frame_s;
#pragma pack()

typedef struct {
    uint32_t pack_seq;
    uint32_t frame_len;
    uint8_t version;
    tuya_ble_frame_s *data; // encrypt mode (1 byte) + iv (16 byte) + ciphertext
}tuya_ble_pack_s;

typedef enum {
    BLE_SVC_STATUS_START = 0,
    BLE_SVC_STATUS_CONNECT,
    BLE_SVC_STATUS_DISCONNECT,
    BLE_SVC_STATUS_RECV_DATA,
    BLE_SVC_STATUS_GET_TOKEN,
    BLE_SVC_STATUS_STOP,
}tuya_ble_service_status_e;

// ble msg queue
struct ble_msg_node {
    TAILQ_ENTRY(ble_msg_node) next;
    tuya_ble_service_status_e cmd;
    uint32_t len;
    uint8_t data[0];
};
TAILQ_HEAD(ble_msg_queue, ble_msg_node);

typedef struct {
    uint8_t pid[MAX_LENGTH_PRODUCT_ID+1];
    uint8_t uuid[MAX_LENGTH_UUID+1];
    uint8_t uuid_16[16];
    uint8_t auth_key[MAX_LENGTH_AUTHKEY+1];
    ble_token_get_callback cb;
    uint8_t is_stop;

    uint16_t conn_hdl;
    uint16_t write_char_hdl;
    uint16_t notify_char_hdl;

    uint32_t sn;
    uint16_t app_mtu;
    uint8_t srand[6];
    uint8_t key_1[16];
    uint8_t key_2[16];
    uint8_t register_key[16];
    uint8_t key_mask;

    MultiTimer timer_hdl;
    struct ble_msg_queue msg_queue;
}tuya_ble_service_params_s;

typedef struct {
    wifi_info_t wifi_info;
    tuya_binding_info_t binding_info;
}ble_msg_token_t;

typedef enum {
    ENCRYPTION_MODE_KEY_1 = 1,
    ENCRYPTION_MODE_KEY_2,
    ENCRYPTION_MODE_MAX,
}tuya_ble_service_key_type_e;

static tuya_ble_service_params_s *sg_ble_service_params = NULL;

static void tuya_device_id_20_to_16(uint8_t *in,uint8_t *out)
{
    uint8_t i,j;
    uint8_t temp[4];
    for(i=0; i<5; i++) {
        for(j=i*4; j<(i*4+4); j++) {
            if((in[j] >= 0x30)&&(in[j] <= 0x39)) {
                temp[j-i*4] = in[j] - 0x30;
            } else if((in[j] >= 0x41)&&(in[j] <= 0x5A)) {
                temp[j-i*4] = in[j] - 0x41 + 36;
            } else if((in[j] >= 0x61)&&(in[j] <= 0x7A)) {
                temp[j-i*4] = in[j] - 0x61 + 10;
            }
        }

        out[i*3] = temp[0]&0x3F;
        out[i*3] <<= 2;
        out[i*3] |= ((temp[1]>>4)&0x03);

        out[i*3+1] = temp[1]&0x0F;
        out[i*3+1] <<= 4;
        out[i*3+1] |= ((temp[2]>>2)&0x0F);

        out[i*3+2] = temp[2]&0x03;
        out[i*3+2] <<= 6;
        out[i*3+2] |= temp[3]&0x3F;
    }
    out[15] = 0xFF;

    return;
}

static void get_random(uint8_t *random, uint16_t random_size)
{
    uint16_t i=0;
    for (i=0; i<random_size; i++) {
        random[i] = system_random() & 0xFF;
    }
    return;
}

static void ble_msg_queue_insert(tuya_ble_service_status_e cmd, uint32_t len, uint8_t *data)
{
    struct ble_msg_node *node = system_malloc(sizeof(struct ble_msg_node)+len);
    TUYA_CHECK_NULL_GOTO(node, __EXIT);
    memset(node, 0, sizeof(struct ble_msg_node)+len);

    node->cmd = cmd;
    node->len = len;
    memcpy(node->data, data, len);

    TAILQ_INSERT_TAIL(&sg_ble_service_params->msg_queue, node, next);

__EXIT:
    return;
}

static int ble_adv_data_set(tuya_ble_service_params_s *dev_info, TKL_BLE_DATA_T *p_adv, TKL_BLE_DATA_T *p_scan_rsp)
{
    OPERATE_RET rt = OPRT_OK;
    uint8_t segment_length = 0;

    /* adv data */
    /* BLE link flag */
    segment_length = 1;
    p_adv->p_data[p_adv->length + segment_length] = 0x01; segment_length++;
    p_adv->p_data[p_adv->length + segment_length] = 0x06; segment_length++;
    p_adv->p_data[p_adv->length] = segment_length-1;
    p_adv->length += segment_length;
    /* Service UUID */
    segment_length = 1;
    p_adv->p_data[p_adv->length + segment_length] = 0x02; segment_length++;
    p_adv->p_data[p_adv->length + segment_length] = 0x50; segment_length++;
    p_adv->p_data[p_adv->length + segment_length] = 0xFD; segment_length++;
    p_adv->p_data[p_adv->length] = segment_length-1;
    p_adv->length += segment_length;
    /* Service data */
    segment_length = 1;
    p_adv->p_data[p_adv->length + segment_length] = 0x16; segment_length++;
    p_adv->p_data[p_adv->length + segment_length] = 0x50; segment_length++;
    p_adv->p_data[p_adv->length + segment_length] = 0xFD; segment_length++;
    // Frame Control
    p_adv->p_data[p_adv->length + segment_length] = 0x43; segment_length++;
    p_adv->p_data[p_adv->length + segment_length] = 0x00; segment_length++;
    // PID: type (1 byte) + len (1 byte) + pid
    p_adv->p_data[p_adv->length + segment_length] = 0x00; segment_length++;
    p_adv->p_data[p_adv->length + segment_length] = strlen(dev_info->pid); segment_length++;
    strcpy(&p_adv->p_data[p_adv->length + segment_length], dev_info->pid); segment_length += strlen(dev_info->pid);
    p_adv->p_data[p_adv->length] = segment_length-1;
    p_adv->length += segment_length;

    /* scan rsp data */
    // DIY
    segment_length = 1;
    p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 0xFF; segment_length++;
    // company code: 0x07D0
    p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 0xD0; segment_length++;
    p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 0x07; segment_length++;
    // ENC mode
    p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 0x00; segment_length++;
    // communication type
    p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 0x00; segment_length++;
    p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 0x0C; segment_length++;
    // flag
    if (20 == strlen(dev_info->uuid)) {
        p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 0x11; segment_length++;
    } else {
        p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 0x10; segment_length++;
    }


    uint8_t md5_data[16] = {0};
    uni_md5_digest_tolal(&p_adv->p_data[11], 20, md5_data);

    uint8_t *aes_key = md5_data;
    uint8_t *aes_iv = md5_data;
    uint8_t cipher[16] = {0};
    uint8_t *plain = NULL;
    uint8_t plain_len = 16;
    plain = dev_info->uuid_16;
    tal_aes128_cbc_encode_raw(plain, plain_len, aes_key, aes_iv, cipher);

    memcpy(&p_scan_rsp->p_data[p_scan_rsp->length + segment_length], cipher, plain_len);
    segment_length += plain_len;
    p_scan_rsp->p_data[p_scan_rsp->length] = segment_length - 1;
    p_scan_rsp->length += segment_length;

    // name
    segment_length = 1;
    p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 0x09; segment_length++;
    p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 'T'; segment_length++;
    p_scan_rsp->p_data[p_scan_rsp->length + segment_length] = 'Y'; segment_length++;
    p_scan_rsp->p_data[p_scan_rsp->length] = segment_length - 1;
    p_scan_rsp->length += segment_length;

    return rt;
}

static int ble_service_adv_start(void)
{
    OPERATE_RET rt = OPRT_OK;
    uint8_t adv_data_buf[31] = {0};
    uint8_t scan_rsp_buf[31] = {0};
    TKL_BLE_DATA_T adv_data = {
        .length = 0,
        .p_data = adv_data_buf
    };
    TKL_BLE_DATA_T scan_rsp_data = {
        .length = 0,
        .p_data = scan_rsp_buf
    };

    TUYA_CALL_ERR_RETURN(ble_adv_data_set(sg_ble_service_params, &adv_data, &scan_rsp_data));
    TUYA_CALL_ERR_RETURN(tkl_ble_gap_adv_rsp_data_set(&adv_data, &scan_rsp_data));

    TKL_BLE_GAP_ADV_PARAMS_T adv_params = {
        .adv_type = TKL_BLE_GAP_ADV_TYPE_CONN_SCANNABLE_UNDIRECTED,
        .adv_channel_map = 0x01 | 0x02 | 0x04,
        .adv_interval_min = 30,
        .adv_interval_max = 60,
        .direct_addr = {
            .type = TKL_BLE_GAP_ADDR_TYPE_PUBLIC,
        },
    };
    TUYA_CALL_ERR_RETURN(tkl_ble_gap_adv_start(&adv_params));
    PR_DEBUG("ble adv start");

    return rt;
}

static int ble_service_key_generation(uint8_t *iv)
{
    OPERATE_RET rt = OPRT_OK;

    /* set key1 */
    uint8_t in_data[48] = {0};
    uint8_t out_data[48] = {0};
    uint8_t key_iv[FRAME_IV_SIZE] = {0};
    /* key1 plaintext */
    memcpy(in_data, sg_ble_service_params->auth_key, 32);
    memcpy(in_data+32, iv, FRAME_IV_SIZE);
    /* key1 iv */
    TUYA_CALL_ERR_RETURN(tal_aes128_cbc_encode_raw(in_data, 48, sg_ble_service_params->auth_key, key_iv, out_data));
    memcpy(sg_ble_service_params->key_1, out_data+32, 16);
    sg_ble_service_params->key_mask |= 0x02;

    /* set key2 */
    uint8_t md5_data[22] = {0};
    get_random(sg_ble_service_params->srand, 6);
    memcpy(md5_data, sg_ble_service_params->key_1, 16);
    memcpy(md5_data+16, sg_ble_service_params->srand, 6);
    uni_md5_digest_tolal(md5_data, 22, sg_ble_service_params->key_2);
    sg_ble_service_params->key_mask |= 0x04;

    /* regist key */
    memcpy(key_iv, iv, 16);
    tal_aes128_ecb_encode_raw(key_iv, 16, sg_ble_service_params->register_key, sg_ble_service_params->auth_key);

    return rt;
}

static int ble_recv_data_unpack(uint8_t *data, uint32_t len, tuya_ble_pack_s *pack)
{
    OPERATE_RET rt = OPRT_OK;
    static uint32_t data_offset = 0;
    uint8_t tmp_num = 0;
    uint32_t tmp_pack_seq = 0;
    uint16_t pack_offset = 0;

    /* get pack seq */
    pack_offset = 0;
    tmp_pack_seq = (data[pack_offset] & 0x7F);
    tmp_num = 0;
    while (data[pack_offset] & 0x80) {
        pack_offset++;
        tmp_pack_seq += (data[pack_offset] & 0x7F) * (0x00000080 << (tmp_num*8));
        tmp_num++;
    }
    pack_offset++;

    if (tmp_pack_seq == 0) { // first pack
        data_offset = 0;
        /* get frame len */
        pack->frame_len = 0;
        pack->frame_len += (data[pack_offset] & 0x7F);
        tmp_num = 0;
        while (data[pack_offset] & 0x80) {
            pack_offset++;
            pack->frame_len += (data[pack_offset] & 0x7F) * (0x00000080 << (tmp_num*8));
            tmp_num++;
        }
        pack_offset++;

        if (NULL != pack->data) {
            system_free(pack->data);
            pack->data = NULL;
        }

        /* malloc data memory */
        pack->data = system_malloc(pack->frame_len);
        if (NULL == pack->data) {
            rt = OPRT_MALLOC_FAILED;
            goto __ERR;
        }
        memset(pack->data, 0, pack->frame_len);

        /* get protocol version */
        pack->version = data[pack_offset] >> 4; pack_offset++;
    }

    /* process ble frame crypt data */
    memcpy(&pack->data[data_offset], &data[pack_offset], len - pack_offset);
    data_offset += len - pack_offset;
    rt = data_offset;

    return rt;

__ERR:
    if (NULL != pack->data) {
        system_free(pack->data);
        pack->data = NULL;
    }
    return rt;
}

static uint16_t get_crc_16(uint8_t *data, uint16_t size)
{
    uint16_t poly[2] = {0, 0xa001}; //0x8005 <==> 0xa001
    uint16_t crc = 0xffff;
    int i, j;

    for (j = size; j > 0; j--) {
        uint8_t ds = *data++;

        for (i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ poly[(crc ^ ds) & 1];
            ds = ds >> 1;
        }
    }

    return crc;
}

static int ble_recv_data_decrypt(tuya_ble_pack_s *recv_pack, tuya_ble_frame_plain_s *recv_frame)
{
    OPERATE_RET rt = OPRT_OK;
    uint8_t *key = NULL;
    uint8_t iv[FRAME_IV_SIZE] = {0};
    uint32_t ciphertext_len = 0;
    uint32_t crc16_len = 0;
    uint16_t crc16_value = 0;

    // check encrypt key
    if (0 == sg_ble_service_params->key_mask) { // no key, first pack
        TUYA_CALL_ERR_RETURN(ble_service_key_generation(recv_pack->data->iv));
    }

    switch(recv_pack->data->encrypt_mode) {
        case ENCRYPTION_MODE_KEY_1:
            key = sg_ble_service_params->key_1;
        break;
        case ENCRYPTION_MODE_KEY_2:
            key = sg_ble_service_params->key_2;
        break;
        default :
            return OPRT_COM_ERROR;
    }
    memcpy(iv, recv_pack->data->iv, FRAME_IV_SIZE);

    ciphertext_len = recv_pack->frame_len - FRAME_ENCRYPT_MODE_SIZE - FRAME_IV_SIZE;
    TUYA_CALL_ERR_RETURN(tal_aes128_cbc_decode_raw(recv_pack->data->ciphertext, ciphertext_len, key, iv, (uint8_t *)recv_frame));

    // check crc16
    crc16_len = UNI_HTONS(recv_frame->len);
    crc16_len += FRAME_SN_SIZE+FRAME_ACK_SN_SIZE+FRAME_CMD_SIZE+FRAME_DATA_LEN_SIZE;
    crc16_value = ((uint8_t *)recv_frame)[crc16_len]<<8 | ((uint8_t *)recv_frame)[crc16_len+1];
    if (crc16_value != get_crc_16((uint8_t *)recv_frame, crc16_len)) {
        PR_ERR("receive data crc16 check fail");
        return OPRT_COM_ERROR;
    }

    recv_frame->sn = UNI_NTOHL(recv_frame->sn);
    recv_frame->ack_sn = UNI_NTOHL(recv_frame->ack_sn);
    recv_frame->cmd = UNI_HTONS(recv_frame->cmd);
    recv_frame->len = UNI_HTONS(recv_frame->len);

    return rt;
}

static OPERATE_RET ble_service_get_device_info(const uint8_t *srand, const uint8_t *register_key , uint8_t *p_data, uint16_t len)
{
    uint16_t data_offset = 0;

    if (NULL == p_data) {
        return OPRT_COM_ERROR;
    }
    memset(p_data, 0, len);

    //* firmware version 1
    p_data[data_offset] = (FIREWARE_VERSION_1 >> 8)&0xFF; data_offset++;
    p_data[data_offset] = FIREWARE_VERSION_1&0xFF; data_offset++;
    //* tuya ble protocol version
    p_data[data_offset] = (TUYA_BLE_PROTOCOL_VERSION >> 8)&0xFF; data_offset++;
    p_data[data_offset] = TUYA_BLE_PROTOCOL_VERSION&0xFF; data_offset++;
    //* flag
    p_data[data_offset] = 0x05; data_offset++;
    // bond
    p_data[data_offset] = 0x00; data_offset++;
    //* srand
    memcpy(&p_data[data_offset], srand, 6);
    data_offset += 6;
    //* hardware version 1
    p_data[data_offset] = (HARDWARE_VERSION_1 >> 8)&0xFF; data_offset++;
    p_data[data_offset] = HARDWARE_VERSION_1&0xFF; data_offset++;
    //* register_key + 0(16 byte)
    memcpy(&p_data[data_offset], register_key, 16); data_offset += 32;
    //* fireware version 2
    p_data[data_offset] = (FIREWARE_VERSION_2 >> 16)&0xFF; data_offset++;
    p_data[data_offset] = (FIREWARE_VERSION_2 >> 8)&0xFF; data_offset++;
    p_data[data_offset] = FIREWARE_VERSION_2&0xFF; data_offset++;
    //* hardware version 2
    p_data[data_offset] = (HARDWARE_VERSION_2 >> 16)&0xFF; data_offset++;
    p_data[data_offset] = (HARDWARE_VERSION_2 >> 8)&0xFF; data_offset++;
    p_data[data_offset] = HARDWARE_VERSION_2&0xFF; data_offset++;
    //* communication type
    p_data[data_offset] = 0x00; data_offset++;
    p_data[data_offset] = 0x0C; data_offset++;
    //* flag2
    p_data[data_offset] = 0x00; data_offset++;
    // device virtual id
    data_offset += 22;
    //* mcu fireware version
    p_data[data_offset] = (MCU_FIREWARE_VERSION >> 16)&0xFF; data_offset++;
    p_data[data_offset] = (MCU_FIREWARE_VERSION >> 8)&0xFF; data_offset++;
    p_data[data_offset] = MCU_FIREWARE_VERSION&0xFF; data_offset++;
    //* mcu hardware version
    p_data[data_offset] = (MCU_HARDWARE_VERSION >> 16)&0xFF; data_offset++;
    p_data[data_offset] = (MCU_HARDWARE_VERSION >> 8)&0xFF; data_offset++;
    p_data[data_offset] = MCU_HARDWARE_VERSION&0xFF; data_offset++;
    //* wifi flag
    p_data[data_offset] = 0x01; data_offset++;
    //* reserve
    data_offset++;
    //* device function
    p_data[data_offset] = 0x00; data_offset++;
    p_data[data_offset] = 0x00; data_offset++;
    p_data[data_offset] = 0x00; data_offset++;
    //* ble address type
    p_data[data_offset] = 0x00; data_offset++;
    //* ble mac address
    data_offset += 6;
    //* fireware key
    data_offset++;
    //* zigbee mac len
    data_offset++;
    //* attach len
    data_offset++;
    //* packet max size len
    p_data[data_offset] = 0x02; data_offset++;
    p_data[data_offset] = APP_PACK_DATA_MAX>>8; data_offset++;
    p_data[data_offset] = APP_PACK_DATA_MAX; data_offset++;
    //* sl len
    data_offset++;

    return data_offset;
}

static int ble_recv_cmd_process(tuya_ble_frame_plain_s *recv_frame, tuya_ble_frame_s **output, uint32_t *output_size)
{
    OPERATE_RET rt = OPRT_OK;
    uint8_t *key = NULL;
    uint8_t iv[FRAME_IV_SIZE] = {0};
    tuya_ble_frame_s *rsp_frame = NULL;
    uint8_t encrypt_mode = 0;

    uint8_t rsp_data[255] = {0};
    uint16_t rsp_data_len = 0;

    switch (recv_frame->cmd) {
        case APP_CMD_DEV_INFO:
            /* set app mtu */
            sg_ble_service_params->app_mtu = recv_frame->data[0] << 8 | recv_frame->data[1];
            PR_DEBUG("app mtu: 0x%04x", sg_ble_service_params->app_mtu);
            /* get response frame */
            rsp_data_len = ble_service_get_device_info(sg_ble_service_params->srand, sg_ble_service_params->register_key, rsp_data, 255);
            if (rsp_data_len < 0) {
                PR_ERR("get device infomation fail, %d", rsp_data_len);
                rt = rsp_data_len;
                goto __ERR;
            }
            key = sg_ble_service_params->key_1;
            encrypt_mode = ENCRYPTION_MODE_KEY_1;
        break;
        case APP_CMD_PAIR_REQ :
            rsp_data_len = 1;
            if (0 == memcmp(recv_frame->data, sg_ble_service_params->uuid_16, 16)) {
                rsp_data[0] = 0;
            } else {
                rsp_data[0] = 1;
            }
            key = sg_ble_service_params->key_2;
            encrypt_mode = ENCRYPTION_MODE_KEY_2;
        break;
        case APP_CMD_GET_TOKEN :
            ble_msg_queue_insert(BLE_SVC_STATUS_GET_TOKEN, recv_frame->len, recv_frame->data);
            rsp_data_len = 1;
            rsp_data[0] = 0;
            key = sg_ble_service_params->key_2;
            encrypt_mode = ENCRYPTION_MODE_KEY_2;
        break;
        default:
            rt = OPRT_COM_ERROR;
            goto __ERR;
    }

    uint32_t plaintext_size = sizeof(tuya_ble_frame_plain_s) + rsp_data_len + FRAME_CRC16_SIZE;
    /* 16-byte alignment */
    uint8_t align = 16;
    uint8_t aligned_num  = plaintext_size % align;
    if (aligned_num) {
        plaintext_size += align - aligned_num ;
    }
    /* malloc plaintext */
    tuya_ble_frame_plain_s *plaintext = system_malloc(plaintext_size);
    TUYA_CHECK_NULL_GOTO(plaintext, __ERR);
    memset(plaintext, 0, plaintext_size);

    sg_ble_service_params->sn++;
    plaintext->sn = UNI_HTONL(sg_ble_service_params->sn);
    plaintext->ack_sn = UNI_HTONL(recv_frame->sn);
    plaintext->cmd = UNI_HTONS(recv_frame->cmd);
    plaintext->len = UNI_HTONS(rsp_data_len);

    memcpy(plaintext->data, rsp_data, rsp_data_len);
    uint16_t rsp_frame_crc16 = get_crc_16((uint8_t *)plaintext, FRAME_SN_SIZE+FRAME_ACK_SN_SIZE+FRAME_CMD_SIZE+FRAME_DATA_LEN_SIZE+rsp_data_len);
    plaintext->data[rsp_data_len] = rsp_frame_crc16 >> 8;
    plaintext->data[rsp_data_len+1] = rsp_frame_crc16;

    /* malloc rsp_frame(output) */
    *output_size = sizeof(tuya_ble_frame_s) + plaintext_size;
    rsp_frame = (tuya_ble_frame_s *)system_malloc(*output_size);
    TUYA_CHECK_NULL_GOTO(rsp_frame, __ERR);
    *output = rsp_frame;
    memset(rsp_frame, 0, *output_size);

    rsp_frame->encrypt_mode = encrypt_mode;
    get_random(rsp_frame->iv, FRAME_IV_SIZE);
    memcpy(iv, rsp_frame->iv, FRAME_IV_SIZE);

    TUYA_CALL_ERR_GOTO(tal_aes128_cbc_encode_raw((uint8_t*)plaintext, plaintext_size, key, iv, rsp_frame->ciphertext), __ERR);

    if (NULL != (plaintext)) {
        system_free(plaintext);
        plaintext = NULL;
    }
    return rt;

__ERR:
    if (NULL != (rsp_frame)) {
        system_free(rsp_frame);
        rsp_frame = NULL;
        *output = NULL;
    }

    if (NULL != (plaintext)) {
        system_free(plaintext);
        plaintext = NULL;
    }

    return rt;
}

static int ble_rsp_data_pack_and_send(uint8_t *frame, uint32_t frame_size)
{
    int rt = OPRT_OK;
    uint32_t total_len = 0;
    uint32_t pack_len = 0;

    uint8_t *send_data = NULL;

    total_len = frame_size + 4 + 4 + 1;
    if (total_len > sg_ble_service_params->app_mtu) {
        PR_DEBUG("Need Sub-pack");
        pack_len = sg_ble_service_params->app_mtu;
    } else {
        pack_len = total_len;
    }

    send_data = system_malloc(pack_len);
    TUYA_CHECK_NULL_GOTO(send_data, __EXIT);
    memset(send_data, 0, pack_len);

    uint32_t pack_seq = 0;
    int32_t remain_len = frame_size;
    uint32_t tmp_num = 0;
    uint32_t copy_len = 0;
    uint32_t data_offset = 0;
    uint16_t i = 0;
    do {
        data_offset = 0;
        tmp_num = pack_seq;
        memset(send_data, 0, pack_len);
        for (i = 0; i < 4; i++) {
            send_data[data_offset] = tmp_num % 0x80;
            if ((tmp_num / 0x80)) {
                send_data[data_offset] |= 0x80;
            }
            data_offset++;
            tmp_num /= 0x80;
            if (0 == tmp_num) {
                break;
            }
        }
        if (pack_seq == 0) { // first pack
            tmp_num = frame_size;
            for (i = 0; i < 4; i++) {
                send_data[data_offset] = tmp_num % 0x80;
                if ((tmp_num / 0x80)) {
                    send_data[data_offset] |= 0x80;
                }
                data_offset++;
                tmp_num /= 0x80;
                if (0 == tmp_num) {
                    break;
                }
            }
            /* version */
            send_data[data_offset] = 0x04<<4; data_offset++;
        }

        /* copy frame data */
        tmp_num = pack_len - data_offset;
        if (tmp_num > frame_size) {
            copy_len = frame_size;
        } else {
            copy_len = tmp_num;
        }

        memcpy(&send_data[data_offset], &frame[frame_size-remain_len], copy_len); data_offset += copy_len;
        remain_len -= copy_len;

        TUYA_CALL_ERR_GOTO(tkl_ble_gatts_value_notify(sg_ble_service_params->conn_hdl, sg_ble_service_params->notify_char_hdl, send_data, data_offset), __EXIT);
        PR_DEBUG("ble notify send ok");

        pack_seq++;
    } while(remain_len > 0);

__EXIT:
    if (NULL != send_data) {
        system_free(send_data);
        send_data = NULL;
    }

    return rt;
}

static void ble_recv_data_process(uint8_t *data, uint32_t len)
{
    OPERATE_RET rt = OPRT_OK;
    static tuya_ble_pack_s recv_pack = {0};
    tuya_ble_frame_plain_s *recv_frame = NULL;
    uint32_t recv_frame_len = 0;
    tuya_ble_frame_s *rsp_frame = NULL;
    uint32_t rsp_frame_size = 0;

    /* check connect handle, char handle */
    if (TKL_BLE_GATT_INVALID_HANDLE == sg_ble_service_params->conn_hdl || \
            TKL_BLE_GATT_INVALID_HANDLE == sg_ble_service_params->notify_char_hdl) {
        PR_ERR("BLE handle invalid");
        return;
    }

    if (NULL == data || len <= 0) {
        PR_ERR("Input invalid");
        return;
    }

    // unpack
    rt = ble_recv_data_unpack(data, len, &recv_pack);
    if (rt < 0) {
        PR_ERR("ble recv data unpack fail, %d", rt);
        goto __EXIT;
    } else if(rt < recv_pack.frame_len) { // One frame of data not received
        PR_ERR("wait next pack");
        return;
    }
    // decrypt
    recv_frame_len = recv_pack.frame_len - FRAME_ENCRYPT_MODE_SIZE - FRAME_IV_SIZE;
    recv_frame = system_malloc(recv_frame_len);
    TUYA_CHECK_NULL_GOTO(recv_frame, __EXIT);
    memset(recv_frame, 0, recv_frame_len);
    TUYA_CALL_ERR_GOTO(ble_recv_data_decrypt(&recv_pack, recv_frame), __EXIT);

    TUYA_CALL_ERR_GOTO(ble_recv_cmd_process(recv_frame, &rsp_frame, &rsp_frame_size), __EXIT);

    // pack and send to app
    ble_rsp_data_pack_and_send((uint8_t *)rsp_frame, rsp_frame_size);

__EXIT:
    if (NULL != recv_pack.data) {
        system_free(recv_pack.data);
        recv_pack.data = NULL;
    }

    if (NULL != recv_frame) {
        system_free(recv_frame);
        recv_frame = NULL;
    }

    if (NULL != rsp_frame) {
        system_free(rsp_frame);
        rsp_frame = NULL;
    }

    return;
}

static void ble_disconnect(MultiTimer* timer, void* userData)
{
    PR_DEBUG("ble disconnect");
    ble_msg_queue_insert(BLE_SVC_STATUS_DISCONNECT, 0, NULL);
    return;
}

static int ble_service_token_parse(uint8_t *data, ble_msg_token_t *token)
{
    OPERATE_RET rt = OPRT_OK;
    uint8_t *p = NULL;

    cJSON *token_root = cJSON_Parse(data);

    p = cJSON_GetObjectItem(token_root, "ssid")->valuestring;
    strncpy(token->wifi_info.ssid, p, MAX_LENGTH_WIFI_SSID);

    p = cJSON_GetObjectItem(token_root, "pwd")->valuestring;
    strncpy(token->wifi_info.pwd, p, MAX_LENGTH_WIFI_PWD);

    p = cJSON_GetObjectItem(token_root, "token")->valuestring;
    memcpy(token->binding_info.region, p, MAX_LENGTH_REGION);
    memcpy(token->binding_info.token, &p[MAX_LENGTH_REGION], MAX_LENGTH_TOKEN);
    memcpy(token->binding_info.regist_key, &p[MAX_LENGTH_REGION + MAX_LENGTH_TOKEN], MAX_LENGTH_REGIST);

    cJSON_Delete(token_root);

    return rt;
}

static void ble_gap_evt_cb(TKL_BLE_GAP_PARAMS_EVT_T *p_event)
{
    OPERATE_RET rt = OPRT_OK;

    if (NULL == p_event) return;

    switch (p_event->type) {
        case TKL_BLE_GAP_EVT_CONNECT: {
            PR_DEBUG("connect hdl 0x%04x", p_event->conn_handle);
            ble_msg_queue_insert(BLE_SVC_STATUS_CONNECT, sizeof(p_event->conn_handle), (uint8_t *)&p_event->conn_handle);
        }
        break;
        case TKL_BLE_GAP_EVT_DISCONNECT: {
            ble_msg_queue_insert(BLE_SVC_STATUS_DISCONNECT, 0, NULL);
        }
        break;
        default: break;
    }

    return;
}

static void ble_gatt_evt_cb(TKL_BLE_GATT_PARAMS_EVT_T *p_event)
{
    OPERATE_RET rt = OPRT_OK;

    if (NULL == p_event) return;

    switch (p_event->type) {
        case TKL_BLE_GATT_EVT_WRITE_REQ: {
            PR_DEBUG("recv data");
            if (sg_ble_service_params->write_char_hdl != p_event->gatt_event.write_report.char_handle) {
                // nothing to do
                PR_DEBUG("nothing todo");
                break;
            }
            ble_msg_queue_insert(BLE_SVC_STATUS_RECV_DATA, p_event->gatt_event.write_report.report.length,\
                                    p_event->gatt_event.write_report.report.p_data);
        } break;

        default : break;
    }

    return;
}

int tuya_ble_service_start(tuya_ble_service_init_params_t *init_params, ble_token_get_callback cb)
{
    OPERATE_RET rt = OPRT_OK;

    if (NULL != sg_ble_service_params) {
        return OPRT_OK;
    }

    sg_ble_service_params = (tuya_ble_service_params_s *)system_malloc(sizeof(tuya_ble_service_params_s));
    TUYA_CHECK_NULL_RETURN(sg_ble_service_params, OPRT_MALLOC_FAILED);
    memset(sg_ble_service_params, 0, sizeof(tuya_ble_service_params_s));
    sg_ble_service_params->cb = cb;

    // copy device infomation
    memcpy(sg_ble_service_params->pid, init_params->pid, MAX_LENGTH_PRODUCT_ID);
    memcpy(sg_ble_service_params->uuid, init_params->uuid, MAX_LENGTH_UUID);
    memcpy(sg_ble_service_params->auth_key, init_params->auth_key, MAX_LENGTH_AUTHKEY);
    if (20 == strlen(sg_ble_service_params->uuid)) {
        tuya_device_id_20_to_16(sg_ble_service_params->uuid, sg_ble_service_params->uuid_16);
    } else {
        memcpy(sg_ble_service_params->uuid_16, sg_ble_service_params->uuid, 16);
    }

    // ble stack init
    TUYA_CALL_ERR_RETURN(tkl_ble_gap_callback_register(ble_gap_evt_cb));
    TUYA_CALL_ERR_RETURN(tkl_ble_gatt_callback_register(ble_gatt_evt_cb));

    TKL_BLE_CHAR_PARAMS_T ble_netcfg_char[BLE_NETCFG_CHAR_NUM] = {0};
    /* ble write char, app -> device */
    TKL_BLE_CHAR_PARAMS_T *p_char = &ble_netcfg_char[BLE_NETCFG_WRITE_INDEX];
    p_char->handle = TKL_BLE_GATT_INVALID_HANDLE;
    p_char->char_uuid.uuid_type = TKL_BLE_UUID_TYPE_128;
    memcpy(p_char->char_uuid.uuid.uuid128, BLE_NETCFG_WRITE_CHAR_UUID128, 16);
    p_char->property = TKL_BLE_GATT_CHAR_PROP_WRITE | TKL_BLE_GATT_CHAR_PROP_WRITE_NO_RSP;
    p_char->permission = TKL_BLE_GATT_PERM_READ | TKL_BLE_GATT_PERM_WRITE;
    p_char->value_len = 244;

    /* ble notify char, device -> app */
    p_char = &ble_netcfg_char[BLE_NETCFG_NOTIFY_INDEX];
    p_char->handle = TKL_BLE_GATT_INVALID_HANDLE;
    p_char->char_uuid.uuid_type = TKL_BLE_UUID_TYPE_128;
    memcpy(p_char->char_uuid.uuid.uuid128, BLE_NETCFG_NOTIFY_CHAR_UUID128, 128/8);
    p_char->property = TKL_BLE_GATT_CHAR_PROP_NOTIFY;
    p_char->permission = TKL_BLE_GATT_PERM_READ | TKL_BLE_GATT_PERM_WRITE;
    p_char->value_len = 244;

    /* ble service */
    TKL_BLE_SERVICE_PARAMS_T ble_netcfg_service = {
        .handle = TKL_BLE_GATT_INVALID_HANDLE,
        .svc_uuid.uuid_type = TKL_BLE_UUID_TYPE_16,
        .svc_uuid.uuid.uuid16 = BLE_NETCFG_SERVICE_UUID,
        .type = TKL_BLE_UUID_SERVICE_PRIMARY,
        .char_num = BLE_NETCFG_CHAR_NUM,
        .p_char = ble_netcfg_char,
    };
    TKL_BLE_GATTS_PARAMS_T gatt_params = {
        .svc_num = BLE_NETCFG_SERVICE_NUM,
        .p_service = &ble_netcfg_service
    };
    TUYA_CALL_ERR_RETURN(tkl_ble_gatts_service_add(&gatt_params));

    TUYA_CALL_ERR_RETURN(tkl_ble_stack_init(TKL_BLE_ROLE_SERVER));
    sg_ble_service_params->write_char_hdl = ble_netcfg_char[BLE_NETCFG_WRITE_INDEX].handle;
    sg_ble_service_params->notify_char_hdl = ble_netcfg_char[BLE_NETCFG_NOTIFY_INDEX].handle;

    PR_DEBUG("write_char_hdl: 0x%04x", sg_ble_service_params->write_char_hdl);
    PR_DEBUG("notify_char_hdl: 0x%04x", sg_ble_service_params->notify_char_hdl);

    TAILQ_INIT(&sg_ble_service_params->msg_queue);
    ble_msg_queue_insert(BLE_SVC_STATUS_START, 0, NULL);

    return OPRT_OK;
}

void tuya_ble_service_stop(void)
{
    ble_msg_queue_insert(BLE_SVC_STATUS_STOP, 0, NULL);
    return;
}

int ble_service_is_stop(void)
{
    return ((NULL == sg_ble_service_params) ? (1) : (0));
}

int ble_service_loop(void)
{
    OPERATE_RET rt = OPRT_OK;
    struct ble_msg_node *first_node = NULL;
    ble_msg_token_t token_info;

    if (NULL == sg_ble_service_params) {
        PR_ERR("BLE service start fail");
        return OPRT_COM_ERROR;
    }

    /* check queue is null */
    first_node = TAILQ_FIRST(&sg_ble_service_params->msg_queue);
    if (NULL == first_node) {
        return OPRT_OK;
    }

    /* not null, process */
    switch (first_node->cmd) {
        case (BLE_SVC_STATUS_START) :
            /* start adv */
            TUYA_CALL_ERR_RETURN(ble_service_adv_start());
        break;
        case (BLE_SVC_STATUS_CONNECT) :
            sg_ble_service_params->conn_hdl = first_node->data[0] | first_node->data[1]<<8;
            PR_DEBUG("conn_hdl 0x%04x", sg_ble_service_params->conn_hdl);
            /* start timer */
            MultiTimerInit(&sg_ble_service_params->timer_hdl, BLE_DISCONNECT_TIME_MS, ble_disconnect, NULL);
            MultiTimerStart(&sg_ble_service_params->timer_hdl, BLE_DISCONNECT_TIME_MS);
        break;
        case (BLE_SVC_STATUS_DISCONNECT) :
            /* close timer */
            if (MultiTimerActivated(&sg_ble_service_params->timer_hdl)) {
                MultiTimerStop(&sg_ble_service_params->timer_hdl);
            }
            /* Not get token, start ble adv */
            if (!sg_ble_service_params->is_stop) {
                ble_msg_queue_insert(BLE_SVC_STATUS_START, 0, NULL);
            }
        break;
        case (BLE_SVC_STATUS_RECV_DATA) :
            ble_recv_data_process(first_node->data, first_node->len);
        break;
        case (BLE_SVC_STATUS_GET_TOKEN) :
            PR_DEBUG("wifi provision info: %s", first_node->data);
            memset(&token_info, 0, sizeof(ble_msg_token_t));
            ble_service_token_parse(first_node->data, &token_info);
            if (sg_ble_service_params->cb) {
                sg_ble_service_params->cb(token_info.wifi_info, token_info.binding_info);
            }
            tuya_ble_service_stop();
        break;
        case (BLE_SVC_STATUS_STOP) :
            sg_ble_service_params->is_stop = 1;
            /* stop adv */
            TUYA_CALL_ERR_LOG(tkl_ble_gap_adv_stop());
            /* disconnect */
            if (sg_ble_service_params->conn_hdl != TKL_BLE_GATT_INVALID_HANDLE) {
                TUYA_CALL_ERR_LOG(tkl_ble_gap_disconnect(sg_ble_service_params->conn_hdl, \
                                                        TKL_BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION));
                sg_ble_service_params->conn_hdl = TKL_BLE_GATT_INVALID_HANDLE;
            }
        break;
        default : break;
    }

    TAILQ_REMOVE(&sg_ble_service_params->msg_queue, first_node, next);
    system_free(first_node);
    first_node = NULL;

    if (sg_ble_service_params->is_stop && NULL == TAILQ_FIRST(&sg_ble_service_params->msg_queue)) {
        TUYA_CALL_ERR_LOG(tkl_ble_stack_deinit(TKL_BLE_ROLE_SERVER));
        PR_DEBUG("ble service finish");

        if (NULL != sg_ble_service_params) {
            system_free(sg_ble_service_params);
            sg_ble_service_params = NULL;
        }
    }

    return rt;
}
