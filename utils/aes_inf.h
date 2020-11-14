/*
aes_inf.h
Copyright(C),2018-2020, 涂鸦科技 www.tuya.comm
*/
#ifndef _AES_INF_H_
#define _AES_INF_H_

#include "tuya_error_code.h"
#include "tuya_cloud_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*AES128_ECB_ENC_BUF)(const BYTE_T *, const UINT_T, const BYTE_T *, BYTE_T *);
typedef VOID (*AES128_ECB_DEC_BUF)(const BYTE_T *, const UINT_T, const BYTE_T *, BYTE_T *);
typedef VOID (*AES128_CBC_ENC_BUF)(const BYTE_T *, const UINT_T, const BYTE_T *, BYTE_T *, BYTE_T *);
typedef VOID (*AES128_CBC_DEC_BUF)(const BYTE_T *, const UINT_T, const BYTE_T *, BYTE_T *, BYTE_T *);

typedef struct {
    AES128_ECB_ENC_BUF ecb_enc_128;
    AES128_ECB_DEC_BUF ecb_dec_128;
    AES128_CBC_ENC_BUF cbc_enc_128;
    AES128_CBC_DEC_BUF cbc_dec_128;
}AES_METHOD_REG_S;

#define AES128_ENCRYPT_KEY_LEN 16


typedef enum TUYA_HW_AES_MODE_ {
    TUYA_HW_AES_MODE_ENCRYPT,
    TUYA_HW_AES_MODE_DECRYPT,
} TUYA_HW_AES_MODE_E;


typedef enum TUYA_HW_AES_CRYPT_MODE_ {
    TUYA_HW_AES_CRYPT_MODE_ECB,
    TUYA_HW_AES_CRYPT_MODE_CBC,
    TUYA_HW_AES_CRYPT_MODE_CFB,
    TUYA_HW_AES_CRYPT_MODE_OFB,
} TUYA_HW_AES_CRYPT_MODE_E;


typedef struct TUYA_HW_AES_PARAM_ {
    TUYA_HW_AES_MODE_E        method;
    TUYA_HW_AES_CRYPT_MODE_E  encryptMode;
} TUYA_HW_AES_PARAM_S;


typedef struct TUYA_HW_AES_ {
    int (*aes_create)(void** pphdl, TUYA_HW_AES_PARAM_S* pparam);
    int (*aes_destroy)(void* phdl);
    int (*aes_setkey_enc)(void* phdl, const unsigned char *key, unsigned int keybits);
    int (*aes_setkey_dec)(void* phdl, const unsigned char *key, unsigned int keybits);
    int (*aes_crypt_ecb)(void* phdl, const unsigned char* input, size_t length, unsigned char* output);
    int (*aes_crypt_cbc)(void* phdl, const unsigned char* iv, unsigned int ivbits, const unsigned char *input, size_t length, unsigned char *output);
} TUYA_HW_AES_S;


typedef INT_T (*Tuya_CBC_AES128_Init)(VOID);
typedef INT_T (*Tuya_CBC_AES128_Encrypt)(IN BYTE_T *pdata_in,   //data to be encrypted, should NOT be changed
                                             IN UINT_T data_len,     //date length to be encrypted
                                             IN BYTE_T *pdata_out,   //data after encrytion, memory is MALLOC inside tuya SDK already
                                             OUT UINT_T *pdata_out_len,   //data length after encrytion
                                             IN BYTE_T *pkey,     //aes key 
                                             IN BYTE_T *piv);     //aes iv for cbc mode
                                             
typedef INT_T (*Tuya_CBC_AES128_Decrypt)(IN BYTE_T *pdata_in,   //date to be decryted, should NOT be changed
                                             IN UINT_T data_len,     //data length after decryption
                                             IN BYTE_T *pdata_out,   //data after decryption, memory is MALLOC inside tuya SDK already
                                             OUT UINT_T *pdata_out_len,   //data length after decrytion
                                             IN BYTE_T *pkey,     //aes key
                                             IN BYTE_T *piv);     //aes iv for cbc mode

typedef INT_T (*Tuya_CBC_AES128_Destroy)(VOID);

typedef struct
{
    Tuya_CBC_AES128_Init init;
    Tuya_CBC_AES128_Encrypt encrypt;
    Tuya_CBC_AES128_Decrypt decrypt;
    Tuya_CBC_AES128_Destroy destory;
}AES_HW_CBC_FUNC;



UINT_T aes_pkcs7padding_buffer(BYTE_T *p_buffer, UINT_T length);

OPERATE_RET aes_method_register(IN const AES_METHOD_REG_S *aes, IN const TUYA_HW_AES_S* pafunc);

VOID aes_method_unregister(VOID);


OPERATE_RET aes192_cbc_encode(IN const BYTE_T *data,IN const UINT_T len,\
                            IN const BYTE_T *key,IN BYTE_T *iv,\
                            OUT BYTE_T **ec_data,OUT UINT_T *ec_len);
OPERATE_RET aes192_cbc_decode(IN const BYTE_T *data,IN const UINT_T len,\
                            IN const BYTE_T *key,IN BYTE_T *iv,\
                            OUT BYTE_T **dec_data,OUT UINT_T *dec_len);


OPERATE_RET aes128_ecb_encode(IN const BYTE_T *data,IN const UINT_T len,\
                              OUT BYTE_T **ec_data,OUT UINT_T *ec_len,\
                              IN const BYTE_T *key);
OPERATE_RET aes128_ecb_decode(IN const BYTE_T *data,IN const UINT_T len,\
                              OUT BYTE_T **dec_data,OUT UINT_T *dec_len,\
                              IN const BYTE_T *key);
OPERATE_RET aes128_cbc_encode(IN const BYTE_T *data,IN const UINT_T len,\
                              IN const BYTE_T *key,IN BYTE_T *iv,\
                              OUT BYTE_T **ec_data,OUT UINT_T *ec_len);
OPERATE_RET aes128_cbc_decode(IN const BYTE_T *data,IN const UINT_T len,\
                              IN const BYTE_T *key,IN BYTE_T *iv,\
                              OUT BYTE_T **dec_data,OUT UINT_T *dec_len);
OPERATE_RET aes_free_data(IN BYTE_T *data);
INT_T aes_get_actual_length(IN const BYTE_T *dec_data,IN const UINT_T dec_data_len);


OPERATE_RET aes192_cbc_encode_raw(IN const BYTE_T *data,IN const UINT_T len,\
                                  IN const BYTE_T *key,IN BYTE_T *iv,\
                                  OUT BYTE_T *ec_data);
OPERATE_RET aes192_cbc_decode_raw(IN const BYTE_T *data,IN const UINT_T len,\
                                  IN const BYTE_T *key,IN BYTE_T *iv,\
                                  OUT BYTE_T *dec_data);

OPERATE_RET aes256_cbc_encode_raw(IN const BYTE_T *data,IN const UINT_T len,\
                                  IN const BYTE_T *key,IN BYTE_T *iv,\
                                  OUT BYTE_T *ec_data);


OPERATE_RET aes128_ecb_encode_raw(IN const BYTE_T *data, IN const UINT_T len,\
                                  OUT BYTE_T *ec_data,IN const BYTE_T *key);
OPERATE_RET aes128_ecb_decode_raw(IN const BYTE_T *data, IN const UINT_T len,\
                                  OUT BYTE_T *dec_data,IN const BYTE_T *key);
OPERATE_RET aes128_cbc_encode_raw(IN const BYTE_T *data,IN const UINT_T len,\
                                  IN const BYTE_T *key,IN BYTE_T *iv,\
                                  OUT BYTE_T *ec_data);
OPERATE_RET aes128_cbc_decode_raw(IN const BYTE_T *data,IN const UINT_T len,\
                                  IN const BYTE_T *key,IN BYTE_T *iv,\
                                  OUT BYTE_T *dec_data);


#define aes128_free_data                    aes_free_data
#define aes128_get_data_actual_length       aes_get_actual_length




typedef struct TUYA_HW_AES_HANDLE_ {
    int             init;
    TUYA_HW_AES_S   aesFunc;
    void*           phwHdl;
} TUYA_HW_AES_HANDLE_S;


void aes_method_get_callback_func(TUYA_HW_AES_S* paes);

int tuya_hw_aes_crypt_init(TUYA_HW_AES_HANDLE_S* paesHdl, char* pkey);

int tuya_hw_aes_crypt_uninit(TUYA_HW_AES_HANDLE_S* paesHdl);

int tuya_hw_aes_update_key(TUYA_HW_AES_HANDLE_S* paesHdl, char* pkey);

int tuya_hw_aes_encrypt_cbc(TUYA_HW_AES_HANDLE_S* paesHdl, const unsigned char* iv, unsigned int ivbits,
                            const unsigned char *input, size_t length, unsigned char *output, size_t* poutlen);


#ifdef __cplusplus
}
#endif
#endif

