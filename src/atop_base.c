#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "tuya_log.h"
#include "tuya_config_defaults.h"

#include "system_interface.h"
#include "network_interface.h"
#include "transport_interface.h"
#include "core_http_client.h"
#include "core_json.h"
#include "cJSON.h"
#include "aes_inf.h"
#include "uni_md5.h"
#include "base64.h"
#include "atop_base.h"

#define MD5SUM_LENGTH (16)
#define POST_DATA_PREFIX (5) // 'data='
#define MAX_URL_LENGTH (255)
#define HEADER_BUFFER_LENGTH (512)
#define DEFAULT_RESPONSE_BUFFER_LEN (1024)
#define AES_BLOCK_SIZE (16)

#define ATOP_COMMON_HEADER "application/x-www-form-urlencoded;charset=UTF-8"

typedef struct {
    char* key;
    char* value;
} url_param_t;

static int atop_url_params_sign(const char* key,
                                url_param_t* params, int param_num,
                                uint8_t* out, size_t* olen)
{
    int rt = OPRT_OK;
    int printlen = 0;
    int i = 0;
    uint8_t digest[MD5SUM_LENGTH];

    char* buffer = system_malloc(512);
    TUYA_CHECK_NULL_RETURN(buffer, OPRT_MALLOC_FAILED);

    for (i = 0; i < param_num; ++i) {
        printlen += sprintf(buffer + printlen, "%s=%s||", params[i].key, params[i].value);
    }
    printlen += sprintf(buffer + printlen, "%s", (char*)key);

    // make md5 digest bin
    uni_md5_digest_tolal((const uint8_t*)buffer, printlen, digest);
    system_free(buffer);

    // make digest hex
    for (i = 0; i < MD5SUM_LENGTH; i++) {
        *olen += sprintf((char*)out + i*2, "%02x", digest[i]);
    }
    return rt;
}

static int atop_url_params_encode(  const char* key, 
                                    url_param_t* params, int param_num,
                                    char* out, size_t* olen)
{
    int rt = OPRT_OK;
    char* buffer = out;
    int printlen = 0;
    size_t sign_len = 0;
    int i;

    // attach url params 
    for (i = 0; i < param_num; i++) {
        printlen += sprintf(buffer + printlen, "%s=%s&", params[i].key, params[i].value);
    }

    // attach md5 signature
    printlen += sprintf(buffer + printlen, "sign=");
    rt = atop_url_params_sign(key, params, param_num, (uint8_t*)buffer + printlen, &sign_len);
    if (rt != 0) {
        TY_LOGE("atop_url_params_sign error:%d", rt);
        return rt;
    }
    printlen += sign_len;
    *olen = printlen;
    return rt;
}

static int atop_request_data_encode(const char* key,
                                    const uint8_t* input, int ilen,
                                    uint8_t* output, size_t* olen)
{
    if (key == NULL || input == NULL || ilen == 0 || output == NULL || olen == NULL) {
        return OPRT_INVALID_PARM;        
    }

    int rt = OPRT_OK;
    int printlen = 0;
    int i;

    /* AES data PKCS7 padding */
    uint8_t padding_value = AES_BLOCK_SIZE - ilen % AES_BLOCK_SIZE;
    size_t input_buffer_len = ilen + padding_value;
    uint8_t* input_buffer = system_malloc(input_buffer_len);
    memcpy(input_buffer, input, ilen);
    for(i = 0; i < padding_value; i++) {
        input_buffer[ilen + i] = padding_value;
    }

    /* AES128-ECB encode */
    uint8_t* encrypted_buffer = system_malloc(input_buffer_len);
    size_t encrypted_len = input_buffer_len;

    OPERATE_RET ret = aes128_ecb_encode_raw(input_buffer, input_buffer_len, encrypted_buffer, (const uint8_t*)key);
    system_free(input_buffer);
    if(ret != OPRT_OK) {
        system_free(encrypted_buffer);
        return ret;
    }

    // output the hex data
    printlen = sprintf((char*)output, "%s", "data=");
    for (i = 0; i < (int)encrypted_len; i++) {
        printlen += sprintf((char*)output + printlen, "%02X", (uint8_t)(encrypted_buffer[i]));
    }

    system_free(encrypted_buffer);
    *olen = printlen;
    return 0;
}

static int atop_response_result_decrpyt( const char* key,
                                            const uint8_t* input, int ilen,
                                            uint8_t* output, size_t* olen)
{
    if (key == NULL || input == NULL || ilen == 0 || output == NULL || olen == NULL) {
        return OPRT_INVALID_PARM;        
    }

    int rt = OPRT_OK;

    // AES decrypt
    rt = aes128_ecb_decode_raw(input, ilen, output, (const uint8_t*)key);
    if (rt != OPRT_OK) {
        TY_LOGE("aes128_ecb_decode error:%d", rt);
        return rt;
    }

    /* PKCS7 unpadding */
    *olen = ilen - output[ilen - 1];
    output[*olen] = 0;
    
    return rt;    
}

static int atop_response_data_decode(const char* key, 
                                    const uint8_t* input, size_t ilen,
                                    uint8_t* output, size_t* olen)
{
    int rt = OPRT_OK;

    // Variables used in this example.
    JSONStatus_t result;
    const char query_key[] = "result";
    char * value;
    size_t value_length;

    // Calling JSON_Validate() is not necessary if the document is guaranteed to be valid.
    result = JSON_Validate( (const char*)input, ilen );
    if( result != JSONSuccess ) {
        TY_LOGE("JSON_Validate error");
        return OPRT_CR_CJSON_ERR;
    }

    result = JSON_Search( (char*)input, ilen, query_key, sizeof(query_key) - 1, &value, &value_length );
    if( result != JSONSuccess ) {
        TY_LOGE("JSON_Search result not found");
        return OPRT_CR_CJSON_ERR;
    }
    TY_LOGV("base64 encode result:\r\n%.*s", value_length, value);

    // base64 decode buffer
    size_t b64buffer_len = value_length * 3 / 4;
    uint8_t* b64buffer = system_malloc(b64buffer_len);
    size_t b64buffer_olen = 0;

    // base64 decode
    rt = mbedtls_base64_decode(b64buffer, b64buffer_len, &b64buffer_olen, (const uint8_t*)value, value_length);
    if (rt != OPRT_OK) {
        TY_LOGE("base64 decode error:%d", rt);
        system_free(b64buffer);
        return rt;
    }

    rt = atop_response_result_decrpyt(key, (const uint8_t*)b64buffer, b64buffer_olen, output, olen);
    system_free(b64buffer);
    if (rt != OPRT_OK) {
        TY_LOGE("atop_data_decrpyt error: %d", rt);
        return rt;
    }
    TY_LOGV("result:\r\n%.*s", *olen, output);

    return rt;
}

static int atop_response_result_parse_cjson(const uint8_t* input, size_t ilen, 
                                            atop_base_response_t* response)
{
    int rt = OPRT_OK;

    if (NULL == input || NULL == response) {
        TY_LOGE("param error");
        return OPRT_INVALID_PARM;
    }

    if (input[ilen] != '\0') {
        TY_LOGE("string length error ilen:%d, stlen:%d", ilen, strlen((char*)input));
    }

    // json parse
    cJSON* root = cJSON_Parse((const char*)input);
    if (NULL == root) {
        TY_LOGE("Json parse error");
        return OPRT_CJSON_PARSE_ERR;
    }

    // verify success key
    if (!cJSON_HasObjectItem(root, "success")) {
        TY_LOGE("not found json success key");
        cJSON_Delete(root);
        return OPRT_CJSON_GET_ERR;
    }

    // sync timestamp
    if (cJSON_HasObjectItem(root, "t")) {
        response->t = cJSON_GetObjectItem(root, "t")->valueint;
    }
    
    // if 'success == True', copy the json object to result point
    if (cJSON_GetObjectItem(root, "success")->type == cJSON_True) {
        response->success = true;
        response->result = cJSON_DetachItemFromObject(root, "result");
        cJSON_Delete(root);
        return OPRT_OK;
    } 
    
    // Exception parse
    char* errorCode = NULL;
    response->success = false;
    response->result = NULL;

    // error msg dump
    if (cJSON_GetObjectItem(root, "errorMsg")) {
        TY_LOGE("errorMsg:%s", cJSON_GetObjectItem(root, "errorMsg")->valuestring);
    }

    if (cJSON_GetObjectItem(root, "errorCode") == NULL) {
        cJSON_Delete(root);
        return OPRT_COM_ERROR;
    }

    errorCode = cJSON_GetObjectItem(root, "errorCode")->valuestring;

    if(strcasecmp(errorCode, "GATEWAY_NOT_EXISTS") == 0) {
        rt = OPRT_LINK_CORE_HTTP_GW_NOT_EXIST;
    }

    // free cJSON object
    cJSON_Delete(root);
    return rt;
}

int32_t http_request_send( const TransportInterface_t * pTransportInterface,
                                  const HTTPRequestInfo_t * requestInfo,
                                  const uint8_t * pRequestBodyBuf,
                                  size_t reqBodyBufLen,
                                  HTTPResponse_t * response)
{
    /* Represents header data that will be sent in an HTTP request. */
    HTTPRequestHeaders_t requestHeaders;

    /* Return value of all methods from the HTTP Client library API. */
    HTTPStatus_t httpStatus = HTTPSuccess;

    assert( requestInfo != NULL );
    assert( response != NULL );

    /* Initialize all HTTP Client library API structs to 0. */
    ( void ) memset( &requestHeaders, 0, sizeof( requestHeaders ) );

    /* Set the buffer used for storing request headers. */
    requestHeaders.bufferLen = HEADER_BUFFER_LENGTH;
    requestHeaders.pBuffer = system_malloc(requestHeaders.bufferLen);
    if (requestHeaders.pBuffer == NULL) {
        return OPRT_LINK_CORE_HTTP_RESPONSE_BUFFER_EMPTY;
    }

    httpStatus = HTTPClient_InitializeRequestHeaders( &requestHeaders,
                                                      requestInfo );

    httpStatus |= HTTPClient_AddHeader( &requestHeaders,
                                        "Content-Type",
                                        sizeof("Content-Type") - 1U,
                                        ATOP_COMMON_HEADER,
                                        sizeof(ATOP_COMMON_HEADER) - 1U);

    if( httpStatus != HTTPSuccess ) {
        TY_LOGE("HTTP header error:%d", httpStatus);
        system_free(requestHeaders.pBuffer);
        return OPRT_LINK_CORE_HTTP_CLIENT_HEADER_ERROR;
    }

    /* Initialize the response object. The same buffer used for storing
        * request headers is reused here. */
    if (NULL == response->pBuffer || response->bufferLen <= 0) {
        system_free(requestHeaders.pBuffer);
        return OPRT_MALLOC_FAILED;
    }

    TY_LOGI( "Sending HTTP %.*s request to %.*s%.*s",
                ( int32_t ) requestInfo->methodLen, requestInfo->pMethod,
                ( int32_t ) requestInfo->hostLen, requestInfo->pHost,
                ( int32_t ) requestInfo->pathLen, requestInfo->pPath ) ;

    /* Send the request and receive the response. */
    httpStatus = HTTPClient_Send( pTransportInterface,
                                    &requestHeaders,
                                    ( uint8_t * ) pRequestBodyBuf,
                                    reqBodyBufLen,
                                    response,
                                    0 );

    /* Release headers buffer */
    system_free(requestHeaders.pBuffer);

    if( httpStatus != HTTPSuccess ) {
        TY_LOGE( "Failed to send HTTP %.*s request to %.*s%.*s: Error=%s.",
                    ( int32_t ) requestInfo->methodLen, requestInfo->pMethod,
                    ( int32_t ) requestInfo->hostLen, requestInfo->pHost,
                    ( int32_t ) requestInfo->pathLen, requestInfo->pPath,
                    HTTPClient_strerror( httpStatus ));
        return OPRT_LINK_CORE_HTTP_CLIENT_SEND_ERROR;
    }

    TY_LOGV("Response Headers:\n%.*s\n"
            "Response Status:\n%u\n"
            "Response Body:\n%.*s\n",
            ( int32_t ) response->headersLen, response->pHeaders,
            response->statusCode,
            ( int32_t ) response->bodyLen, response->pBody );

    return OPRT_OK;
}

int atop_base_request(const atop_base_request_t* request, atop_base_response_t* response)
{
    // TODO 参数校验
    if (NULL == request || NULL == response) {
        return OPRT_INVALID_PARM;
    }

    int rt = OPRT_OK;

    /* user data */
    response->user_data = (void*)request->user_data;

    /* params fill */
    url_param_t params[6];
    int idx = 0;
    params[idx].key = "a";
    params[idx++].value = (char*)request->api;

    if (request->devid) {
        params[idx].key = "devId";
        params[idx++].value = (char*)request->devid;
    }

    params[idx].key = "et";
    params[idx++].value = "1";
    
    char ts_str[11];
    sprintf(ts_str, "%d", request->timestamp);
    params[idx].key = "t";
    params[idx++].value = ts_str;

    if (request->uuid) {
        params[idx].key = "uuid";
        params[idx++].value = (char*)request->uuid;
    }
    
    if(request->version){
        params[idx].key = "v";
        params[idx++].value = (char*)request->version;
    }

    /* url param buffer make */
    char* path_buffer = system_malloc(MAX_URL_LENGTH);
    if (NULL == path_buffer) {
        TY_LOGE("path_buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    /* attach path prefix */
    int path_buffer_len = sprintf(path_buffer, "%s?", (char*)request->path);
    TY_LOGV("TUYA_HTTPS_ATOP_URL: %s", path_buffer);

    /* param encode */
    size_t encode_len = 0;
    rt = atop_url_params_encode((char*)request->key, params, idx, path_buffer + path_buffer_len, &encode_len);
    if (rt != OPRT_OK) {
        TY_LOGE("url param encode error:%d", rt);
        system_free(path_buffer);
        return rt;
    }
    path_buffer_len += encode_len;
    TY_LOGD("request url len:%d: %s", path_buffer_len, path_buffer);

    /* POST data buffer */
    size_t body_length = 0;
    uint8_t* body_buffer = system_malloc(POST_DATA_PREFIX + (request->datalen + AES_BLOCK_SIZE) * 2 + 1);
    if (NULL == body_buffer) {
        TY_LOGE("body_buffer malloc fail");
        system_free(path_buffer);
        return OPRT_MALLOC_FAILED;
    }

    /* POST data encode */
    TY_LOGD("atop_request_data_encode");
    rt = atop_request_data_encode((char*)request->key, request->data, request->datalen, body_buffer, &body_length);
    if (rt != OPRT_OK) {
        TY_LOGE("atop_post_data_encrypt error:%d", rt);
        system_free(path_buffer);
        system_free(body_buffer);
        return rt;
    }
    TY_LOGV("out post data len:%d, data:%s", body_length, body_buffer);

    /* TLS pre init */
    NetworkContext_t network;
    extern const char tuya_rootCA_pem[];
    
    rt = network_tls_init(&network, &(const TLSConnectParams){
            .pRootCALocation = tuya_rootCA_pem,
            .pDestinationURL = request->host,
            .DestinationPort = request->port,
            .TimeoutMs = DEFAULT_HTTP_TIMEOUT,
            .ServerVerificationFlag = true
    });

    if (OPRT_OK != rt) {
        TY_LOGE("network_tls_init fail:%d", rt);
        system_free(path_buffer);
        system_free(body_buffer);
        return rt;
    }

    /* Start TLS connect */
    rt = network_tls_connect(&network, NULL);
    if (OPRT_OK != rt) {
        TY_LOGE("network_tls_connect fail:%d", rt);
        network_tls_disconnect(&network);
        network_tls_destroy(&network);
        system_free(path_buffer);
        system_free(body_buffer);
        return rt;
    }
    TY_LOGD("tls connencted!");

    /* http client TransportInterface */
    TransportInterface_t pTransportInterface = {
        .pNetworkContext = (NetworkContext_t*)&network,
        .recv = (TransportRecv_t)network_tls_read,
        .send = (TransportSend_t)network_tls_write
    };

    /* http client request object make */
    HTTPRequestInfo_t requestInfo = {
        .pMethod = HTTP_METHOD_POST,
        .methodLen = sizeof(HTTP_METHOD_POST) - 1,
        .pHost = request->host,
        .hostLen = strlen(request->host),
        .pPath = path_buffer,
        .pathLen = path_buffer_len,
        .reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG
    };

    uint8_t* response_buffer = NULL;
    size_t response_buffer_length = DEFAULT_RESPONSE_BUFFER_LEN;

    /* if custom set the response length, set buffer custom length */
    if (request->buflen_custom > 0) {
        response_buffer_length = request->buflen_custom;
    }

    /* response buffer make */
    response_buffer = system_malloc(response_buffer_length);
    if (NULL == response_buffer) {
        TY_LOGE("response_buffer malloc fail");
        system_free(path_buffer);
        system_free(body_buffer);
        return OPRT_MALLOC_FAILED;
    }
    HTTPResponse_t http_response = {
        .pBuffer = response_buffer,
        .bufferLen = response_buffer_length
    };

    /* HTTP request send */
    TY_LOGD("http request send!");
    rt = http_request_send( (const TransportInterface_t*)&pTransportInterface,
                            (const HTTPRequestInfo_t*)&requestInfo,
                            (const uint8_t*)body_buffer,
                            body_length,
                            &http_response);

    if (OPRT_OK != network_tls_disconnect(&network)) {
        TY_LOGW("network_tls_disconnect fail:%d", rt);
    }

    if (OPRT_OK != network_tls_destroy(&network)) {
        TY_LOGW("network_tls_destroy fail:%d", rt);
    }

    /* Release http buffer */
    system_free(path_buffer);
    system_free(body_buffer);
    system_free(response_buffer);

    if (OPRT_OK != rt) {
        TY_LOGE("http_request_send error:%d", rt);
        return rt;
    }

    size_t result_buffer_length = 0;
    uint8_t* result_buffer = system_calloc(1, http_response.bodyLen);
    if (NULL == result_buffer) {
        TY_LOGE("result_buffer malloc fail");
        return OPRT_MALLOC_FAILED;
    }

    /* Decoded response data */
    rt = atop_response_data_decode( request->key, 
                                    http_response.pBody, http_response.bodyLen,
                                    result_buffer, &result_buffer_length);

    if (OPRT_OK == rt) {
        rt = atop_response_result_parse_cjson(result_buffer, result_buffer_length, response);
        system_free(result_buffer);
        return rt;
    }

    TY_LOGW("atop_response_decode error:%d, try parse the plaintext data.", rt);
    return atop_response_result_parse_cjson(http_response.pBody, http_response.bodyLen, response);
}

void atop_base_response_free(atop_base_response_t* response)
{
    if (response->success == true && response->result) {
        cJSON_Delete(response->result);
    }
}
