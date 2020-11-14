#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <string.h>
#include "log.h"
#include "network_interface.h"

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"


/* This is the value used for ssl read timeout */
#define IOT_SSL_READ_TIMEOUT 2000

/* This defines the value of the debug buffer that gets allocated.
 * The value can be altered based on memory constraints
 */
#ifdef ENABLE_IOT_DEBUG
#define MBEDTLS_DEBUG_BUFFER_SIZE 2048
#endif

/**
 * @brief TLS Connection Parameters
 *
 * Defines a type containing TLS specific parameters to be passed down to the
 * TLS networking layer to create a TLS secured socket.
 */
struct tls_context {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	uint32_t flags;
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt clicert;
	mbedtls_pk_context pkey;
	mbedtls_net_context server_fd;
};

/*
 * This is a function to do further verification if needed on the cert received
 */

static int _iot_tls_verify_cert(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
	char buf[1024];
	((void) data);

	log_debug("\nVerify requested for (Depth %d):\n", depth);
	mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
	log_debug("%s", buf);

	if((*flags) == 0) {
		log_debug("  This certificate has no flags\n");
	} else {
		log_debug(buf, sizeof(buf), "  ! ", *flags);
		log_debug("%s\n", buf);
	}

	return 0;
}

static void _iot_tls_set_connect_params(NetworkContext_t *pNetwork, const char *pRootCALocation, const char *pDeviceCertLocation,
								 const char *pDevicePrivateKeyLocation, const char *pDestinationURL,
								 uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag)
{
	pNetwork->tlsConnectParams.DestinationPort = destinationPort;
	pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
	pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
	pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
	pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
	pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
	pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;
}

int iot_tls_init(NetworkContext_t *pNetwork, const char *pRootCALocation, const char *pDeviceCertLocation,
					const char *pDevicePrivateKeyLocation, const char *pDestinationURL,
					uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag)
{
	if (NULL == pNetwork) {
		return OPRT_INVALID_PARM;
	}

	_iot_tls_set_connect_params(pNetwork, pRootCALocation, pDeviceCertLocation, pDevicePrivateKeyLocation,
								pDestinationURL, destinationPort, timeout_ms, ServerVerificationFlag);

	pNetwork->connect = iot_tls_connect;
	pNetwork->read = iot_tls_read;
	pNetwork->write = iot_tls_write;
	pNetwork->disconnect = iot_tls_disconnect;
	pNetwork->destroy = iot_tls_destroy;

	tls_context_t* tls_ctx = mbedtls_calloc(1, sizeof(tls_context_t));
	if(NULL == tls_ctx) {
		log_error("tls_ctx malloc fail");
		return OPRT_MALLOC_FAILED;
	}

	tls_ctx->flags = 0;
	pNetwork->context = tls_ctx;
	return OPRT_OK;
}

int iot_tls_connect(NetworkContext_t *pNetwork, TLSConnectParams *params)
{
	int ret = 0;
	tls_context_t *tlsDataParams = NULL;
	const char *pers = "iot_tls_wrapper";
	char portBuffer[6];

	if(NULL == pNetwork) {
		return OPRT_INVALID_PARM;
	}

	if(NULL != params) {
		_iot_tls_set_connect_params(pNetwork, params->pRootCALocation, params->pDeviceCertLocation,
									params->pDevicePrivateKeyLocation, params->pDestinationURL,
									params->DestinationPort, params->timeout_ms, params->ServerVerificationFlag);
	}

	tlsDataParams = (tls_context_t*)(pNetwork->context);

	mbedtls_net_init(&(tlsDataParams->server_fd));
	mbedtls_ssl_init(&(tlsDataParams->ssl));
	mbedtls_ssl_config_init(&(tlsDataParams->conf));
	mbedtls_ctr_drbg_init(&(tlsDataParams->ctr_drbg));
	mbedtls_x509_crt_init(&(tlsDataParams->cacert));
	mbedtls_x509_crt_init(&(tlsDataParams->clicert));
	mbedtls_pk_init(&(tlsDataParams->pkey));

	log_debug("\n  . Seeding the random number generator...");
	mbedtls_entropy_init(&(tlsDataParams->entropy));
	if((ret = mbedtls_ctr_drbg_seed(&(tlsDataParams->ctr_drbg), mbedtls_entropy_func, &(tlsDataParams->entropy),
									(const unsigned char *) pers, strlen(pers))) != 0) {
		log_error(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
		return OPRT_MID_TLS_CTR_DRBG_ENTROPY_SOURCE_ERROR;
	}

	log_debug("  . Loading the CA root certificate ...");
	ret = mbedtls_x509_crt_parse(&(tlsDataParams->cacert), pNetwork->tlsConnectParams.pRootCALocation, 
		strlen(pNetwork->tlsConnectParams.pRootCALocation) + 1);
	if(ret < 0) {
		log_error(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing root cert\n\n", -ret);
		return OPRT_MID_TLS_X509_ROOT_CRT_PARSE_ERROR;
	}
	log_debug(" ok (%d skipped)\n", ret);

	if (pNetwork->tlsConnectParams.pDeviceCertLocation) {
		log_debug("  . Loading the client cert. and key...");
		ret = mbedtls_x509_crt_parse(&(tlsDataParams->clicert), pNetwork->tlsConnectParams.pDeviceCertLocation,
										strlen(pNetwork->tlsConnectParams.pDeviceCertLocation) + 1);
		if(ret != 0) {
			log_error(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing device cert\n\n", -ret);
			return OPRT_MID_TLS_X509_DEVICE_CRT_PARSE_ERROR;
		}
	}

	if (pNetwork->tlsConnectParams.pDevicePrivateKeyLocation) {
		ret = mbedtls_pk_parse_key(&(tlsDataParams->pkey), pNetwork->tlsConnectParams.pDevicePrivateKeyLocation, 
									strlen(pNetwork->tlsConnectParams.pDevicePrivateKeyLocation) + 1, NULL, 0);
		if(ret != 0) {
			log_error(" failed\n  !  mbedtls_pk_parse_key returned -0x%x while parsing private key\n\n", -ret);
			log_debug(" path : %s ", pNetwork->tlsConnectParams.pDevicePrivateKeyLocation);
			return OPRT_MID_TLS_PK_PRIVATE_KEY_PARSE_ERROR;
		}
		log_debug(" ok\n");
	}

	snprintf(portBuffer, 6, "%d", pNetwork->tlsConnectParams.DestinationPort);
	log_debug("  . Connecting to %s/%s...", pNetwork->tlsConnectParams.pDestinationURL, portBuffer);
	if((ret = mbedtls_net_connect(&(tlsDataParams->server_fd), pNetwork->tlsConnectParams.pDestinationURL,
								  portBuffer, MBEDTLS_NET_PROTO_TCP)) != 0) {
		log_error(" failed\n  ! mbedtls_net_connect returned -0x%x\n\n", -ret);
		switch(ret) {
			case MBEDTLS_ERR_NET_SOCKET_FAILED:
				return OPRT_MID_TLS_NET_SOCKET_ERROR;
			case MBEDTLS_ERR_NET_UNKNOWN_HOST:
				return OPRT_MID_TLS_UNKNOWN_HOST_ERROR;
			case MBEDTLS_ERR_NET_CONNECT_FAILED:
			default:
				return OPRT_MID_TLS_NET_CONNECT_ERROR;
		};
	}

	ret = mbedtls_net_set_block(&(tlsDataParams->server_fd));
	if(ret != 0) {
		log_error(" failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret);
		return OPRT_MID_TLS_CONNECTION_ERROR;
	} log_debug(" ok\n");

	mbedtls_ssl_set_bio(&(tlsDataParams->ssl), &(tlsDataParams->server_fd), mbedtls_net_send, NULL, mbedtls_net_recv_timeout);
	mbedtls_ssl_conf_read_timeout(&(tlsDataParams->conf), pNetwork->tlsConnectParams.timeout_ms);

	log_debug("  . Setting up the SSL/TLS structure...");
	if((ret = mbedtls_ssl_config_defaults(&(tlsDataParams->conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
										  MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		log_error(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret);
		return OPRT_MID_TLS_CONNECTION_ERROR;
	}

	mbedtls_ssl_conf_verify(&(tlsDataParams->conf), _iot_tls_verify_cert, NULL);
	if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) {
		mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_REQUIRED);
	} else {
		mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_OPTIONAL);
	}
	mbedtls_ssl_conf_rng(&(tlsDataParams->conf), mbedtls_ctr_drbg_random, &(tlsDataParams->ctr_drbg));

	mbedtls_ssl_conf_ca_chain(&(tlsDataParams->conf), &(tlsDataParams->cacert), NULL);

	if ((pNetwork->tlsConnectParams.pDeviceCertLocation) && (pNetwork->tlsConnectParams.pDevicePrivateKeyLocation)) {
		if((ret = mbedtls_ssl_conf_own_cert(&(tlsDataParams->conf), &(tlsDataParams->clicert), &(tlsDataParams->pkey))) !=
		0) {
			log_error(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
			return OPRT_MID_TLS_CONNECTION_ERROR;
		}
	}

	/* Assign the resulting configuration to the SSL context. */
	if((ret = mbedtls_ssl_setup(&(tlsDataParams->ssl), &(tlsDataParams->conf))) != 0) {
		log_error(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
		return OPRT_MID_TLS_CONNECTION_ERROR;
	}
	if((ret = mbedtls_ssl_set_hostname(&(tlsDataParams->ssl), pNetwork->tlsConnectParams.pDestinationURL)) != 0) {
		log_error(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		return OPRT_MID_TLS_CONNECTION_ERROR;
	}

	log_debug("\n\nSSL state connect : %d ", tlsDataParams->ssl.state);
	log_debug("  . Performing the SSL/TLS handshake...");
	while((ret = mbedtls_ssl_handshake(&(tlsDataParams->ssl))) != 0) {
		if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			log_error(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
			if(ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
				log_error("    Unable to verify the server's certificate. "
							  "Either it is invalid,\n"
							  "    or you didn't set ca_file or ca_path "
							  "to an appropriate value.\n"
							  "    Alternatively, you may want to use "
							  "auth_mode=optional for testing purposes.\n");
			}
			return OPRT_MID_TLS_CONNECTION_ERROR;
		}
	}

	log_debug(" ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n", mbedtls_ssl_get_version(&(tlsDataParams->ssl)),
		  mbedtls_ssl_get_ciphersuite(&(tlsDataParams->ssl)));
	if((ret = mbedtls_ssl_get_record_expansion(&(tlsDataParams->ssl))) >= 0) {
		log_debug("    [ Record expansion is %d ]\n", ret);
	} else {
		log_debug("    [ Record expansion is unknown (compression) ]\n");
	}

	log_debug("  . Verifying peer X.509 certificate...");

	if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) {
		if((tlsDataParams->flags = mbedtls_ssl_get_verify_result(&(tlsDataParams->ssl))) != 0) {
			char vrfy_buf[512];
			log_error(" failed\n");
			mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", tlsDataParams->flags);
			log_error("%s\n", vrfy_buf);
			ret = OPRT_MID_TLS_CONNECTION_ERROR;
		} else {
			log_debug(" ok\n");
			ret = OPRT_OK;
		}
	} else {
		log_debug(" Server Verification skipped\n");
		ret = OPRT_OK;
	}

#ifdef ENABLE_IOT_DEBUG
	unsigned char buf[MBEDTLS_DEBUG_BUFFER_SIZE];
	if (mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)) != NULL) {
		log_debug("  . Peer certificate information    ...\n");
		mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)));
		log_debug("%s\n", buf);
	}
#endif

	return ret;
}

int iot_tls_disconnect(NetworkContext_t *pNetwork) {
	int ret = 0;
	tls_context_t *tlsDataParams = (tls_context_t*)(pNetwork->context);

	do {
		ret = mbedtls_ssl_close_notify(&tlsDataParams->ssl);
	} while(ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	/* All other negative return values indicate connection needs to be reset.
	 * No further action required since this is disconnect call */

	mbedtls_net_free(&(tlsDataParams->server_fd));

	mbedtls_x509_crt_free(&(tlsDataParams->cacert));
	mbedtls_x509_crt_free(&(tlsDataParams->clicert));
	mbedtls_pk_free(&(tlsDataParams->pkey));
	mbedtls_ssl_free(&(tlsDataParams->ssl));
	mbedtls_ssl_config_free(&(tlsDataParams->conf));
	mbedtls_ctr_drbg_free(&(tlsDataParams->ctr_drbg));
	mbedtls_entropy_free(&(tlsDataParams->entropy));

	return OPRT_OK;
}

int iot_tls_destroy(NetworkContext_t *pNetwork)
{
	tls_context_t *tlsDataParams = (pNetwork->context);

	mbedtls_free(tlsDataParams);
	pNetwork->context = NULL;

	return OPRT_OK;
}

static int mbedtls_status_is_ssl_in_progress( int ret )
{
    return( ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
			ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS ||
			ret == MBEDTLS_ERR_SSL_TIMEOUT ||
            ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS );
}

int iot_tls_write(NetworkContext_t *pNetwork, const unsigned char *pMsg, size_t len)
{
	tls_context_t *tlsDataParams = (tls_context_t*)(pNetwork->context);
	int rv = mbedtls_ssl_write(&(tlsDataParams->ssl), pMsg, len);
    if (rv <= 0) {
        if (mbedtls_status_is_ssl_in_progress(rv)) {
            return 0;
        }
        return OPRT_MID_TLS_NET_SOCKET_ERROR;
    }
    return rv;
}

int iot_tls_read(NetworkContext_t *pNetwork, unsigned char *pMsg, size_t len)
{
	tls_context_t *tlsDataParams = (tls_context_t*)(pNetwork->context);
	int rv = mbedtls_ssl_read(&(tlsDataParams->ssl), pMsg, len);
    if (rv <= 0) {
        if (mbedtls_status_is_ssl_in_progress(rv)) {
            return 0;
        }
        return OPRT_MID_TLS_NET_SOCKET_ERROR;
    }
    return rv;
}

#ifdef __cplusplus
}
#endif
