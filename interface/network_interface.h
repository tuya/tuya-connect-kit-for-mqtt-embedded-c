/**
 * @file network_interface.h
 * @brief NetworkContext_t interface definition for HTTP and MQTT client.
 *
 * Defines an interface to the TLS layer to be used by the HTTP and MQTT client.
 * Starting point for porting the SDK to the networking layer of a new platform.
 */

#ifndef __NETWORK_INTERFACE_H_
#define __NETWORK_INTERFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @brief NetworkContext_t Type
 *
 * Defines a type for the network struct.  See structure definition below.
 */
typedef struct NetworkContext NetworkContext_t;

/**
 * @brief tls_context_t Type
 *
 * Defines a type for the tls context struct.
 */
typedef struct tls_context tls_context_t;

/**
 * @brief TLS Connection Parameters
 *
 * Defines a type containing TLS specific parameters to be passed down to the
 * TLS networking layer to create a TLS secured socket.
 */
typedef struct {
	const char*     host;             /*!< Domain or IP as string */
	uint16_t        port;             /*!< Port to connect, default depend on esp_http_client_transport_t (80 or 443) */
	const uint8_t*  cacert;           /*!< SSL server certification, if the client requires to verify server */
	size_t          cacert_len;       /*!< Length of the buffer pointed to by cert_pem. May be 0 for null-terminated pem */
	const uint8_t*  client_cert;      /*!< SSL client certification, if the server requires to verify client */
	size_t          client_cert_len;  /*!< Length of the buffer pointed to by client_cert_pem. May be 0 for null-terminated pem */
	const uint8_t*  client_key;       /*!< SSL client key, if the server requires to verify client */
	size_t          client_key_len;   /*!< Length of the buffer pointed to by client_key_pem. May be 0 for null-terminated pem */
	uint32_t        timeout_ms;       /*!< Unsigned integer defining the TLS handshake timeout value in milliseconds */
	bool            cert_verify;      /*!< Boolean.  True = perform server certificate hostname validation.  False = skip validation \b NOT recommended */
} TLSConnectParams;

/**
 * @brief NetworkContext_t Structure
 *
 * Structure for defining a network connection.
 */
struct NetworkContext {
	int (*connect)(NetworkContext_t *, const TLSConnectParams *);
	int (*read)(NetworkContext_t *, unsigned char *, size_t);   ///< Function pointer pointing to the network function to read from the network
	int (*write)(NetworkContext_t *, const unsigned char *, size_t);    ///< Function pointer pointing to the network function to write to the network
	int (*disconnect)(NetworkContext_t *);    ///< Function pointer pointing to the network function to disconnect from the network
	int (*destroy)(NetworkContext_t *);        ///< Function pointer pointing to the network function to destroy the network object
	TLSConnectParams tlsConnectParams;        ///< TLSConnect params structure containing the common connection parameters
	tls_context_t* context;
};

/**
 * @brief Initialize the TLS implementation
 *
 * Perform any initialization required by the TLS layer.
 * Connects the interface to implementation by setting up
 * the network layer function pointers to platform implementations.
 *
 * @param pNetwork - Pointer to a NetworkContext_t struct defining the network interface.
 * @param TLSParams - TLSConnectParams defines the properties of the TLS connection.
 *
 * @return int - successful initialization or TLS error
 */
int network_tls_init(NetworkContext_t *pNetwork, const TLSConnectParams *TLSParams);

/**
 * @brief Create a TLS socket and open the connection
 *
 * Creates an open socket connection including TLS handshake.
 *
 * @param pNetwork - Pointer to a NetworkContext_t struct defining the network interface.
 * @param TLSParams - TLSConnectParams defines the properties of the TLS connection, 
 * 					  Optional parameter. If set to NULL, use the initialization parameter to connect.
 * @return int - successful connection or TLS error
 */
int network_tls_connect(NetworkContext_t *pNetwork, const TLSConnectParams *TLSParams);

/**
 * @brief Disconnect from network socket
 *
 * @param NetworkContext_t - Pointer to a NetworkContext_t struct defining the network interface.
 * @return int - successful read or TLS error code
 */
int network_tls_disconnect(NetworkContext_t *pNetwork);

/**
 * @brief Perform any tear-down or cleanup of TLS layer
 *
 * Called to cleanup any resources required for the TLS layer.
 *
 * @param NetworkContext_t - Pointer to a NetworkContext_t struct defining the network interface
 * @return int - successful cleanup or TLS error code
 */
int network_tls_destroy(NetworkContext_t *pNetwork);

/**
 * @brief Write bytes to the network socket
 *
 * @param NetworkContext_t - Pointer to a NetworkContext_t struct defining the network interface.
 * @param unsigned char pointer - buffer to write to socket
 * @param integer - number of bytes to write
 * @return integer - number of bytes written or TLS error
 * @return int - successful write length or TLS error code
 */
int network_tls_write(NetworkContext_t *pNetwork, const unsigned char *pMsg, size_t len);

/**
 * @brief Read bytes from the network socket
 *
 * @param NetworkContext_t - Pointer to a NetworkContext_t struct defining the network interface.
 * @param unsigned char pointer - pointer to buffer where read bytes should be copied
 * @param size_t - number of bytes to read
 * @param size_t - pointer to store number of bytes read
 * @return int - successful read length or TLS error code
 */
int network_tls_read(NetworkContext_t *pNetwork, unsigned char *pMsg, size_t len);


#ifdef __cplusplus
}
#endif

#endif //__NETWORK_INTERFACE_H_
