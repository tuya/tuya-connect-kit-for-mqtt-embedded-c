#include <string.h>
#include "log.h"
#include "tuya_error_code.h"
#include "mqtt_client_interface.h"
#include "transport_interface.h"
#include "system_interface.h"
#include "core_mqtt_config.h"
#include "core_mqtt.h"

typedef struct {
    mqtt_client_config_t config;
    MQTTContext_t mqclient;
    NetworkContext_t network;
    uint8_t mqttbuffer[CORE_MQTT_BUFFER_SIZE];
} mqtt_client_context_t;

static void core_mqtt_library_callback( struct MQTTContext* pContext,
                                        struct MQTTPacketInfo* pPacketInfo,
                                        struct MQTTDeserializedInfo* pDeserializedInfo )
{
    mqtt_client_context_t* context = (mqtt_client_context_t*)pContext->userData;

    uint16_t msgid = pDeserializedInfo->packetIdentifier;

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH ) {
        if (context->config.on_message == NULL) {
            return;
        }

        char* topic = system_malloc(pDeserializedInfo->pPublishInfo->topicNameLength + 1);
        if (topic == NULL) {
            return;
        }
        memcpy(topic, pDeserializedInfo->pPublishInfo->pTopicName, pDeserializedInfo->pPublishInfo->topicNameLength);
        topic[pDeserializedInfo->pPublishInfo->topicNameLength] = '\0';

        context->config.on_message( context,
            msgid,
            &(const mqtt_client_message_t) {
                .topic = topic,
                .payload = pDeserializedInfo->pPublishInfo->pPayload, 
                .length = pDeserializedInfo->pPublishInfo->payloadLength,
                .qos = pDeserializedInfo->pPublishInfo->qos,
            },
            context->config.userdata
        );
        system_free(topic);

    } else {
        switch (  pPacketInfo->type ) {
        case MQTT_PACKET_TYPE_SUBACK:
            log_debug("MQTT_PACKET_TYPE_SUBACK id:%d", msgid);
            if(context->config.on_subscribed) {
                context->config.on_subscribed(context, msgid, context->config.userdata);
            }
            break;

        case MQTT_PACKET_TYPE_UNSUBACK:
            log_debug("MQTT_PACKET_TYPE_UNSUBACK id:%d", msgid);
            if(context->config.on_unsubscribed) {
                context->config.on_unsubscribed(context, msgid, context->config.userdata);
            }
            break;

        case MQTT_PACKET_TYPE_PUBACK:
            log_debug("MQTT_PACKET_TYPE_PUBACK id:%d", msgid);
            if(context->config.on_published) {
                context->config.on_published(context, msgid, context->config.userdata);
            }
            break;

        default:
            log_debug("type:0x%02x, id:%d", pPacketInfo->type, msgid);
        }
    }
}

void* mqtt_client_new(void)
{
    return system_malloc(sizeof(mqtt_client_context_t));
}

void mqtt_client_free(void* client)
{
    system_free(client);
}

mqtt_client_status_t mqtt_client_init(void* client, const mqtt_client_config_t* config)
{
    mqtt_client_context_t* context = (mqtt_client_context_t*)client;
    MQTTStatus_t mqtt_status;

    /* Clean memory */
    memset(context, 0, sizeof(mqtt_client_context_t));

    /* Setting data */
    context->config = *config;

    /* TLS pre init */
	int ret = network_tls_init(&context->network, 
        &(const TLSConnectParams){
            .cacert = context->config.cacert,
            .cacert_len = context->config.cacert_len,
            .client_cert = NULL,
            .client_cert_len = 0,
            .client_key = NULL,
            .client_key_len = 0,
            .host = context->config.host,
            .port = context->config.port,
            .timeout_ms = context->config.timeout_ms,
            .cert_verify = true,
	});
	if (OPRT_OK != ret) {
		log_error("network_tls_init fail:%d", ret);
		return MQTT_STATUS_NETWORK_INIT_FAILED;
	}

    /* Fill in TransportInterface send and receive function pointers.
     * For this demo, TCP sockets are used to send and receive data
     * from network. Network context is SSL context for OpenSSL.*/
    TransportInterface_t transport;
    transport.pNetworkContext = &context->network;
    transport.send = (TransportSend_t)network_tls_write;
    transport.recv = (TransportRecv_t)network_tls_read;

    /* Fill the values for network buffer. */
    MQTTFixedBuffer_t network_buffer;
    network_buffer.size = CORE_MQTT_BUFFER_SIZE;
    network_buffer.pBuffer = context->mqttbuffer;

    /* Initialize MQTT library. */
    mqtt_status = MQTT_Init( &context->mqclient,
                             &transport,
                             system_ticks,
                             core_mqtt_library_callback,
                             &network_buffer,
							 context );

    if( mqtt_status != MQTTSuccess ) {
        log_error( "MQTT init failed: Status = %s.", MQTT_Status_strerror( mqtt_status ) );
        context->network.destroy(&context->network);
		return OPRT_COM_ERROR;
    }
    
    return MQTT_STATUS_SUCCESS;
}

mqtt_client_status_t mqtt_client_deinit(void* client)
{
    mqtt_client_context_t* context = (mqtt_client_context_t*)client;
    context->network.disconnect(&context->network);
    context->network.destroy(&context->network);
    return MQTT_STATUS_SUCCESS;
}

mqtt_client_status_t mqtt_client_connect(void* client)
{
    mqtt_client_context_t* context = (mqtt_client_context_t*)client;
    MQTTStatus_t mqtt_status;

    int ret = context->network.connect(&context->network, NULL);
    if (OPRT_OK != ret) {
        context->network.disconnect(&context->network);
        return MQTT_STATUS_NETWORK_CONNECT_FAILED;
    } 
    log_debug("TLS connected.");

    bool pSessionPresent = false;

    /* Send MQTT CONNECT packet to broker. */
    mqtt_status = MQTT_Connect( &context->mqclient,
        &(const MQTTConnectInfo_t){
            .cleanSession = true,
            .keepAliveSeconds = context->config.keepalive,
            .pClientIdentifier = context->config.clientid,
            .clientIdentifierLength = strlen(context->config.clientid),
            .pUserName = context->config.username,
            .userNameLength = strlen(context->config.username),
            .pPassword = context->config.password,
            .passwordLength = strlen(context->config.password)
        }, 
        NULL, 
        context->config.timeout_ms, 
        &pSessionPresent );
    if (MQTTSuccess != mqtt_status) {
        log_error("mqtt connect err: %s(%d)", MQTT_Status_strerror(mqtt_status), mqtt_status);
        context->network.disconnect(&context->network);
        if (MQTTNotAuthorized == mqtt_status) {
            return MQTT_STATUS_NOT_AUTHORIZED;
        }
        return MQTT_STATUS_CONNECT_FAILED;
    }

    if(context->config.on_connected) {
        context->config.on_connected(context, context->config.userdata);
    }

    return MQTT_STATUS_SUCCESS;
}

mqtt_client_status_t mqtt_client_disconnect(void* client)
{
    mqtt_client_context_t* context = (mqtt_client_context_t*)client;
    MQTTStatus_t mqtt_status;

    mqtt_status = MQTT_Disconnect(&context->mqclient);
    if (MQTTSuccess != mqtt_status) {
        log_error("mqtt disconnect err: %s(%d)", MQTT_Status_strerror(mqtt_status), mqtt_status);
    }

    context->network.disconnect(&context->network);

    if(context->config.on_disconnected) {
        context->config.on_disconnected(context, context->config.userdata);
    }

    return MQTT_STATUS_SUCCESS;
}

uint16_t mqtt_client_subscribe(void* client, const char* topic, uint8_t qos)
{
    mqtt_client_context_t* context = (mqtt_client_context_t*)client;
    MQTTStatus_t mqtt_status;

    uint16_t msgid = MQTT_GetPacketId( &context->mqclient );

    mqtt_status = MQTT_Subscribe( &context->mqclient,
                                  &(const MQTTSubscribeInfo_t){
                                        .qos = qos,
                                        .pTopicFilter = topic,
                                        .topicFilterLength = strlen(topic)
                                  },
                                  1,
                                  msgid );

    if( mqtt_status != MQTTSuccess ) {
        log_error( "Failed to send SUBSCRIBE packet to broker with error = %s.", MQTT_Status_strerror( mqtt_status ) );
        return 0;
    }

    return msgid;
}

uint16_t mqtt_client_unsubscribe(void* client, const char* topic, uint8_t qos)
{
    mqtt_client_context_t* context = (mqtt_client_context_t*)client;
    MQTTStatus_t mqtt_status;

    uint16_t msgid = MQTT_GetPacketId( &context->mqclient );

    mqtt_status = MQTT_Unsubscribe( &context->mqclient,
                                    &(const MQTTSubscribeInfo_t){
                                        .qos = qos,
                                        .pTopicFilter = topic,
                                        .topicFilterLength = strlen(topic)
                                    },
                                    1,
                                    msgid );

    if( mqtt_status != MQTTSuccess ) {
        log_error( "Failed to send SUBSCRIBE packet to broker with error = %s.", MQTT_Status_strerror( mqtt_status ) );
        return 0;
    }

    return msgid;
}

uint16_t mqtt_client_publish(void* client, const char* topic, const uint8_t* payload, size_t length, uint8_t qos)
{
    mqtt_client_context_t* context = (mqtt_client_context_t*)client;
    MQTTStatus_t mqtt_status;

    uint16_t msgid = MQTT_GetPacketId( &context->mqclient );

    mqtt_status = MQTT_Publish( &context->mqclient,
                                &(const MQTTPublishInfo_t){
                                    .qos = qos,
                                    .pTopicName = topic,
                                    .topicNameLength = strlen(topic),
                                    .pPayload = payload,
                                    .payloadLength = length
                                },
                                msgid);

    if (MQTTSuccess != mqtt_status) {
        return 0;
    }
    return msgid;
}

mqtt_client_status_t mqtt_client_yield(void* client)
{
    mqtt_client_context_t* context = (mqtt_client_context_t*)client;
    MQTTStatus_t mqtt_status;

    mqtt_status = MQTT_ProcessLoop( &context->mqclient, context->config.timeout_ms);
    if( mqtt_status != MQTTSuccess ) {
        log_error("MQTT_ProcessLoop returned with status = %s.", MQTT_Status_strerror( mqtt_status ));
        mqtt_client_disconnect(context);
        return MQTT_STATUS_NETWORK_TIMEOUT;
    }
    return MQTT_STATUS_SUCCESS;
}