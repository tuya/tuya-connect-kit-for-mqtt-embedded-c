#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "cJSON.h"
#include "tuya_cacert.h"
#include "tuya_log.h"
#include "tuya_error_code.h"
#include "system_interface.h"
#include "mqtt_client_interface.h"
#include "tuyalink_core.h"

const char productId[] = "3jbcpefnn1jxxxxx";
const char deviceId[] = "6ced2aa564727c01xxxxx";
const char deviceSecret[] = "ac5d367db39xxxxx";

tuya_mqtt_context_t client_instance;

void on_connected(tuya_mqtt_context_t* context, void* user_data)
{
    TY_LOGI("on connected");

    /* data model test code */
    tuyalink_thing_data_model_get(context, NULL);
    tuyalink_thing_desired_get(context, NULL, "[\"power\"]");
    tuyalink_thing_property_report(context, NULL, "{\"power\":{\"value\":1234,\"time\":1631708204231}}");
    tuyalink_thing_property_report_with_ack(context, NULL, "{\"power\":{\"value\":1234,\"time\":1631708204231}}");
    tuyalink_thing_event_trigger(context, NULL, "{\"eventCode\":\"boom\",\"eventTime\":1626197189630,\"outputParams\":{\"param1\":100}}");
    tuyalink_thing_batch_report(context, "{\"msgId\":\"45lkj3551234001\",\"time\":1626197189638,\"sys\":{\"ack\":1},\"data\":{\"properties\":{\"power\":{\"value\":11,\"time\":1626197189638}},\"events\":{\"boom\":{\"outputParams\":{\"param1\":\"10\"},\"eventTime\":1626197189001}}}}");
}

void on_disconnect(tuya_mqtt_context_t* context, void* user_data)
{
    TY_LOGI("on disconnect");
}

void on_messages(tuya_mqtt_context_t* context, void* user_data, const tuyalink_message_t* msg)
{
    TY_LOGI("on message id:%s, type:%d, code:%d", msg->msgid, msg->type, msg->code);
    switch (msg->type) {
        case THING_TYPE_MODEL_RSP:
            TY_LOGI("Model data:%s", msg->data_string);
            break;

        case THING_TYPE_PROPERTY_SET:
            TY_LOGI("property set:%s", msg->data_string);
            break;

        case THING_TYPE_PROPERTY_REPORT_RSP:
            break;

        default:
            break;
    }
    printf("\r\n");
}

int main(int argc, char** argv)
{
    int ret = OPRT_OK;

    tuya_mqtt_context_t* client = &client_instance;

    ret = tuya_mqtt_init(client, &(const tuya_mqtt_config_t) {
        .host = "m2.tuyacn.com",
        .port = 8883,
        .cacert = tuya_cacert_pem,
        .cacert_len = sizeof(tuya_cacert_pem),
        .device_id = deviceId,
        .device_secret = deviceSecret,
        .keepalive = 60,
        .timeout_ms = 2000,
        .on_connected = on_connected,
        .on_disconnect = on_disconnect,
        .on_messages = on_messages
    });
    assert(ret == OPRT_OK);

    ret = tuya_mqtt_connect(client);
    assert(ret == OPRT_OK);

    for (;;) {
        /* Loop to receive packets, and handles client keepalive */
        tuya_mqtt_loop(client);
    }

    return ret;
}
