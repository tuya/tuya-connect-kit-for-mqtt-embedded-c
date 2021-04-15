include( ${LIBRARIES_DIR}/coreHTTP/httpFilePaths.cmake )
include( ${LIBRARIES_DIR}/coreMQTT/mqttFilePaths.cmake )

# Create target for POSIX implementation of reconnect logic.
add_library( middleware_implementation STATIC
                ${MQTT_SOURCES}
                ${MQTT_SERIALIZER_SOURCES}
                ${HTTP_SOURCES}
                "http_client_wrapper.c"
                "mqtt_client_wrapper.c" )

target_include_directories( middleware_implementation PRIVATE
                              ${CMAKE_CURRENT_LIST_DIR}
                              ${MQTT_INCLUDE_PUBLIC_DIRS}
                              ${HTTP_INCLUDE_PUBLIC_DIRS}
                              ${INTERFACE_DIRS} )

target_link_libraries( middleware_implementation utils_modules platform_port)
