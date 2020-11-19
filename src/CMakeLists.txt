# Include filepaths for source and include.
include( ${LIBRARIES_DIR}/coreJSON/jsonFilePaths.cmake )
include( ${LIBRARIES_DIR}/coreHTTP/httpFilePaths.cmake )
include( ${LIBRARIES_DIR}/coreMQTT/mqttFilePaths.cmake )
include( ${LINKSDK_DIRS}/tuyaFilePaths.cmake )

# Add a library with the above sources
add_library( link_core STATIC
    ${LINK_SDK_SOURCES}
    ${MQTT_SOURCES}
    ${MQTT_SERIALIZER_SOURCES}
    ${HTTP_SOURCES}
    ${JSON_SOURCES}
    "${CERTS_DIRS}/tuya_rootCA.c"
)

target_include_directories( link_core
    PUBLIC 
    ${LINK_SDK_INCLUDE_PUBLIC_DIRS}
    ${INTERFACE_DIRS}
    ${MQTT_INCLUDE_PUBLIC_DIRS}
    ${HTTP_INCLUDE_PUBLIC_DIRS}
    ${JSON_INCLUDE_PUBLIC_DIRS}
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries( link_core
    utils_modules
    platform_port
)
