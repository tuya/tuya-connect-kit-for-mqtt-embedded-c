# This file is to add source files and include directories
# into variables so that it can be reused from different repositories
# in their Cmake based build system by including this file.
#
# Files specific to the repository such as test runner, platform tests
# are not added to the variables.

# Link SDK source files.
# FILE(GLOB LINK_SDK_SOURCES *.c)
set( LINK_SDK_SOURCES
     "${LINKSDK_DIRS}/src/atop_base.c"
     "${LINKSDK_DIRS}/src/atop_service.c"
     "${LINKSDK_DIRS}/src/mqtt_service.c"
     "${LINKSDK_DIRS}/src/mqtt_bind.c"
     "${LINKSDK_DIRS}/src/tuya_iot.c" 
     "${LINKSDK_DIRS}/src/tuya_endpoint.c" 
     "${LINKSDK_DIRS}/src/iotdns.c" 
)


# MQTT library Public Include directories.
set( LINK_SDK_INCLUDE_PUBLIC_DIRS
     "${LINKSDK_DIRS}/include"
)
