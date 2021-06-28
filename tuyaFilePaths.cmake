# This file is to add source files and include directories
# into variables so that it can be reused from different repositories
# in their Cmake based build system by including this file.
#
# Files specific to the repository such as test runner, platform tests
# are not added to the variables.

# Link SDK source files.
# FILE(GLOB LINK_SDK_SOURCES *.c)
set( LINK_SDK_SOURCES
     ${CMAKE_CURRENT_LIST_DIR}/src/atop_base.c
     ${CMAKE_CURRENT_LIST_DIR}/src/atop_service.c
     ${CMAKE_CURRENT_LIST_DIR}/src/mqtt_service.c
     ${CMAKE_CURRENT_LIST_DIR}/src/mqtt_bind.c
     ${CMAKE_CURRENT_LIST_DIR}/src/tuya_iot.c
     ${CMAKE_CURRENT_LIST_DIR}/src/tuya_endpoint.c
     ${CMAKE_CURRENT_LIST_DIR}/src/iotdns.c
     ${CMAKE_CURRENT_LIST_DIR}/src/matop_service.c
     ${CMAKE_CURRENT_LIST_DIR}/src/file_download.c
     ${CMAKE_CURRENT_LIST_DIR}/src/tuya_ota.c
)

# Public Include directories.
set( LINK_SDK_INCLUDE_PUBLIC_DIRS
     ${CMAKE_CURRENT_LIST_DIR}/include
)
