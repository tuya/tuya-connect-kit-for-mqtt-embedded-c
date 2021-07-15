set( DEMO_NAME "tuya_ota_demo" )

# Demo target.
add_executable(
    ${DEMO_NAME}
        "${DEMO_NAME}.c"
        "qrencode_print.c"
)

find_package(PkgConfig REQUIRED)
pkg_search_module(LIBQRENCODE REQUIRED libqrencode)

target_link_libraries(
    ${DEMO_NAME}
    PUBLIC
        link_core
        ${LIBQRENCODE_LIBRARIES}
)

target_link_directories(
    ${DEMO_NAME}
        PUBLIC
        ${LIBQRENCODE_LIBRARY_DIRS}
)

target_include_directories(
    ${DEMO_NAME}
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
        ${LIBQRENCODE_INCLUDE_DIRS}
)

