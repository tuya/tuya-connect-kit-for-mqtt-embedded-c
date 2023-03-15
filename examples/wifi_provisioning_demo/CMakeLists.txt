set( DEMO_NAME "wifi_provisioning_demo" )

# Demo target.
add_executable(
    ${DEMO_NAME}
        "${DEMO_NAME}.c"
)

target_link_libraries(
    ${DEMO_NAME}
    PUBLIC
        link_core
)

target_include_directories(
    ${DEMO_NAME}
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
)
