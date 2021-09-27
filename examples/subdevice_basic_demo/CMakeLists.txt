set( DEMO_NAME "subdevice_basic_demo" )

# Demo target.
add_executable(
    ${DEMO_NAME}
        "${DEMO_NAME}.c"
)

target_link_libraries(
    ${DEMO_NAME}
    PUBLIC
        utils_modules
        platform_port
        middleware_implementation
        link_core
)

target_include_directories(
    ${DEMO_NAME}
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
)
