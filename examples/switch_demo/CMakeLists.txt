set( DEMO_NAME "switch_demo" )

# Demo target.
add_executable(
    ${DEMO_NAME}
        "${DEMO_NAME}.c"
        "qrencode_print.c"
)

target_link_libraries(
    ${DEMO_NAME}
    PUBLIC
        link_core
        qrencode
)

target_include_directories(
    ${DEMO_NAME}
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
)
