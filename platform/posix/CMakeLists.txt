include( ${LIBRARIES_DIR}/mbedtlsFilePaths.cmake )

# Create target for POSIX implementation of reconnect logic.
add_library( platform_port STATIC
               "mbedtls_sockets_wrapper.c"
               "network_wrapper.c"
               "system_wrapper.c"
               "storage_wrapper.c"
               ${MBEDTLS_SOURCE}
               )

target_include_directories( platform_port
                              PUBLIC
                                ${MBEDTLS_INCLUDE_PUBLIC_DIRS}
                                ${INTERFACE_DIRS} )

target_link_libraries( platform_port utils_modules)
