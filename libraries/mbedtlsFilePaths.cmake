# This file is to add source files and include directories
# into variables so that it can be reused from different repositories
# in their Cmake based build system by including this file.
#
# Files specific to the repository such as test runner, platform tests
# are not added to the variables.

set( MBEDTLS_DIR "${CMAKE_CURRENT_LIST_DIR}/mbedtls")

# mbedtls library source files.
file(GLOB MBEDTLS_SOURCE "${MBEDTLS_DIR}/library/*")

# mbedtls library Public Include directories.
set( MBEDTLS_INCLUDE_PUBLIC_DIRS
     "${MBEDTLS_DIR}/include"
     "${MBEDTLS_DIR}/include/mbedtls" )