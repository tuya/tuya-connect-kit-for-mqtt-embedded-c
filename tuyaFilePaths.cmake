# This file is to add source files and include directories
# into variables so that it can be reused from different repositories
# in their Cmake based build system by including this file.
#
# Files specific to the repository such as test runner, platform tests
# are not added to the variables.

# Link SDK source files.
# FILE(GLOB LINK_SDK_SOURCES *.c)
set( LINK_SDK_SOURCES
     ${CMAKE_CURRENT_LIST_DIR}/src/tuyalink_core.c
     ${CMAKE_CURRENT_LIST_DIR}/src/cipher_wrapper.c
)

# Public Include directories.
set( LINK_SDK_INCLUDE_PUBLIC_DIRS
     ${CMAKE_CURRENT_LIST_DIR}/include
)
