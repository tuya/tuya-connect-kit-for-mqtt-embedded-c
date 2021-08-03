# Project information.
cmake_minimum_required( VERSION 3.2.0 )
project( TuyaIoTLinkSdkEmbeddedC
         VERSION 202108.03
         LANGUAGES C )

# Allow the project to be organized into folders.
set_property( GLOBAL PROPERTY USE_FOLDERS ON )

# Use C90.
set( CMAKE_C_STANDARD 90 )
set( CMAKE_C_STANDARD_REQUIRED ON )

# For debug
add_compile_options( -g )

# Set Compiler
# set(CMAKE_C_COMPILER arm-linux-androideabi-gcc)
# set(CMAKE_CXX_COMPILER arm-linux-androideabi-g++)

# Do not allow in-source build.
if( ${PROJECT_SOURCE_DIR} STREQUAL ${PROJECT_BINARY_DIR} )
    message( FATAL_ERROR "In-source build is not allowed. Please build in a separate directory, such as ${PROJECT_SOURCE_DIR}/build." )
endif()

# Set global path variables.
get_filename_component(__root_dir "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
set(ROOT_DIR ${__root_dir} CACHE INTERNAL "C SDK source root.")
set(EXAMPLES_DIR "${ROOT_DIR}/examples" CACHE INTERNAL "C SDK examples root.")
set(PLATFORM_DIR "${ROOT_DIR}/platform" CACHE INTERNAL "C SDK platform root.")
set(LIBRARIES_DIR "${ROOT_DIR}/libraries" CACHE INTERNAL "C SDK libraries root.")
set(LINKSDK_DIRS "${ROOT_DIR}")
set(INTERFACE_DIRS "${ROOT_DIR}/interface")

# Configure options to always show in CMake GUI.
option( BUILD_TESTS
        "Set this to ON to build both demo and test executables. When OFF, only demo executables are built."
        OFF )
option( BUILD_CLONE_SUBMODULES
        "Set this to ON to automatically clone any required Git submodules. When OFF, submodules must be manually cloned."
        ON )
option( DOWNLOAD_CERTS
        "Set this to ON to automatically download certificates needed to run the demo. When OFF, certificates must be manually downloaded."
        ON )

# Unity test framework does not export the correct symbols for DLLs.
set( ALLOW_SHARED_LIBRARIES ON )

include( CMakeDependentOption )
CMAKE_DEPENDENT_OPTION( BUILD_SHARED_LIBS
                        "Set this to ON to build all libraries as shared libraries. When OFF, libraries build as static libraries."
                        ON "${ALLOW_SHARED_LIBRARIES}"
                        OFF )

# Set output directories.
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )

# Add platform.
add_subdirectory( platform )

# Add middleware.
add_subdirectory( middleware )

# Add utils.
add_subdirectory( utils )

# Add link core.
add_subdirectory( src )

# # Build the demos.
add_subdirectory( examples )


message(STATUS "------------------------------------------------------------" )
message(STATUS "[Link SDK] Configuration summary."                            )
message(STATUS "------------------------------------------------------------ ")
message(STATUS " System configuration:"                                       )
message(STATUS " .. Processor type .............. = ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS " .. CMake executable ............ = ${CMAKE_COMMAND}"         )
message(STATUS " .. CMake version ............... = ${CMAKE_VERSION}"         )
message(STATUS " .. System name ................. = ${CMAKE_SYSTEM}"          )
message(STATUS " .. C++ compiler ................ = ${CMAKE_CXX_COMPILER}"    )
message(STATUS " .. C compiler .................. = ${CMAKE_C_COMPILER}"      )
message(STATUS " .. C FLAGS ..................... = ${CMAKE_C_FLAGS}"         )
message(STATUS " .. size(void*) ................. = ${CMAKE_SIZEOF_VOID_P}"   )
message(STATUS " Project configuration:"                                      )
message(STATUS " .. Build test programs  ........ = ${WITH_TESTS}"            )
message(STATUS " .. Build utility tools  ........ = ${WITH_TOOLS}"            )
message(STATUS " .. Disable PNG support  ........ = ${WITHOUT_PNG}"           )
message(STATUS " .. Installation prefix ......... = ${CMAKE_INSTALL_PREFIX}"  )
message(STATUS "------------------------------------------------------------ ")
