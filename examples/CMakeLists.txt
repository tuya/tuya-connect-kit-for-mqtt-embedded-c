# Set the platform named based on the host OS if not defined.
if( NOT DEFINED PLATFORM_NAME )
    if( ${CMAKE_SYSTEM_NAME} STREQUAL "Linux" )
        set( PLATFORM_NAME "posix" CACHE STRING "Port to use for building the SDK." )
    else()
        message( FATAL_ERROR "${CMAKE_SYSTEM_NAME} is not a supported platform." )
    endif()
endif()

# Include each subdirectory that has a CMakeLists.txt file in it
file(GLOB example_dirs "${EXAMPLES_DIR}/*")
foreach(example_dir IN LISTS example_dirs)
    if(IS_DIRECTORY "${example_dir}" AND EXISTS "${example_dir}/CMakeLists.txt")
        add_subdirectory(${example_dir})
    endif()
endforeach()
