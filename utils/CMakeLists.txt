# Include filepaths for source and include.
FILE(GLOB UTILS_SOURCES *.c)

# Add a library with the above sources
add_library( utils_modules
    ${UTILS_SOURCES}
)

target_include_directories( utils_modules
    PUBLIC 
    ${CMAKE_CURRENT_LIST_DIR}
    ${INTERFACE_DIRS}
)