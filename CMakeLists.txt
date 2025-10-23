cmake_minimum_required(VERSION 3.20)
project(PocketHttp LANGUAGES C CXX)

# =========================
# Compilation options
# =========================
# Optional user definitions
option(USE_POCKET_HTTP_LOG "Enable logging" OFF)
option(USE_POCKET_HTTP_ERR "Enable error handling" OFF)
option(USE_POCKET_HTTP_BEARSSL "Use BearSSL" ON)
option(USE_POCKET_HTTP_MOZILLA_ROOT_CERTS "Include Mozilla certificates" ON)

# =========================
# Source files
# =========================
file(GLOB_RECURSE SOURCES src/*.cpp)

# =========================
# Create executable or library
# =========================
add_executable(${PROJECT_NAME} ${SOURCES} examples/basic_request.cpp)
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "pocket-http")

# =========================
# Compiler definitions
# =========================
if(USE_POCKET_HTTP_LOG)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_POCKET_HTTP_LOG)
endif()

if(USE_POCKET_HTTP_ERR)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_POCKET_HTTP_ERR)
endif()

if(USE_POCKET_HTTP_BEARSSL)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_POCKET_HTTP_BEARSSL)
endif()

if(USE_POCKET_HTTP_MOZILLA_ROOT_CERTS)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_POCKET_HTTP_MOZILLA_ROOT_CERTS)
endif()

# =========================
# Include paths
# =========================
target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include)

# =========================
# External dependencies
# =========================
# BearSSL only if USE_POCKET_HTTP_BEARSSL is enabled
if(USE_POCKET_HTTP_BEARSSL)
    add_subdirectory(external/bearssl)
    target_link_libraries(${PROJECT_NAME} PRIVATE bearssl)
endif()

# miniz
add_subdirectory(external/miniz)
target_link_libraries(${PROJECT_NAME} PRIVATE miniz)

# base64
add_subdirectory(external/base64)
target_link_libraries(${PROJECT_NAME} PRIVATE base64)

# =========================
# Compiler options by platform
# =========================
if(WIN32)
    # Windows
    target_compile_definitions(${PROJECT_NAME} PRIVATE "__m128i_u=__m128i" "__m256i_u=__m256i")
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8 /EHsc /Os)
elseif(APPLE)
    # macOS
    target_compile_options(${PROJECT_NAME} PRIVATE -Os)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation)
    find_library(SECURITY_FRAMEWORK Security)
elseif(UNIX)
    # Linux / otros UNIX
    target_compile_options(${PROJECT_NAME} PRIVATE -no-pie -Os)
endif()

# =========================
# Additional optional configuration
# =========================
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)