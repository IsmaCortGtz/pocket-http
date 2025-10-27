cmake_minimum_required(VERSION 3.20)
project(PocketHttp LANGUAGES C CXX)

# =========================
# Compilation options
# =========================
# Optional user definitions
option(USE_POCKET_HTTP_LOG "Enable logging" ON)
option(USE_POCKET_HTTP_ERR "Enable error handling" ON)
option(USE_POCKET_HTTP_MOZILLA_ROOT_CERTS "Include Mozilla certificates" OFF)

option(USE_POCKET_HTTP_BEARSSL "Use BearSSL" OFF)
option(USE_POCKET_HTTP_MBEDTLS "Use MbedTLS" OFF)

# =========================
# Source files
# =========================
file(GLOB_RECURSE SOURCES src/*.cpp)

# =========================
# Create executable or library
# =========================
add_executable(${PROJECT_NAME} ${SOURCES} examples/download.cpp)
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "pocket-http-mbedtls")

# =========================
# Compiler definitions
# =========================
if(USE_POCKET_HTTP_LOG)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_POCKET_HTTP_LOG)
endif()

if(USE_POCKET_HTTP_ERR)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_POCKET_HTTP_ERR)
endif()

if(USE_POCKET_HTTP_MOZILLA_ROOT_CERTS)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_POCKET_HTTP_MOZILLA_ROOT_CERTS)
endif()

if(USE_POCKET_HTTP_BEARSSL)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_POCKET_HTTP_BEARSSL)
endif()

if(USE_POCKET_HTTP_MBEDTLS)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_POCKET_HTTP_MBEDTLS)
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

# MbedTLS only if USE_POCKET_HTTP_MBEDTLS is enabled
if(USE_POCKET_HTTP_MBEDTLS)
    set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "Build Mbed TLS static library" FORCE)
    set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "Disable shared mbedtls library" FORCE)

    set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ON CACHE BOOL "Build TF-PSA-Crypto static" FORCE)
    set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY OFF CACHE BOOL "Disable TF-PSA-Crypto shared" FORCE)

    set(GEN_FILES ON CACHE BOOL "Enable generated files" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "Disable BUILD_SHARED_LIBS globally" FORCE)
    set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "Disable package & install targets" FORCE)

    set(MBEDTLS_CONFIG_FILE "${PROJECT_SOURCE_DIR}/include/pockethttp/Sockets/mbedtls_config.h" CACHE FILEPATH "Mbed TLS config file" FORCE)
    
    add_subdirectory(external/mbedtls)
    set(MBEDTLS_LINK_TARGETS "")
    foreach(tg IN ITEMS
        MbedTLS::tfpsacrypto MbedTLS::mbedtls MbedTLS::mbedx509
        tfpsacrypto mbedcrypto mbedtls mbedx509
    )
        if(TARGET ${tg})
            list(APPEND MBEDTLS_LINK_TARGETS ${tg})
        endif()
    endforeach()

    if(MBEDTLS_LINK_TARGETS)
        message(STATUS "Linking with MbedTLS targets: ${MBEDTLS_LINK_TARGETS}")
        target_link_libraries(${PROJECT_NAME} PUBLIC ${MBEDTLS_LINK_TARGETS})
    else()
        message(FATAL_ERROR "MbedTLS requested but no known Mbed TLS targets found after add_subdirectory(external/mbedtls). Revisa external/mbedtls/CMakeLists.txt o usa find_package(MbedTLS).")
    endif()

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
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8 /EHsc /Os /Gy /OPT:REF /OPT:ICF)
elseif(APPLE)
    # macOS
    target_compile_options(${PROJECT_NAME} PRIVATE -Os)
    target_compile_options(${PROJECT_NAME} PRIVATE -ffunction-sections -fdata-sections -Wl,--gc-sections)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation)
    find_library(SECURITY_FRAMEWORK Security)
elseif(UNIX)
    # Linux / otros UNIX
    target_compile_options(${PROJECT_NAME} PRIVATE -no-pie -Os)
    target_compile_options(${PROJECT_NAME} PRIVATE -ffunction-sections -fdata-sections -Wl,--gc-sections)
endif()

# =========================
# Additional optional configuration
# =========================
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)