cmake_minimum_required(VERSION 3.16)
project(PocketHTTP LANGUAGES C CXX)

# Usar C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Forzar Ninja si se desea
if(NOT CMAKE_GENERATOR)
    set(CMAKE_GENERATOR "Ninja" CACHE INTERNAL "" FORCE)
endif()

# ============================================================
# ⚙️ OPCIONES DE CONFIGURACIÓN
# ============================================================
option(USE_POCKET_HTTP_LOG "Enable internal logging" ON)
option(USE_POCKET_HTTP_ERR "Enable error reporting" ON)
option(USE_POCKET_HTTP_BEARSSL "Enable BearSSL support" ON)
option(USE_POCKET_HTTP_MOZILLA_ROOT_CERTS "Include Mozilla root certs" ON)

# ============================================================
# 📁 INCLUDE DIRS
# ============================================================
set(INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/dist
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/miniz
    ${PROJECT_SOURCE_DIR}/include/bearssl
    ${PROJECT_SOURCE_DIR}/src/bearssl
)

# ============================================================
# 📦 SOURCES
# ============================================================
file(GLOB_RECURSE POCKETHTTP_SOURCES
    ${PROJECT_SOURCE_DIR}/include/miniz/miniz.c
    ${PROJECT_SOURCE_DIR}/dist/*.cpp
)

if(USE_POCKET_HTTP_BEARSSL)
    file(GLOB_RECURSE BEARSSL_SOURCES
        ${PROJECT_SOURCE_DIR}/src/bearssl/*.c
    )
    list(APPEND POCKETHTTP_SOURCES ${BEARSSL_SOURCES})
endif()

# ============================================================
# 💬 DEFINICIONES (comunes)
# ============================================================
set(COMMON_DEFS "")
foreach(DEF IN ITEMS
    USE_POCKET_HTTP_LOG
    USE_POCKET_HTTP_ERR
    USE_POCKET_HTTP_BEARSSL
    USE_POCKET_HTTP_MOZILLA_ROOT_CERTS
)
    if(${DEF})
        list(APPEND COMMON_DEFS ${DEF})
    endif()
endforeach()

# ============================================================
# ⚙️ FLAGS Y DEFINICIONES POR PLATAFORMA
# ============================================================

if(WIN32)
    message(STATUS "🪟 Compilando para Windows")
    list(APPEND COMMON_DEFS "__m128i_u=__m128i" "__m256i_u=__m256i")
    add_compile_options(/utf-8 /EHsc /Os)
elseif(APPLE)
    message(STATUS "🍎 Compilando para macOS")
    add_compile_options(-Os)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation)
    find_library(SECURITY_FRAMEWORK Security)
    set(EXTRA_LIBS ${COREFOUNDATION_FRAMEWORK} ${SECURITY_FRAMEWORK})
elseif(UNIX)
    message(STATUS "🐧 Compilando para Linux")
    add_compile_options(-no-pie -Os)
endif()

# ============================================================
# 🧪 (Opcional) Ejecutable demo si existe
# ============================================================
add_executable(pockethttp_demo 
    ${POCKETHTTP_SOURCES} 
    ${PROJECT_SOURCE_DIR}/examples/amalgamated.cpp
)
target_include_directories(pockethttp_demo PRIVATE ${INCLUDE_DIRS})
target_compile_definitions(pockethttp_demo PRIVATE ${COMMON_DEFS})

if(EXTRA_LIBS)
    target_link_libraries(pockethttp_demo PRIVATE ${EXTRA_LIBS})
endif()