add_library(bearssl STATIC)

file(GLOB_RECURSE BEARSSL_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
target_sources(bearssl PRIVATE ${BEARSSL_SOURCES})

target_include_directories(bearssl
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(bearssl PUBLIC c_std_99)