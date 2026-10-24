cmake_minimum_required(VERSION 3.21)
project(AES_Suite VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================
#  Build Options
# ============================================================
option(AES_ENABLE_AESNI       "Enable AES-NI hardware acceleration" ON)
option(AES_BUILD_TESTS        "Build test suite"                     ON)
option(AES_BUILD_BENCH        "Build benchmark executable"           ON)
option(AES_ENABLE_SANITIZERS  "Enable ASan and UBSan (GCC/Clang)"    OFF)

# ============================================================
#  Compiler Warnings & Flags
# ============================================================
if(MSVC)
    add_compile_options(/W4 /permissive-)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/O2)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O3)
    endif()

    if(AES_ENABLE_SANITIZERS)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

# ============================================================
#  Core Sources
# ============================================================
set(AES_CORE_SOURCES
    src/aes.cpp
    src/aes_modes.cpp
    src/cpu_features.cpp
)

set(AES_CORE_HEADERS
    include/aes.h
    include/aes_modes.h
    include/aes_c_api.h
)

if(AES_ENABLE_AESNI)
    list(APPEND AES_CORE_SOURCES src/aes_ni.cpp)
    # Apply AES-NI flags only to aes_ni.cpp on GCC/Clang
    if(NOT MSVC)
        set_source_files_properties(src/aes_ni.cpp PROPERTIES COMPILE_FLAGS "-maes -mpclmul -msse4.1")
    endif()
endif()

# ============================================================
#  Targets
# ============================================================

# 1. Static Library: aes_core
add_library(aes_core STATIC ${AES_CORE_SOURCES})
target_include_directories(aes_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)

# 2. Shared Library: aes_shared (exports pure C API)
add_library(aes_shared SHARED ${AES_CORE_SOURCES} src/aes_c_api.cpp)
target_include_directories(aes_shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)
target_compile_definitions(aes_shared PRIVATE AES_BUILDING_SHARED)

# 3. Test Suite: aes_tests
if(AES_BUILD_TESTS)
    enable_testing()

    add_executable(aes_tests test/test_aes.cpp)
    target_link_libraries(aes_tests PRIVATE aes_core)

    add_executable(aes_diff_test test/diff_test.cpp test/old_aes.cpp)
    target_link_libraries(aes_diff_test PRIVATE aes_core)
    target_include_directories(aes_diff_test PRIVATE test)

    add_test(NAME NIST_KAT_and_Modes COMMAND aes_tests)
    add_test(NAME Differential_1M_Blocks COMMAND aes_diff_test)
endif()

# 4. Benchmark: aes_bench
if(AES_BUILD_BENCH)
    add_executable(aes_bench test/test_aes.cpp)
    target_link_libraries(aes_bench PRIVATE aes_core)
    # Pass --bench argument
    set_target_properties(aes_bench PROPERTIES OUTPUT_NAME "aes_bench")
endif()

# 5. CLI Demo: aes_cli
add_executable(aes_cli AES/main.cpp)
target_link_libraries(aes_cli PRIVATE aes_core)
target_include_directories(aes_cli PRIVATE AES)

# ============================================================
#  Installation
# ============================================================
install(TARGETS aes_core aes_shared
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES ${AES_CORE_HEADERS} DESTINATION include)

