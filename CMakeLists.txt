cmake_minimum_required(VERSION 3.16)
project(ssm VERSION 0.3.2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# SSM_EXPORT controls symbol visibility (public C API only).
# CMAKE_CXX_VISIBILITY_PRESET=hidden is forced in Release builds.

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(SQLCipher REQUIRED)

include(FetchContent)

# Sanitizer support (ASan + UBSan)
include(cmake/Sanitizer.cmake)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

option(SSM_BUILD_BENCHMARKS "Build benchmark suite" OFF)
if(SSM_BUILD_BENCHMARKS)
    find_package(Threads REQUIRED)
    FetchContent_Declare(
        googlebenchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v1.9.1
    )
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googlebenchmark)
endif()

add_subdirectory(src)
add_subdirectory(cli)

option(SSM_BUILD_TESTS "Build tests" ON)
if(SSM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
