cmake_minimum_required(VERSION 3.16)
project(ssm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Visibility defaults are left off during active development.
# Set CMAKE_CXX_VISIBILITY_PRESET=hidden before release and
# annotate public C API symbols with __attribute__((visibility("default"))).

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(SQLCipher REQUIRED)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_subdirectory(src)

option(SSM_BUILD_TESTS "Build tests" ON)
if(SSM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
