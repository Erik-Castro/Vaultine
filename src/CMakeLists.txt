add_library(ssm SHARED
    ssm.cc
    utils/secure_memory.cc
    crypto/random.cc
    crypto/argon2id.cc
    crypto/aes_kw.cc
    crypto/aes_gcm.cc
    db/database.cc
    db/users.cc
    db/kek_metadata.cc
    db/secrets.cc
    db/audit_log.cc
    kek/kek.cc
    backup/backup.cc
    export/export.cc
)

target_include_directories(ssm
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(ssm
    PUBLIC
        OpenSSL::Crypto
        SQLCipher::SQLCipher
        PkgConfig::SODIUM
)

if(COMMAND target_precompile_headers)
    target_precompile_headers(ssm PRIVATE
        <cstddef>
        <cstring>
        <memory>
        <mutex>
        <shared_mutex>
    )
endif()

set_target_properties(ssm PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME ssm
)

option(SSM_VISIBILITY_HIDDEN "Hide internal symbols; only SSM_EXPORT public API visible" OFF)
if(SSM_VISIBILITY_HIDDEN)
    set_target_properties(ssm PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
endif()

# Force visibility hidden in Release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(SSM_VISIBILITY_HIDDEN ON CACHE BOOL "" FORCE)
    message(STATUS "Release build: forcing SSM_VISIBILITY_HIDDEN=ON")
endif()

# --- install rules ---
include(GNUInstallDirs)

install(TARGETS ssm
    EXPORT ssmTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

install(EXPORT ssmTargets
    FILE ssmTargets.cmake
    NAMESPACE ssm::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ssm
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_SOURCE_DIR}/cmake/ssmConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/ssmConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ssm
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/ssmConfig.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ssm
)
