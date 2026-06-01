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
    kek/kek.cc
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
