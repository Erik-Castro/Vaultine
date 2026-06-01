add_executable(ssm_test
    main.cc
    utils/secure_memory_test.cc
    crypto/random_test.cc
    crypto/argon2id_test.cc
    crypto/aes_kw_test.cc
    crypto/aes_gcm_test.cc
    db/database_test.cc
    db/users_test.cc
    db/kek_metadata_test.cc
    db/secrets_test.cc
    kek/kek_test.cc
    ssm_test.cc
)

target_include_directories(ssm_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ssm_test
    PRIVATE
        ssm
        GTest::gmock_main
        GTest::gmock
        GTest::gtest
)

# LLD note: no --allow-shlib-undefined needed — sqlcipher PRAGMA key avoids sqlite3_key symbol

add_test(NAME ssm_test COMMAND ssm_test)
