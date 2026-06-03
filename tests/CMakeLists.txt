add_executable(ssm_test
    main.cc
    utils/secure_memory_test.cc
    crypto/random_test.cc
    crypto/argon2id_test.cc
    crypto/aes_kw_test.cc
    crypto/aes_gcm_test.cc
    db/database_test.cc
    db/migrations_test.cc
    db/users_test.cc
    db/kek_metadata_test.cc
    db/secrets_test.cc
    kek/kek_test.cc
    ssm_test.cc
    integration/lifecycle_test.cc
    backup_test.cc
    export_test.cc
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

# ── Benchmarks ─────────────────────────────────────────────────────────
if(SSM_BUILD_BENCHMARKS)
    add_executable(ssm_bench bench_ssm.cc)
    target_include_directories(ssm_bench PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(ssm_bench PRIVATE ssm benchmark::benchmark)

    # Benchmarks are informational only — never fail CI
    add_test(NAME ssm_bench COMMAND ssm_bench --benchmark_min_time=0.1)
endif()

# ── Fuzzing targets (clang + libFuzzer) ─────────────────────────────────
option(SSM_FUZZING "Build libFuzzer fuzz targets (requires clang)" OFF)
if(SSM_FUZZING)
    add_executable(fuzz_api fuzz/fuzz_api.cc)
    target_include_directories(fuzz_api PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(fuzz_api PRIVATE ssm)
    target_compile_options(fuzz_api PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_api PRIVATE -fsanitize=fuzzer)

    add_test(NAME fuzz_api_quick
        COMMAND fuzz_api -max_total_time=10 -runs=100000
            ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/api/
    )

    # CLI utility fuzzing (hex_decode, hex_val)
    add_executable(fuzz_cli fuzz/fuzz_cli.cc)
    target_include_directories(fuzz_cli PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/cli)
    target_compile_options(fuzz_cli PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_cli PRIVATE -fsanitize=fuzzer)

    add_test(NAME fuzz_cli_quick
        COMMAND fuzz_cli -max_total_time=10 -runs=100000
    )

    # Password validation fuzzing
    add_executable(fuzz_password fuzz/fuzz_password.cc)
    target_include_directories(fuzz_password PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(fuzz_password PRIVATE ssm)
    target_compile_options(fuzz_password PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_password PRIVATE -fsanitize=fuzzer)

    add_test(NAME fuzz_password_quick
        COMMAND fuzz_password -max_total_time=10 -runs=100000
    )
endif()
