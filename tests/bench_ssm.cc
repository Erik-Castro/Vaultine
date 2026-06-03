#include <benchmark/benchmark.h>

#include <cstdio>
#include <cstring>

#include "ssm/ssm.h"

static void BM_UserRegister(benchmark::State& state) {
    for (auto _ : state) {
        ssm_handle* h = nullptr;
        if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK)
            continue;
        ssm_user_register(h, "alice", "password123");
        ssm_destroy(h);
    }
}
BENCHMARK(BM_UserRegister)->Unit(benchmark::kMillisecond);

static void BM_UserAuthenticate(benchmark::State& state) {
    ssm_handle* h = nullptr;
    ssm_init(&h, ":memory:", nullptr, 0);
    ssm_user_register(h, "alice", "password123");

    for (auto _ : state) {
        int valid = 0;
        ssm_user_authenticate(h, "alice", "password123", &valid);
    }
    ssm_destroy(h);
}
BENCHMARK(BM_UserAuthenticate)->Unit(benchmark::kMillisecond);

static void BM_SecretStore(benchmark::State& state) {
    ssm_handle* h = nullptr;
    ssm_init(&h, ":memory:", nullptr, 0);
    ssm_user_register(h, "alice", "password123");

    unsigned char key[32];
    std::memset(key, 'A', sizeof(key));
    int i = 0;

    for (auto _ : state) {
        char name[16];
        std::snprintf(name, sizeof(name), "key%d", i++);
        ssm_secret_store(h, "alice", key, sizeof(key), nullptr, 0, name, nullptr);
    }
    ssm_destroy(h);
}
BENCHMARK(BM_SecretStore)->Unit(benchmark::kMillisecond);

static void BM_CacheHit(benchmark::State& state) {
    ssm_handle* h = nullptr;
    ssm_init(&h, ":memory:", nullptr, 0);
    ssm_user_register(h, "alice", "password123");

    unsigned char key[32];
    std::memset(key, 'B', sizeof(key));
    ssm_secret_store(h, "alice", key, sizeof(key), nullptr, 0, "mykey", nullptr);

    unsigned char out[64];
    size_t len = sizeof(out);

    for (auto _ : state) {
        ssm_secret_get(h, "alice", "mykey", out, &len, nullptr, nullptr);
    }
    ssm_destroy(h);
}
BENCHMARK(BM_CacheHit)->Unit(benchmark::kMicrosecond);

static void BM_CacheMiss(benchmark::State& state) {
    ssm_handle* h = nullptr;
    ssm_init(&h, ":memory:", nullptr, 0);
    ssm_user_register(h, "alice", "password123");

    unsigned char out[64];
    size_t len = sizeof(out);

    for (auto _ : state) {
        ssm_secret_get(h, "alice", "nonexistent", out, &len, nullptr, nullptr);
    }
    ssm_destroy(h);
}
BENCHMARK(BM_CacheMiss)->Unit(benchmark::kMicrosecond);

static void BM_UserDelete(benchmark::State& state) {
    for (auto _ : state) {
        ssm_handle* h = nullptr;
        if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK)
            continue;
        ssm_user_register(h, "alice", "password123");
        ssm_user_delete(h, "alice", "password123");
        ssm_destroy(h);
    }
}
BENCHMARK(BM_UserDelete)->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
