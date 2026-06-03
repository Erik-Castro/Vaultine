#include <benchmark/benchmark.h>

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "ssm/ssm.h"

static void BM_UserRegister(benchmark::State& state) {
    for (auto _ : state) {
        ssm_handle* h = nullptr;
        if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
            state.SkipWithError("ssm_init failed");
            break;
        }
        if (ssm_user_register(h, "alice", "password123") != SSM_OK)
            state.SkipWithError("ssm_user_register failed");
        ssm_destroy(h);
    }
}
BENCHMARK(BM_UserRegister)->Unit(benchmark::kMillisecond);

static void BM_UserAuthenticate(benchmark::State& state) {
    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
        state.SkipWithError("ssm_init failed");
        return;
    }
    if (ssm_user_register(h, "alice", "password123") != SSM_OK) {
        state.SkipWithError("ssm_user_register failed");
        ssm_destroy(h);
        return;
    }

    for (auto _ : state) {
        int valid = 0;
        ssm_user_authenticate(h, "alice", "password123", &valid);
    }
    ssm_destroy(h);
}
BENCHMARK(BM_UserAuthenticate)->Unit(benchmark::kMillisecond);

static void BM_SecretStore(benchmark::State& state) {
    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
        state.SkipWithError("ssm_init failed");
        return;
    }
    if (ssm_user_register(h, "alice", "password123") != SSM_OK) {
        state.SkipWithError("ssm_user_register failed");
        ssm_destroy(h);
        return;
    }

    unsigned char key[32];
    std::memset(key, 'A', sizeof(key));
    int i = 0;

    for (auto _ : state) {
        char name[16];
        std::snprintf(name, sizeof(name), "key%d", i++);
        if (ssm_secret_store(h, "alice", key, sizeof(key), nullptr, 0, name, nullptr) != SSM_OK)
            state.SkipWithError("ssm_secret_store failed");
    }
    ssm_destroy(h);
}
BENCHMARK(BM_SecretStore)->Unit(benchmark::kMillisecond);

static void BM_CacheHit(benchmark::State& state) {
    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
        state.SkipWithError("ssm_init failed");
        return;
    }
    if (ssm_user_register(h, "alice", "password123") != SSM_OK) {
        state.SkipWithError("ssm_user_register failed");
        ssm_destroy(h);
        return;
    }

    unsigned char key[32];
    std::memset(key, 'B', sizeof(key));
    if (ssm_secret_store(h, "alice", key, sizeof(key), nullptr, 0, "mykey", nullptr) != SSM_OK) {
        state.SkipWithError("ssm_secret_store failed");
        ssm_destroy(h);
        return;
    }

    unsigned char out[64];
    size_t len = sizeof(out);

    for (auto _ : state)
        ssm_secret_get(h, "alice", "mykey", out, &len, nullptr, nullptr);
    ssm_destroy(h);
}
BENCHMARK(BM_CacheHit)->Unit(benchmark::kMicrosecond);

static void BM_CacheMiss(benchmark::State& state) {
    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
        state.SkipWithError("ssm_init failed");
        return;
    }
    if (ssm_user_register(h, "alice", "password123") != SSM_OK) {
        state.SkipWithError("ssm_user_register failed");
        ssm_destroy(h);
        return;
    }

    unsigned char out[64];
    size_t len = sizeof(out);

    for (auto _ : state)
        ssm_secret_get(h, "alice", "nonexistent", out, &len, nullptr, nullptr);
    ssm_destroy(h);
}
BENCHMARK(BM_CacheMiss)->Unit(benchmark::kMicrosecond);

static void BM_UserDelete(benchmark::State& state) {
    for (auto _ : state) {
        ssm_handle* h = nullptr;
        if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
            state.SkipWithError("ssm_init failed");
            break;
        }
        if (ssm_user_register(h, "alice", "password123") != SSM_OK) {
            state.SkipWithError("ssm_user_register failed");
            ssm_destroy(h);
            break;
        }
        ssm_user_delete(h, "alice", "password123");
        ssm_destroy(h);
    }
}
BENCHMARK(BM_UserDelete)->Unit(benchmark::kMillisecond);

static void BM_KekRotate(benchmark::State& state) {
    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
        state.SkipWithError("ssm_init failed");
        return;
    }
    if (ssm_user_register(h, "alice", "password123") != SSM_OK) {
        state.SkipWithError("ssm_user_register failed");
        ssm_destroy(h);
        return;
    }

    for (auto _ : state)
        ssm_kek_rotate(h, "alice");
    ssm_destroy(h);
}
BENCHMARK(BM_KekRotate)->Unit(benchmark::kMillisecond);

static void BM_SecretList(benchmark::State& state) {
    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
        state.SkipWithError("ssm_init failed");
        return;
    }
    if (ssm_user_register(h, "alice", "password123") != SSM_OK) {
        state.SkipWithError("ssm_user_register failed");
        ssm_destroy(h);
        return;
    }

    unsigned char key[32];
    std::memset(key, 'C', sizeof(key));
    for (int i = 0; i < 10; ++i) {
        char name[16];
        std::snprintf(name, sizeof(name), "key%d", i);
        if (ssm_secret_store(h, "alice", key, sizeof(key), nullptr, 0, name, nullptr) != SSM_OK) {
            state.SkipWithError("ssm_secret_store failed");
            ssm_destroy(h);
            return;
        }
    }

    for (auto _ : state)
        ssm_secret_list(h, "alice", nullptr, nullptr);
    ssm_destroy(h);
}
BENCHMARK(BM_SecretList)->Unit(benchmark::kMicrosecond);

static void BM_ChangePassword(benchmark::State& state) {
    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
        state.SkipWithError("ssm_init failed");
        return;
    }
    if (ssm_user_register(h, "alice", "old_password") != SSM_OK) {
        state.SkipWithError("ssm_user_register failed");
        ssm_destroy(h);
        return;
    }

    for (auto _ : state) {
        ssm_user_change_password(h, "alice", "old_password", "new_password123");
        ssm_user_change_password(h, "alice", "new_password123", "old_password");
    }
    ssm_destroy(h);
}
BENCHMARK(BM_ChangePassword)->Unit(benchmark::kMillisecond);

static void BM_ConcurrentReads(benchmark::State& state) {
    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK) {
        state.SkipWithError("ssm_init failed");
        return;
    }
    if (ssm_user_register(h, "alice", "password123") != SSM_OK) {
        state.SkipWithError("ssm_user_register failed");
        ssm_destroy(h);
        return;
    }

    unsigned char key[32];
    std::memset(key, 'D', sizeof(key));
    ssm_secret_store(h, "alice", key, sizeof(key), nullptr, 0, "shared_key", nullptr);

    unsigned char out[64];
    size_t len = sizeof(out);

    for (auto _ : state) {
        std::vector<std::thread> threads;
        for (int t = 0; t < 4; ++t)
            threads.emplace_back([h] {
                for (int i = 0; i < 5; ++i) {
                    unsigned char buf[64];
                    size_t l = sizeof(buf);
                    ssm_secret_get(h, "alice", "shared_key", buf, &l, nullptr, nullptr);
                }
            });
        for (auto& t : threads)
            t.join();
    }
    ssm_destroy(h);
}
BENCHMARK(BM_ConcurrentReads)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
