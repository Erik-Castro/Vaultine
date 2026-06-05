# AGENTS.md — Vaultine

**Projeto:** Biblioteca dinâmica C++ (.so) POSIX para gerenciamento criptográfico de segredos multi-tenant. v0.3.2-beta.

## Convenções

- C++17, extensões `.cc`/`.h`, namespace `ssm::v1`
- API pública em `include/ssm/ssm.h` (C-compatible `extern "C"`). Headers privados em `src/` ao lado do `.cc`.
- Padrão de erro: `do { ... } while(false)` com `break` no primeiro fallo — sem exceções.
- Wiping: `sodium_memzero` via `secure_erase()`. `secure_alloc()` faz `malloc + mlock`. `secure_vector` também usa `secure_alloc`.
- `secure_string` (RAII) para globals de senha — faz `sodium_memzero` no destructor.
- Username validation: `is_valid_username()` verifica `strlen <= SSM_USERNAME_MAX` (255) em todas APIs.
- `SSM_EXPORT` controla visibilidade de símbolos; `SSM_VISIBILITY_HIDDEN=ON` em Release.

## Comandos

```bash
# Build
cmake -B build && cmake --build build

# Testes (GTest v1.15.2 via FetchContent)
ctest --test-dir build --output-on-failure
# ou direto: ./build/tests/ssm_test

# Release
cmake -B build-release -DCMAKE_BUILD_TYPE=Release && cmake --build build-release

# Lint (CI usa --dry-run -Werror)
find src/ include/ tests/ cli/ -name '*.cc' -o -name '*.h' | xargs clang-format -i

# Fuzzing (clang only)
cmake -B build-fuzz -DCMAKE_C_COMPILER=clang -DSSM_FUZZING=ON && cmake --build build-fuzz
./build-fuzz/tests/fuzz_api -max_total_time=10 -runs=100000 tests/fuzz/corpus/api/

# Benchmarks
cmake -B build-bench -DSSM_BUILD_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build-bench
./build-bench/tests/ssm_bench --benchmark_min_time=0.1
```

## Dependências

```bash
# Debian/Ubuntu
apt install libsqlcipher-dev libsodium-dev libssl-dev libncursesw5-dev cmake pkg-config
# Termux (SQLCipher indisponível — fallback para SQLite puro)
pkg install libsodium openssl sqlite ncursesw cmake ninja
```

## Arquitetura

- **Handle:** `ssm_handle` com `sqlite3*`, `std::shared_mutex`, LRU cache de 256 KEKs wrapping keys
- **Thread-safety:** `SQLITE_OPEN_FULLMUTEX` + `std::unique_lock<std::shared_mutex>` em toda API pública
- **KEK:** AES-KW-256 wrapped, validade 90d, rotação atômica via transação ACID (`BEGIN IMMEDIATE`)
- **Cache:** wrapping keys cacheadas por `username`; `ssm_cache_get_stats()` expõe hit/miss
- **Audit log:** toda operação registra `operation`, `operation_target`, `details`, `result`
- **Validador de senha:** configurável via `ssm_set_password_validator()`; default 4+ chars

## Testes

- SQLite `:memory:` para maioria dos testes; fixtures baseadas em arquivo para expiração KEK e corrupção de tag GCM
- `SsmApiCorruptionTest` corrompe tag GCM direto no DB para testar `SSM_ERR_INTEGRITY`
- Testes de concorrência: `std::thread` com até 10 threads
- CI roda `ctest --timeout 300`, valgrind em Debug, `nm -D` checa ≥8 símbolos exportados em Release

## CodeGraph

O projeto tem índice CodeGraph (`.codegraph/`). Use `codegraph_*` tools para consultas estruturais
(definições, chamadores, callees, impacto) — é mais rápido e preciso que grep.

## CLI

```bash
ssm-cli user register|auth|delete|change-password <username>
ssm-cli secret store|get|delete|list <username> [<name>]
ssm-cli kek rotate <username>
ssm-cli cache-stats
ssm-cli env exec <username> <cmd> [args...]  # injeta SSM_<NAME> como env vars
ssm-cli tui                                  # ncurses interativo
ssm-cli completion [bash|zsh]                # gera script de autocomplete
```
Opções: `--db <path>` (default `./ssm.db`), `--db-key <hex>`, `--password <str>`, `--backup-key <hex64>`, `--api-key <str>`, `--json`.
Environment vars (substituem config, sobrescritas por flags): `SSM_PASSWORD`, `SSM_DB_KEY`, `SSM_BACKUP_KEY`, `SSM_API_KEY`.

## Config File

`ssm-cli` carrega `./vaultine.json` ou `~/.vaultinerc` (JSON). Flags CLI sobrescrevem.
Chaves: `db`, `db_key`, `password`, `backup_key`, `json`. Usar statics `g_cfg_*` para persistência.
Environment vars (substituem config, sobrescritas por flags): `SSM_PASSWORD`, `SSM_DB_KEY`, `SSM_BACKUP_KEY`, `SSM_API_KEY`.
