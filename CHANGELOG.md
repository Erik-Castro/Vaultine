# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
e este projeto segue [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.1-beta] — 2026-06-03

### 🔧 Otimizações & Correções (33 itens)

#### 🐛 Bugs & Segurança (P0 — 7/7)
- **Transaction leak**: `BEGIN IMMEDIATE` movido após alocações em `kek.cc`
- **const_cast UB**: `aes_gcm.cc` copia tag GCM antes de passar para OpenSSL
- **Json::CharReader leak**: `ssm_server.cc` substituído por `unique_ptr`
- **Fuzz underflow**: `fuzz_password.cc` guard para `pos >= size`
- **Key separation**: `backup.cc` deriva `enc_key` + `hmac_key` via SHA-256 domain separation
- **Argon2id API**: parâmetros `salt`/`salt_len` removidos (eram ignorados)
- **Integer overflow**: `secure_memory.h` guards em secure_buffer/vector alocações

#### ⚡ Performance (P1 — 8/8)
- **kek.cc**: `sqlite3_prepare` movido para fora do loop re-encrypt
- **kek.cc**: buffers pré-alocados por KEK em vez de por iteração
- **URI parsing**: `ssm_server.cc` usa `string_view` (elimina O(n²) erase)
- **Stack→heap**: arrays de 128KB substituídos por `std::vector` em `ssm_server.cc`
- **AES-GCM**: `EVP_CIPHER_CTX` thread-local reusado em vez de alocado por operação
- **secrets.cc**: `reserve(64)` em buffer de saída
- **backup.cc**: HMAC streaming (pipeline encrypt+mac)

#### 🧹 Qualidade de Código (P2 — 15/17)
- **getpass seguro**: `ssm_cli.cc` aloca senha no heap + `sodium_memzero`
- **Backup key wiped**: stack de `ssm_server.cc` limpo após uso
- **strncpy→snprintf**: garante null-termination em `ssm_server.cc`
- **hex_decode**: raw `new[]` substituído por `std::vector` em `hex_utils.h`
- **ssm_cli.cc**: 3 ocorrências de raw `new[]`/`delete[]` convertidas para `std::vector`
- **atoll→strtol/strtoll**: validação de erro adicionada em `ssm_server.cc` e `ssm_cli.cc`
- **C-casts→static_cast**: 6 ocorrências em `ssm_server.cc`
- **volatile wipe→sodium_memzero**: `ssm_cli.cc` usa função segura
- **Dead code removido**: `secrets_list` (apenas `secrets_list_for_user` usada)
- **std::size**: `sizeof`/`sizeof` substituído em `migrations.cc`
- **strdup→std::string**: `AuditLogTest` em `ssm_test.cc`
- **sodium_init centralizado**: removido de 3 leaf functions, chamado uma vez em `ssm_init`
- **Forward-declare types**: `export.h` evita incluir `ssm.h` inteiro
- **std::array**: `migrations.h` substitui raw C array + count
- **Benchmark checks**: `SkipWithError` adicionado em `bench_ssm.cc`

#### 🏗️ Build & Infra (P3 — 3/3)
- **Comentário CMake**: desatualizado sobre visibility
- **PCH**: `<shared_mutex>` adicionado ao precompiled header
- **Backup format breaking**: `timestamp` uint32→uint64, `BACKUP_VERSION` 1→2

### ⚠️ Nota de Breaking Change
- **Backup v1 incompatível**: backups criados com v0.3.0-beta ou anterior não podem ser restaurados nesta versão. Use v0.3.0-beta para restaurar backups antigos antes de atualizar.

---

## [0.3.0-beta] — 2026-06-03

### 🎉 Adicionado

#### 🔒 Segurança
- ✅ **Backup/Restore**: AES-256-GCM + HMAC-SHA256 backup format, 12 testes
- ✅ **Schema Migration**: `PRAGMA user_version` tracking, migration v1→v2, rollback capability, 9 testes
- ✅ **Database Export (JSON/CSV)**: metadata export streaming via callback, PII redaction, 11 testes
- ✅ **Error Message Clarity**: `ssm_status_to_string` para todos os 6 status; null-handle checks em 9 APIs
- ✅ **User Enumeration Fix**: `ssm_user_register` retorna `SSM_OK` para username duplicado

#### 🧪 Qualidade & CI/CD
- ✅ **182 testes passando** (era 139 no rc1)
- ✅ **Memory Leak Detection**: `cmake/Sanitizer.cmake` com `-DSSM_SANITIZE=ON` (ASan+UBSan)
- ✅ **Valgrind Suppressions**: expandido para OpenSSL, SQLCipher, ncurses, libstdc++
- ✅ **Fuzzing Targets**: `fuzz_api`, `fuzz_cli` (hex decode), `fuzz_password` (user lifecycle)
- ✅ **Benchmark Suite**: 10 benchmarks (BM_KekRotate, BM_SecretList, BM_ChangePassword, BM_ConcurrentReads)
- ✅ **Benchmark Delta Tool**: `tools/bench_compare.py` para comparação JSON

#### 🌐 REST API Server
- ✅ **REST API (libevent evhttp + jsoncpp)**: 17 endpoints sob `/v1/*`
  - `GET /v1/health`, `GET /v1/version`
  - `POST /v1/users/<user>/register|auth`, `DELETE /v1/users/<user>`, `PUT /v1/users/<user>/password`
  - `GET|POST /v1/users/<user>/secrets`, `GET|DELETE /v1/users/<user>/secrets/<name>`
  - `POST /v1/users/<user>/kek/rotate`
  - `POST /v1/backup/create|restore`
  - `GET /v1/audit`, `GET /v1/export`
  - `GET /v1/cache/stats`, `GET /v1/db/version`, `POST /v1/db/migrate`
- ✅ **Daemonize**: double-fork + setsid + pidfile (`--daemonize`)
- ✅ **Signal handling**: SIGINT/SIGTERM graceful shutdown
- ✅ **CLI dispatch**: `ssm-cli server start [--port] [--host] [--daemonize] [--pidfile]`

#### 📚 Documentação
- ✅ **PR/Issue Templates**: SDD checklist, security contact config
- ✅ **ROADMAP sync**: itens 1.1.4, 1.2.1, 1.2.3, 1.3.2, 2.1.2, 2.2.1, 2.2.2 marcados como concluídos

### 🔧 Alterado

- ⚠️ `ssm_user_register` agora não diferencia "usuário já existe" de "registrado" (anti-enumeration)
- ⚠️ `cli/hex_utils.h` extraído de `ssm_cli.cc` para `hex_decode`/`hex_val` compartilhados
- ⚠️ `tests/valgrind.supp` expandido com supressões de terceiros
- ⚠️ Schemas SQLite agora versionados via `PRAGMA user_version`

### 🐛 Corrigido

- `strdup` → `malloc` + `memcpy` para compatibilidade POSIX
- CI job sem `-DSSM_BUILD_TESTS=OFF` nos targets bench/fuzz

### ⚠️ Deprecado

- ❌ Nenhum

### 🗑️ Removido

- ❌ Nenhum

### ✋ Conhecidos

- ⏳ TPM integration (2.1.1) — postergado
- ⏳ Package Managers (2.3.1) — postergado
- ⏳ Docker Image (2.3.2) — postergado
- 🟡 Rotação de KEK é O(n) — para usuários com 10k+ segredos pode levar 2s+

---

## [0.2.0-rc1] — 2026-06-01

### 🎉 Adicionado

#### 🔒 Segurança
- ✅ **mlock() Memory Protection**: KEK e buffers sensíveis são bloqueados em memória (evita page-out para swap)
- ✅ **Force Visibility Hidden**: Release builds agora forçam `-fvisibility=hidden` (apenas 11 símbolos públicos)
- ✅ **Password Validation**: Callback para validação de força de senha (aplicação define política)
- ✅ **Audit Log Enhancement**: Logs expandidos com `operation_target`, `details` JSON, timestamps UTC

#### 🧪 Qualidade & CI/CD
- ✅ **Comprehensive Test Suite**: 139 testes passando (80%+ coverage)
  - Tag corruption tests (GCM integrity)
  - KEK expiration tests
  - Rotation failure & rollback tests
  - Concurrency stress tests (10+ threads)
  - Password validation integration tests
  - Audit log completeness tests (13 test cases)
  - Cache statistics tests
  - secure_buffer RAII tests
  - secure_vector resize/move tests

- ✅ **GitHub Actions CI/CD**: `.github/workflows/ci.yml`
  - Multi-platform builds (gcc/clang, Debug/Release)
  - Automated test execution
  - Memory leak detection (valgrind)
  - Code coverage reporting (lcov)
  - Static analysis (clang-tidy)
  - Security scanning (hardcoded secrets check)

#### ⚡ Performance
- ✅ **Cache Statistics API**: `ssm_cache_get_stats()` expõe hit rate, misses, lookups
- ✅ **CLI Cache Display**: `ssm-cli cache-stats` mostra estatísticas em tempo real
- ✅ **TUI Cache Screen**: Novo menu "Cache Statistics" em `ssm-cli tui`

#### 📚 Documentação
- ✅ **SECURITY.md**: Vulnerability disclosure policy, deployment recommendations
- ✅ **CONTRIBUTING.md**: Development guidelines, testing requirements, PR workflow
- ✅ **ROADMAP.md**: 3-phase development plan (v0.2, v0.3, v1.0) com 9 meses de planejamento
- ✅ **AGENTS.md**: Instructions para AI/agents com guias de segurança

### 🔧 Alterado

- ⚠️ Audit log schema: Adicionadas colunas `operation_target` e `details`
- ⚠️ TUI menu: Adicionado novo item "Cache Statistics" (agora 6 opções no menu principal)
- ⚠️ CMake: `SSM_VISIBILITY_HIDDEN` agora é forçado em `CMAKE_BUILD_TYPE=Release`
- 🟡 Password validation: Mínimo de 4 caracteres (default; aplicação pode customizar via callback)

### 🐛 Corrigido

- Proteção de memória contra memory dumps (mlock)
- Vazamento de símbolos internos em release builds
- Senhas muito fracas podendo ser usadas
- Falta de visibilidade de logs de auditoria

### ⚠️ Deprecado

- ❌ Nenhum

### 🗑️ Removido

- ❌ Nenhum

### ✋ Conhecidos

- ⏳ Fuzzing com libFuzzer ainda não integrado (próximo sprint)
- ⏳ Benchmark suite com Google Benchmark ainda não implementada
- ⏳ JSON serialization de audit logs usa texto simples (será migrado em v0.3)
- ⏳ Branch protection rules não estão configuradas no GitHub
- 🟡 Rotação de KEK é O(n) — para usuários com 10k+ segredos pode levar 2s+

---

## [0.1.0] — 2026-05-15 (Inicial)

### 🎉 Adicionado

#### 🔐 Core Features
- ✅ Multi-tenant secrets management com per-user KEK
- ✅ AES-KW-256 para proteção de KEK
- ✅ AES-GCM-256 AEAD para criptografia de segredos
- ✅ Argon2id password hashing (NIST SP 800-63B)
- ✅ 90-day KEK rotation cycle (configurável)
- ✅ ACID-compliant atomic operations (SQLite BEGIN IMMEDIATE)
- ✅ LRU cache de 256 entradas para chaves de wrapping

#### 🎯 API Pública
- ✅ `ssm_init` / `ssm_destroy`
- ✅ `ssm_user_register` / `ssm_user_authenticate` / `ssm_user_delete` / `ssm_user_change_password`
- ✅ `ssm_secret_store` / `ssm_secret_get` / `ssm_secret_delete` / `ssm_secret_list`
- ✅ `ssm_kek_rotate`
- ✅ `ssm_status_to_string`

#### 🖥️ Interfaces
- ✅ CLI (`ssm-cli`): user, secret, kek, env, tui subcommands
- ✅ TUI (ncurses): Interactive menu-driven interface para todas operações
- ✅ JSON output (`--json` flag) para automation
- ✅ Suporte a stdin para senhas (`--password` flag)

#### 📦 Bindings
- ✅ Python ctypes binding com context manager

#### 🗄️ Database
- ✅ SQLite schema com users, kek_metadata, secrets, audit_log tables
- ✅ SQLCipher support (AES-256 at-rest encryption)
- ✅ ON DELETE CASCADE para consistency

#### 🧪 Testing
- ✅ Google Test framework
- ✅ 100+ test cases covering core functionality

#### 📚 Documentation
- ✅ README.md (30KB) com exemplos completos
- ✅ WHITEPAPER.md/pt-BR (24-28KB) com threat model e design details
- ✅ API reference com C, Rust, Go, Node.js, Python examples

---

## Licença

MIT License — Copyright (c) 2026 Vaultine

Veja [LICENSE](LICENSE) para detalhes.
