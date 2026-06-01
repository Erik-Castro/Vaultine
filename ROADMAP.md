# 🗺️ Vaultine Roadmap 2026

> **Visão**: Transformar Vaultine de um projeto alfa bem-estruturado para a **solução padrão de gerenciamento de chaves embarcado** para aplicações que exigem segurança, flexibilidade e zero dependências externas.

---

## 📊 Fases de Desenvolvimento

```
┌─────────────────────────────────────────────────────────────────┐
│ v0.1.0 (ATUAL)                                                  │
│ ✅ API Core completa                                             │
│ ✅ CLI + TUI                                                     │
│ ✅ Python bindings                                               │
│ ⚠️ Testes mínimos | ❌ CI/CD | ❌ Security audit                 │
└─────────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────────┐
│ v0.2.0 (Beta — 2-3 meses)                                       │
│ 🔴 SEGURANÇA: mlock, force password validation, audit logs      │
│ 🟡 QUALIDADE: 80%+ testes, CI/CD, fuzzing                       │
│ 🟢 PERFORMANCE: Cache optimization, benchmark suite             │
└─────────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────────┐
│ v0.3.0 (RC — 4-6 meses)                                         │
│ 🔒 AUDITORIA EXTERNA                                            │
│ 🛠️ TPM integration, backup/restore                              │
│ 📦 Package managers (apt, brew, conan)                          │
└─────────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────────┐
│ v1.0.0 (GA — 6-9 meses)                                         │
│ ✅ PRODUÇÃO-PRONTO                                              │
│ ✅ LTS (Long-Term Support)                                      │
│ ✅ Community ecosystem                                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔴 FASE 1: v0.2.0 — Beta (CRÍTICO)

### 1.1 🔒 Segurança Crítica

#### **1.1.1 Memory Protection (mlock)**
**Prioridade**: 🔴 CRÍTICA | **Esforço**: 1-2 dias | **Risk**: Alto

**Problema**:
- KEK fica em memória durante rotação (~500ms-2s)
- Atacante com acesso root pode fazer memory dump

**Solução**:
```cpp
// src/utils/secure_memory.h
#include <sys/mman.h>

template <typename T>
class secure_buffer {
public:
    secure_buffer(size_t size) {
        data_ = malloc(size);
        mlock(data_, size);  // ← Evita page-out
    }
    
    ~secure_buffer() {
        if (data_) {
            secure_erase(data_, size_);
            munlock(data_, size_);
            free(data_);
        }
    }
private:
    void* data_;
    size_t size_;
};
```

**Tarefas**:
- [ ] Implementar `secure_alloc` com `mlock()`
- [ ] Refatorar `handle->kek` para usar secure_buffer
- [ ] Testes de behavior (mlock falha em non-priveleged)
- [ ] Documentação de limitações (SE Linux, AppArmor)

**Teste**: 
```bash
# Verificar que paging está desabilitado
cat /proc/[pid]/maps | grep -i heap
# Deve mostrar [heap] com VSZ == RSS (não swapped)
```

---

#### **1.1.2 Force Visibility Hidden in Release**
**Prioridade**: 🔴 CRÍTICA | **Esforço**: 4 horas | **Risk**: Médio

**Problema**:
- `SSM_VISIBILITY_HIDDEN=OFF` é default (apenas 11 símbolos expostos)
- Release builds devem forçar `-fvisibility=hidden`

**Solução**:
```cmake
# src/CMakeLists.txt
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(SSM_VISIBILITY_HIDDEN ON CACHE BOOL "" FORCE)
    message(STATUS "Release build: forcing SSM_VISIBILITY_HIDDEN=ON")
endif()
```

**Tarefas**:
- [ ] Modificar CMakeLists.txt
- [ ] Adicionar warning em debug builds
- [ ] Verificar symbol count em release: `nm -D build/libssm.so | grep SSM_EXPORT`

---

#### **1.1.3 Validação de Força de Senha**
**Prioridade**: 🔴 CRÍTICA | **Esforço**: 2-3 dias | **Risk**: Médio

**Problema**:
- Senhas fracas ("123456", "password") comprometem toda segurança
- Vaultine não valida força

**Solução**: Callback de validação (deixar aplicação decidir)

```cpp
// include/ssm/ssm.h
typedef int (*ssm_password_validator)(const char* password, char* error_out, size_t error_len);

ssm_status ssm_set_password_validator(ssm_handle* h, ssm_password_validator validator);
```

**Implementação**:
```cpp
// src/ssm.cc
int default_password_validator(const char* pwd, char* error_out, size_t error_len) {
    size_t len = strlen(pwd);
    
    // Regra padrão: ≥12 chars, pelo menos 3 categorias
    if (len < 12) {
        snprintf(error_out, error_len, "Password must be at least 12 characters");
        return 0;
    }
    
    int categories = 0;
    if (strchr(pwd, 'a')) categories++; // lowercase
    if (strchr(pwd, 'A')) categories++; // uppercase
    if (strchr(pwd, '0')) categories++; // digits
    if (strcspn(pwd, "!@#$%^&*") < len) categories++; // special
    
    if (categories < 3) {
        snprintf(error_out, error_len, "Password must contain at least 3 categories: "
                 "lowercase, uppercase, digits, special");
        return 0;
    }
    
    return 1;  // Valid
}
```

**Tarefas**:
- [ ] Adicionar `ssm_password_validator` callback
- [ ] Validador default com regras NIST SP 800-63
- [ ] Documentação e exemplos
- [ ] Testes com passwords fracas (devem falhar)

---

#### **1.1.4 Audit Log Enhancement**
**Prioridade**: 🟡 ALTA | **Esforço**: 2 dias | **Risk**: Baixo

**Problema**:
- Audit log existe mas é minimal
- Falta detalhes: operação bem-sucedida? Qual secret?

**Schema Atual**:
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    operation TEXT,
    status TEXT,
    timestamp TEXT
);
```

**Schema Novo**:
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    operation TEXT,           -- ex: "secret_store"
    operation_target TEXT,    -- ex: "my-key" (secret name)
    status TEXT,              -- "SSM_OK", "SSM_ERR_AUTH"
    ip_address TEXT,          -- opcional, para future
    user_agent TEXT,          -- opcional
    details TEXT,             -- JSON com contexto
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
);
```

**Detalhes JSON** (exemplo):
```json
{
  "secret_store": {
    "name": "my-key",
    "key_size": 2048,
    "has_public_key": true,
    "description_length": 15
  },
  "secret_get": {
    "name": "my-key",
    "success": true
  },
  "kek_rotate": {
    "secrets_count": 42,
    "duration_ms": 523
  }
}
```

**Tarefas**:
- [ ] Expandir schema `audit_log`
- [ ] Serializar details em JSON
- [ ] Log de todas as 9 operações da API
- [ ] Rotação de logs (ex: manter últimos 90 dias)
- [ ] Query helper: `ssm_audit_log_query()`

---

### 1.2 🧪 Testes & CI/CD

#### **1.2.1 Expand Test Suite (80%+ coverage)**
**Prioridade**: 🔴 CRÍTICA | **Esforço**: 3-4 dias | **Risk**: Baixo

**Testes Faltando**:
```
✅ IMPLEMENTADO:
  - User registration/auth
  - Secret store/get/delete
  - KEK rotation (básico)

❌ FALTANDO (CRÍTICO):
  - [ ] Tag corruption (injetar erro em tag GCM)
  - [ ] KEK expiration (simular passage de tempo)
  - [ ] Rotation failure & rollback
  - [ ] Concurrency stress test (100+ threads)
  - [ ] Password validation integration
  - [ ] Audit log completeness
  
❌ FALTANDO (IMPORTANTE):
  - [ ] Memory leak detection (valgrind/asan)
  - [ ] Performance regression
  - [ ] Schema migration
  - [ ] Backup/restore integrity
  - [ ] Error message clarity
```

**Exemplo: Tag Corruption Test**
```cpp
TEST(AESGCMTest, CorruptedTag) {
    // ... setup ...
    unsigned char ciphertext[64];
    unsigned char tag[16];
    
    // Encrypt secret
    aes_gcm_encrypt(secret, key, nonce, ciphertext, tag);
    
    // Corrupt tag
    tag[0] ^= 0xFF;  // flip all bits
    
    // Decrypt should fail
    unsigned char out[64];
    size_t out_len = sizeof(out);
    EXPECT_NE(aes_gcm_decrypt(ciphertext, sizeof(ciphertext), key, nonce, tag, out, &out_len), 
              AES_GCM_OK);
}
```

**Arquivo**: `tests/ssm_test_extended.cc` (novo)
**Tarefas**:
- [ ] Escrever 50+ casos de teste
- [ ] Usar Google Test + Fixtures
- [ ] SQLite in-memory para speed
- [ ] GitHub Actions para execução automática

---

#### **1.2.2 GitHub Actions CI/CD**
**Prioridade**: 🔴 CRÍTICA | **Esforço**: 1 dia | **Risk**: Baixo

**Workflow**: `.github/workflows/ci.yml`

```yaml
name: CI/CD

on: [push, pull_request]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        build-type: [Debug, Release]
        compiler: [gcc, clang]
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          sudo apt update
          sudo apt install -y libsqlcipher-dev libsodium-dev libssl-dev \
                             libncursesw5-dev cmake pkg-config build-essential \
                             valgrind google-perftools-dev
      
      - name: Build
        run: |
          cmake -B build -DCMAKE_BUILD_TYPE=${{ matrix.build-type }} \
                -DCMAKE_C_COMPILER=${{ matrix.compiler == 'gcc' && 'gcc' || 'clang' }}
          cmake --build build
      
      - name: Run tests
        run: ctest --test-dir build --output-on-failure
      
      - name: Memory leak check (debug)
        if: matrix.build-type == 'Debug'
        run: valgrind --leak-check=full --error-exitcode=1 ./build/tests/ssm_test
      
      - name: Code coverage
        if: matrix.compiler == 'gcc'
        run: |
          apt install -y gcov lcov
          cmake -B build-cov -DCMAKE_CXX_FLAGS="--coverage"
          cmake --build build-cov
          ctest --test-dir build-cov
          lcov --directory build-cov --capture --output-file coverage.lcov
          lcov --remove coverage.lcov '/usr/*' --output-file coverage.lcov
          echo "Coverage: $(lcov --summary coverage.lcov | tail -1)"
      
      - name: Static analysis
        run: |
          sudo apt install -y clang-tools
          run-clang-tidy -p build src/
      
      - name: Release build symbol check
        run: |
          nm -D build/libssm.so | grep "SSM_EXPORT" | wc -l
          # Should output exactly 11 (or your expected count)

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Format check
        run: |
          sudo apt install -y clang-format
          find src/ include/ tests/ cli/ -name '*.cc' -o -name '*.h' | \
            xargs clang-format --dry-run -Werror

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Dependency check
        run: |
          # Check for hardcoded secrets
          grep -r "password\s*=" src/ && exit 1 || true
          grep -r "secret\s*=" src/ && exit 1 || true
          echo "No hardcoded secrets found ✓"
```

**Tarefas**:
- [ ] Criar `.github/workflows/ci.yml`
- [ ] Testar localmente (`act`)
- [ ] Adicionar badge em README
- [ ] Configurar branch protection rules

---

#### **1.2.3 Fuzzing com libFuzzer**
**Prioridade**: 🟡 ALTA | **Esforço**: 2 dias | **Risk**: Baixo

**Targets**:
- CLI argument parser
- Secret store input validation
- Password validation

**Exemplo**: `tests/fuzz_cli.cc`
```cpp
#include <cstddef>
#include <cstdint>

extern "C" int fuzz_cli_parse(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fuzz_cli_parse(data, size);
    return 0;
}
```

**Build**:
```bash
clang++ -fsanitize=fuzzer,address tests/fuzz_cli.cc -o fuzz_cli
./fuzz_cli -max_len=1024 corpus/
```

**Tarefas**:
- [ ] Criar `tests/fuzz_*.cc`
- [ ] CI integration (OSS-Fuzz)
- [ ] Seed corpus

---

### 1.3 ⚡ Performance & Otimizações

#### **1.3.1 Cache Statistics**
**Prioridade**: 🟡 ALTA | **Esforço**: 1 dia | **Risk**: Baixo

**Problema**: 
- Cache LRU existe mas sem visibilidade
- Não sabemos hit rate em produção

**Solução**: Expor estatísticas

```cpp
// include/ssm/ssm.h
struct ssm_cache_stats {
    size_t total_lookups;
    size_t hits;
    size_t misses;
    float hit_rate_percent;
};

ssm_status ssm_cache_get_stats(ssm_handle* h, ssm_cache_stats* out);
```

**CLI**:
```bash
ssm-cli --db app.db cache-stats
# Output:
# Cache Statistics:
#   Total lookups: 1024
#   Hits: 902 (88.1%)
#   Misses: 122 (11.9%)
#   Avg lookup time: 0.2µs
```

**Tarefas**:
- [ ] Adicionar contadores no handle
- [ ] Implementar `ssm_cache_get_stats()`
- [ ] CLI display
- [ ] Tests

---

#### **1.3.2 Benchmark Suite**
**Prioridade**: 🟡 ALTA | **Esforço**: 1.5 dias | **Risk**: Baixo

**Arquivo**: `tests/bench_ssm.cc`

```cpp
#include <benchmark/benchmark.h>

static void BenchUserRegister(benchmark::State& state) {
    ssm_handle* h = nullptr;
    ssm_init(&h, ":memory:", nullptr, 0);
    
    for (auto _ : state) {
        ssm_user_register(h, "alice", "p@ssw0rd");
        // cleanup...
    }
    
    ssm_destroy(h);
}
BENCHMARK(BenchUserRegister);

static void BenchSecretGet(benchmark::State& state) {
    // ... setup ...
    for (auto _ : state) {
        ssm_secret_get(h, "alice", "my-key", ...);
    }
}
BENCHMARK(BenchSecretGet);

BENCHMARK_MAIN();
```

**Tarefas**:
- [ ] Integrar Google Benchmark
- [ ] Rodas em CI (não falha, apenas log)
- [ ] Track histórico (graph em README)

---

### 1.4 📚 Documentação

#### **1.4.1 Security Policy**
**Prioridade**: 🟡 ALTA | **Esforço**: 4 horas | **Risk**: Nenhum

**Arquivo**: `SECURITY.md`

```markdown
# Security Policy

## Reporting a Vulnerability

Please **DO NOT** open a public issue for security vulnerabilities.

Instead, email: security@vaultine.dev with:
- Description of vulnerability
- Affected versions
- Steps to reproduce
- Proof of concept (if available)

We will:
1. Confirm receipt within 24 hours
2. Investigate within 72 hours
3. Release patch within 5 days
4. Credit reporter (unless declined)

## Security Considerations

### What Vaultine Protects
- ✅ Secrets at rest (AES-GCM-256)
- ✅ Multi-tenant isolation
- ✅ Integrity verification
- ✅ Forward secrecy via key rotation

### What Vaultine Does NOT Protect
- ❌ Secrets in application memory (after decryption)
- ❌ Root-level attacks (kernel compromise)
- ❌ Weak passwords
- ❌ Side-channel attacks (timing)

### Recommendations for Deployment

1. **Use mlock()** to prevent swap
2. **Enforce password policy** (≥12 chars, 3+ categories)
3. **Enable SELinux/AppArmor** confinement
4. **Monitor audit logs** for unauthorized access
5. **Rotate KEK periodically** (90 days minimum)
6. **Keep OS patched** (no PII in kernel logs)

## Supported Versions

| Version | Release | Supported | 
|---------|---------|-----------|
| 1.0.x   | TBD     | ✅ Yes    |
| 0.3.x   | TBD     | ✅ Yes    |
| 0.2.x   | TBD     | ✅ Yes    |
| 0.1.x   | 2026-06 | ❌ No     |
```

**Tarefas**:
- [ ] Criar `SECURITY.md`
- [ ] Setup security@vaultine.dev email
- [ ] GitHub secret management

---

#### **1.4.2 Contributing Guide**
**Prioridade**: 🟡 ALTA | **Esforço**: 4 horas | **Risk**: Nenhum

**Arquivo**: `CONTRIBUTING.md`

```markdown
# Contributing to Vaultine

## Code of Conduct
Be respectful, inclusive, and professional.

## Development Setup

```bash
git clone https://github.com/Erik-Castro/Vaultine.git
cd Vaultine
cmake -B build -DSSM_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```

## Submission Guidelines

1. **Create issue** describing problem/feature
2. **Create branch**: `git checkout -b feature/my-feature`
3. **Write tests** for new code
4. **Format code**: `clang-format -i src/**/*.cc`
5. **Run linter**: `clang-tidy -p build src/`
6. **Create PR** with clear description

## Testing Requirements

All PRs must pass:
- ✅ Unit tests (ctest)
- ✅ Integration tests
- ✅ clang-format check
- ✅ clang-tidy check
- ✅ valgrind memory check (if modified memory management)

## Security Guidelines

- No hardcoded secrets
- Use `secure_erase` for sensitive data
- Document new algorithms
- Run through threat model checklist
```

**Tarefas**:
- [ ] Criar `CONTRIBUTING.md`
- [ ] PR template em `.github/pull_request_template.md`
- [ ] Issue templates

---

---

## 🟡 FASE 2: v0.3.0 — Release Candidate (4-6 meses)

### 2.1 🔐 Segurança Avançada

#### **2.1.1 TPM Integration (Opcional)**
**Prioridade**: 🟡 ALTA | **Esforço**: 5-7 dias | **Risk**: Médio

**Objetivo**: Usar TPM para proteger KEK mestre (uma por host)

**Modo TPM**:
```
Sem TPM:
  Password → Argon2id → wrapping_key → AES-KW → KEK → AES-GCM → Secret
  
Com TPM:
  Password → Argon2id → wrapping_key → AES-KW → KEK
  KEK → TPM_Seal → KEK_sealed (específico do host)
  
  On retrieve: TPM_Unseal → KEK
```

**Implementação**:
```cpp
// src/tpm/tpm.h
#ifdef SSM_TPM_ENABLED
typedef int (*ssm_tpm_seal_cb)(const unsigned char* data, size_t len,
                               unsigned char* sealed_out, size_t* sealed_len);
typedef int (*ssm_tpm_unseal_cb)(const unsigned char* sealed, size_t len,
                                 unsigned char* data_out, size_t* data_len);

ssm_status ssm_tpm_register_callbacks(ssm_tpm_seal_cb seal, ssm_tpm_unseal_cb unseal);
#endif
```

**Benefícios**:
- ✅ KEK nunca sai do host (mesmo em backup)
- ✅ Ataque de offline password guessing falha (TPM não funciona offline)

**Desafios**:
- ⚠️ Nem todo sistema tem TPM
- ⚠️ Fallback para software mode necessário

**Tarefas**:
- [ ] Implementar TPM 2.0 sealing (usar tpm2-tools)
- [ ] Callback mechanism
- [ ] Graceful fallback (warn in logs)
- [ ] Documentation + examples
- [ ] Tests (mock TPM)

---

#### **2.1.2 Backup/Restore com Integridade**
**Prioridade**: 🟡 ALTA | **Esforço**: 3-4 dias | **Risk**: Médio

**Problema**:
- Usuário precisa fazer backup do DB
- Mas quer garantia de integridade + autenticidade

**Solução**: Backup assinado + versionado

```cpp
// include/ssm/ssm.h
typedef enum {
    SSM_BACKUP_V1 = 1
} ssm_backup_version;

ssm_status ssm_backup_create(ssm_handle* h, const char* backup_path, 
                             const unsigned char* backup_key, size_t backup_key_len);

ssm_status ssm_backup_restore(ssm_handle* h, const char* backup_path,
                              const unsigned char* backup_key, size_t backup_key_len);
```

**Formato Backup**:
```
[Header (16B)]
  - Magic: "VAULTBKP" (8B)
  - Version: 1 (2B)
  - Created: timestamp (4B)
  - Reserved: (2B)

[Ciphertext]
  - sqlite.db (encrypted with backup_key)

[Integrity]
  - HMAC-SHA256(header + ciphertext, backup_key)
```

**Tarefas**:
- [ ] Implementar backup format
- [ ] CLI: `ssm-cli backup create/restore`
- [ ] Integrity validation
- [ ] Tests (corruption detection)

---

### 2.2 🛠️ Recursos

#### **2.2.1 Schema Migration**
**Prioridade**: 🟡 MÉDIA | **Esforço**: 3-4 dias | **Risk**: Alto

**Objetivo**: Suportar upgrade de schema sem perder dados

**Implementação**:
```cpp
// src/db/migrations.cc
struct migration {
    int from_version;
    int to_version;
    const char* sql;
};

static const migration migrations[] = {
    {1, 2, "ALTER TABLE secrets ADD COLUMN compression_algorithm TEXT;"},
    {2, 3, "CREATE INDEX idx_secrets_user_id ON secrets(user_id);"},
};
```

**Tarefas**:
- [ ] Versioning schema (schema_version em user_data)
- [ ] Migration registry
- [ ] Rollback capability
- [ ] Tests (forward/backward)

---

#### **2.2.2 Database Export (JSON/CSV)**
**Prioridade**: 🟠 BAIXA | **Esforço**: 2-3 dias | **Risk**: Baixo

**Objetivo**: Exportar metadados (não secrets!) para análise

```bash
ssm-cli export --format json --output report.json
# {
#   "users": [{"username": "alice", "created_at": "..."}],
#   "secrets": [{"user": "alice", "name": "key1", "size": 2048, "updated_at": "..."}],
#   "kek_metadata": [{"user": "alice", "expires_at": "..."}]
# }
```

**Tarefas**:
- [ ] JSON exporter
- [ ] CSV exporter
- [ ] PII redaction
- [ ] Tests

---

### 2.3 📦 Distribution

#### **2.3.1 Package Managers**
**Prioridade**: 🟡 ALTA | **Esforço**: 2-3 dias | **Risk**: Baixo

**Targets**:
- APT (Debian/Ubuntu)
- Homebrew (macOS)
- Conan (C++)

**APT Recipe** (debian/control):
```
Package: libssm0
Version: 0.3.0
Architecture: amd64
Depends: libsqlcipher0, libsodium23, libssl3
Maintainer: Erik Castro <erik@vaultine.dev>
Description: Cryptographic secrets management library for POSIX systems
 Vaultine is a C++ library for managing encryption keys with per-tenant
 isolation, automatic key rotation, and atomic operations.
```

**Homebrew Formula** (libssm.rb):
```ruby
class Libssm < Formula
  desc "Cryptographic secrets management library"
  homepage "https://github.com/Erik-Castro/Vaultine"
  url "https://github.com/Erik-Castro/Vaultine/archive/v0.3.0.tar.gz"
  
  depends_on "sqlcipher"
  depends_on "libsodium"
  depends_on "openssl"
  
  def install
    system "cmake", "-B", "build", *std_cmake_args
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end
end
```

**Tarefas**:
- [ ] Debian package (sbuild)
- [ ] Homebrew formula
- [ ] Conan recipe
- [ ] CI: automated releases

---

#### **2.3.2 Docker Image**
**Prioridade**: 🟠 BAIXA | **Esforço**: 1-2 dias | **Risk**: Baixo

**Arquivo**: `Dockerfile`

```dockerfile
FROM debian:bookworm-slim

RUN apt update && apt install -y \
    libsqlcipher0 libsodium23 libssl3 libncursesw6

COPY --from=builder /usr/local/lib/libssm.so.0.3.0 /usr/local/lib/
COPY --from=builder /usr/local/bin/ssm-cli /usr/local/bin/

ENV LD_LIBRARY_PATH=/usr/local/lib

ENTRYPOINT ["ssm-cli"]
CMD ["--help"]
```

**Tarefas**:
- [ ] Dockerfile (multi-stage)
- [ ] Docker Hub image
- [ ] CI: push on release

---

---

## 🟢 FASE 3: v1.0.0 — GA / Production (6-9 meses)

### 3.1 🔍 Auditoria & Certificação

#### **3.1.1 Segurança Audit Profissional**
**Prioridade**: 🔴 CRÍTICA | **Esforço**: 2-4 semanas | **Risk**: N/A

**Escopo**:
- Revisão de design criptográfico
- Análise de código (memory safety)
- Teste de penetração
- Threat modeling validation

**Candidatos**:
- Cure53 (~$20-40K)
- Trail of Bits (~$15-30K)
- NCCGROUP (~$25-50K)

**Tarefas**:
- [ ] RFP preparation
- [ ] Vendor selection
- [ ] Audit execution
- [ ] Remediate findings
- [ ] Publish report (se permitido)

---

#### **3.1.2 Conformidade FIPS 140-2 (Optional)**
**Prioridade**: 🟠 MÉDIA | **Esforço**: 4-8 semanas | **Risk**: Alto

**Nota**: FIPS é caro (~$10-15K). Considerar apenas se mercado exigir.

**Alternativa**: Use OpenSSL FIPS provider (free)

```cmake
set(SSM_USE_OPENSSL_FIPS ON)  # Link com openssl-provider-fips
```

---

### 3.2 🌍 Community & Ecosystem

#### **3.2.1 Language Bindings**
**Prioridade**: 🟡 ALTA | **Esforço**: 1 semana (por linguagem)

**Bindings Sugeridos**:
- ✅ Python (ctypes) — v0.2
- 🔜 Rust (bindgen)
- 🔜 Go (cgo)
- 🔜 Node.js (NAPI)
- 🔜 Java (JNI)

**Exemplo Rust**:
```rust
// vaultine-rs/src/lib.rs
#[link(name = "ssm")]
extern "C" { ... }

pub struct VaultineHandle(*mut std::ffi::c_void);

impl VaultineHandle {
    pub fn new(db_path: &str) -> Result<Self> { ... }
    pub fn user_register(&self, username: &str, password: &str) -> Result<()> { ... }
}
```

**Publicação**:
- crates.io (Rust)
- PyPI (Python)
- npm (Node.js)

**Tarefas por linguagem**:
- [ ] Auto-generate bindings (or manual)
- [ ] Examples + documentation
- [ ] Integration tests
- [ ] Package registry publication

---

#### **3.2.2 Community Hub**
**Prioridade**: 🟡 ALTA | **Esforço**: 2-3 dias

**Ações**:
- [ ] GitHub Discussions (enable)
- [ ] Discord server (opcional)
- [ ] Forum (ou GitHub Discussions)
- [ ] FAQ section in README
- [ ] Blog (security tips, tutorials)

---

### 3.3 📈 Marketing & Adoption

#### **3.3.1 Apresentações & Conferências**
**Prioridade**: 🟡 ALTA | **Esforço**: 2 semanas/conf

**Eventos Alvo**:
- RustSec Summit
- OWASP AppSec
- CppCon / C++ Security
- OffensiveCon

**Formato**:
- Talk: "Vaultine: Per-Tenant Key Management at Scale"
- Workshop: "Building Cryptographic Applications Safely"

---

#### **3.3.2 Case Studies & Blog**
**Prioridade**: 🟠 MÉDIA | **Esforço**: 2-3 dias/post

**Posts Sugeridos**:
1. "Why We Built Vaultine" (rationale)
2. "Key Rotation: Why It Matters" (technical deep-dive)
3. "Cryptographic Best Practices for C++" (educational)
4. "Performance Benchmarks: Vaultine vs. Vault vs. AWS KMS"

**Tarefas**:
- [ ] Setup blog (GitHub Pages + Jekyll)
- [ ] Write 3-4 technical posts
- [ ] Share on HackerNews, Reddit, etc.

---

---

## 📋 Matriz de Prioridade

```
              Impacto Baixo    Médio           Alto
Esforço ┌───────────────────┬──────────────┬──────────────┐
Baixo   │                   │  1.3.1       │  1.1.2       │
        │                   │  1.3.2       │  1.2.3       │
        │                   │  1.4.1       │  1.2.2       │
        │                   │  1.4.2       │              │
        ├───────────────────┼──────────────┼──────────────┤
Médio   │  2.2.2            │  2.1.2       │  1.1.1       │
        │  3.2.2            │  2.2.1       │  1.1.3       │
        │  3.3.2            │  2.3.1       │  1.2.1       │
        │                   │  3.1.2       │              │
        ├───────────────────┼──────────────┼──────────────┤
Alto    │                   │              │  1.1.4       │
        │                   │              │  1.2.2       │
        │                   │              │  3.1.1       │
        │                   │              │  3.2.1       │
        └───────────────────┴──────────────┴──────────────┘
```

---

## 🎯 Quick Reference: Feature Checklist

### v0.2.0 Beta (DO NOW)
- [ ] **Security**: mlock + password validation + audit logs
- [ ] **Testing**: 80%+ coverage, CI/CD pipeline, fuzzing
- [ ] **Performance**: Cache stats, benchmark suite
- [ ] **Documentation**: SECURITY.md, CONTRIBUTING.md

### v0.3.0 RC
- [ ] **Advanced**: TPM integration, backup/restore, schema migration
- [ ] **Distribution**: APT, Homebrew, Conan, Docker
- [ ] **Community**: GitHub Discussions, FAQ

### v1.0.0 GA
- [ ] **Audit**: Third-party security review
- [ ] **Bindings**: Rust, Go, Node.js
- [ ] **Visibility**: Conferences, blog, case studies

---

## 📊 Timeline Visual

```
JUN         AUG         OCT         DEC         FEB
|-----------|-----------|-----------|-----------|-----------|
v0.1.0      v0.2.0-beta v0.2.0-rc  v0.3.0-rc  v0.3.0-final
(NOW)       +mlock      +tpm       +audit
            +tests      +backup    +community
            +ci/cd      +distro

                                                    v1.0.0 (MAR)
                                                    + audit
                                                    + bindings
                                                    + LTS
```

---

## 💡 Success Metrics

| Métrica | v0.2.0 | v0.3.0 | v1.0.0 |
|---------|--------|--------|--------|
| **Test Coverage** | 80%+ | 90%+ | 95%+ |
| **CI/CD** | ✅ | ✅ | ✅ |
| **Security Issues** | 0 | 0 | 0 |
| **GitHub Stars** | 50+ | 500+ | 2000+ |
| **PyPI Downloads** | N/A | 100+ | 1000+/month |
| **Security Audit** | ❌ | Pending | ✅ Complete |
| **Production Users** | 0 | 5-10 | 50+ |

---

## 📞 Coordenação & Responsabilidades

Sugestão de organização:

| Role | Responsibilidade |
|------|------------------|
| **Tech Lead** | Architecture decisions, security review |
| **Dev Lead** | Code quality, testing strategy |
| **Security Lead** | Threat modeling, audit coordination |
| **DevOps Lead** | CI/CD, distribution, deployments |
| **Community Lead** | Docs, bindings, marketing |

Para projeto de 1 pessoa (você): Priorize **1.1 + 1.2** primeiro (segurança + qualidade).

---

## 🚀 Call to Action

**Próximos 7 dias**:
1. ✅ Comitar este ROADMAP.md
2. ⚠️ Criar Issues para v0.2.0 (use Template abaixo)
3. 📌 Abrir milestone no GitHub

**Template de Issue**:
```markdown
## v0.2.0 Milestone

### 1.1 Security
- [ ] #<issue_id>: mlock implementation
- [ ] #<issue_id>: Password validation
- [ ] #<issue_id>: Audit log enhancement

### 1.2 Testing & CI/CD
- [ ] #<issue_id>: Expand test suite
- [ ] #<issue_id>: GitHub Actions setup
- [ ] #<issue_id>: Fuzzing integration

### 1.3 Performance
- [ ] #<issue_id>: Cache statistics
- [ ] #<issue_id>: Benchmark suite

### 1.4 Documentation
- [ ] #<issue_id>: SECURITY.md
- [ ] #<issue_id>: CONTRIBUTING.md
```

---

**Vaultine em 2026: do "projeto legal de segurança" para "padrão de ouro em key management embarcado"** 🔐

