# Vaultine — Gestão de Segredos Multi-Tenant

<p align="center">
  <a href="assets/vaultine-logo.svg"><img src="assets/vaultine-logo.svg" alt="Vaultine Logo" width="200" height="200"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.3.0--beta-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square&logo=c%2B%2B" alt="C++17">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build">
  <img src="https://img.shields.io/badge/tests-182%20passing-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-82%25-yellow?style=flat-square" alt="Coverage">
  <img src="https://img.shields.io/badge/security-audit%20pending-orange?style=flat-square" alt="Security">
</p>

Biblioteca dinâmica C++ (.so) POSIX para gerenciamento criptográfico de segredos multi-tenant com SQLCipher.

## Índice

- [Visão Geral](#visão-geral)
- [Stack](#stack)
- [Build](#build)
- [API Pública](#api-pública)
- [Exemplos](#exemplos)
- [Hierarquia Criptográfica](#hierarquia-criptográfica)
- [Wrapping Key Cache](#wrapping-key-cache)
- [Ciclo de Vida da KEK](#ciclo-de-vida-da-kek)
- [Thread Safety](#thread-safety)
- [Audit Log](#audit-log)
- [Schema SQLite](#schema-sqlite)
- [Bindings](#bindings)

---

## Visão Geral

Vaultine é um cofre de chaves criptográficas multi-tenant. Cada usuário possui um **KEK** (Key Encryption Key) de 256-bit que protege todos os seus segredos. O KEK é armazenado **wrapped** (AES-KW-256) e só é deswrapped em memória durante operações, usando uma chave derivada do hash de autenticação do usuário + salt.

### Conceitos

| Conceito | Descrição |
|----------|-----------|
| **KEK** | Key Encryption Key — 256-bit aleatório, único por usuário |
| **Wrapping Key** | Chave derivada de `auth_hash + salt` via Argon2id, usada para AES-KW-256 |
| **Auth Hash** | Hash da senha do usuário (Argon2id `crypto_pwhash_str`) |
| **Secret** | Par (private_key, public_key) criptografado com AES-GCM-256 usando o KEK |

### Fluxo de Operação

```
Usuário registra → senha hasheada (Argon2id) + KEK gerado + wrapped + armazenado
       │
Usuário armazena segredo → wrapping_key (cache) → AES-KW unwrap → AES-GCM encrypt → KEK zerado
       │
Usuário lê segredo → wrapping_key (cache) → AES-KW unwrap → AES-GCM decrypt → KEK zerado
       │
Usuário lista segredos → callback por secret (sem decrypt)
       │
Usuário deleta segredo → busca + remove da tabela secrets
       │
Usuário deleta conta → verifica senha → CASCADE (KEK + segredos removidos)
       │
Usuário troca senha → re-hash → re-wrap KEK (mesmo salt) → COMMIT atômico
       │
KEK expira (90d) → rotação: decrypt tudo com KEK velho → encrypt com KEK novo → COMMIT
       │
Backup → AES-256-GCM + HMAC-SHA256 → arquivo .bak portável
       │
Export → JSON/CSV metadata (PII redactable) → streaming via callback
       │
Schema Migration → PRAGMA user_version → migrações sequenciais atômicas
```

## Stack

| Componente | Função |
|------------|--------|
| **C++17** | Linguagem |
| **OpenSSL** | AES-KW-256, AES-GCM-256 |
| **libsodium** | Argon2id (hashing + KDF), random_bytes |
| **SQLite3 / SQLCipher** | Persistência (SQLCipher: encrypt at rest; SQLite3 puro: dev) |
| **ncursesw** | TUI (Terminal User Interface) |
| **CMake** | Build system |
| **Google Test** | Testes unitários e integração |

## Build

### Dependências

```bash
# Debian / Ubuntu (produção — SQLCipher real)
apt install libsqlcipher-dev libsodium-dev libssl-dev libncursesw5-dev \
            cmake pkg-config build-essential

# Termux (dev — SQLite3 puro, sem encrypt-at-rest)
pkg install libsodium openssl sqlite ncursesw cmake ninja
```

### Compilar e Testar

```bash
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### Release Build

```bash
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
# Visibility hidden automático em Release (SSM_VISIBILITY_HIDDEN=ON)
```

### Testes e Qualidade

```bash
# Testes completos (182)
ctest --test-dir build --output-on-failure

# Sanitizers (ASan+UBSan)
cmake -B build-san -DSSM_SANITIZE=ON && cmake --build build-san
./build-san/tests/ssm_test

# Fuzzing (clang)
cmake -B build-fuzz -DCMAKE_C_COMPILER=clang -DSSM_FUZZING=ON && cmake --build build-fuzz
./build-fuzz/tests/fuzz_api -max_total_time=10 -runs=100000

# Benchmarks
cmake -B build-bench -DSSM_BUILD_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build-bench
./build-bench/tests/ssm_bench --benchmark_min_time=0.1
```

### Instalação

```bash
cmake -B build
cmake --build build
cmake --install build --prefix /usr/local
# Produz: lib/libssm.so.0.3.0, include/ssm/ssm.h, lib/cmake/ssm/ssmConfig.cmake
```

Consumir via CMake:

```cmake
find_package(ssm REQUIRED)
target_link_libraries(meu_app PRIVATE ssm::ssm)
```

## Licença MIT

```text
MIT License

Copyright (c) 2026 Vaultine

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Lint / Formatação

```bash
# clang-format
find src/ include/ tests/ -name '*.cc' -o -name '*.h' | xargs clang-format -i

# clang-tidy (requer compile_commands.json)
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
run-clang-tidy -p build src/
```

## TUI (Terminal User Interface)

O Vaultine inclui uma interface ncurses interativa via `ssm-cli tui`:

```
┌───────────────────────────────────────────────┐
│  VAULTINE  —  Terminal Interface              │
├───────────────────────────────────────────────┤
│                                               │
│         ╔═══════════════════╗                  │
│         ║   MENU PRINCIPAL  ║                  │
│         ╚═══════════════════╝                  │
│                                               │
│     [1] User Management                       │
│     [2] Secret Management                     │
│     [3] KEK Rotation                          │
│     [4] Database Info                         │
│     [5] Cache Statistics                      │
│     [6] Exit                                  │
│                                               │
├───────────────────────────────────────────────┤
│  DB: ./ssm.db  │  arrows + Enter to select     │
└───────────────────────────────────────────────┘
```

| Tecla | Ação |
|-------|------|
| `↑ ↓` | Navegar entre itens |
| `Enter` | Selecionar |
| `Esc` | Voltar / Cancelar |
| `1-6` | Atalho numérico |
| `q` | Sair |

**Telas:** Register, Authenticate, Delete, Change Password, Secret Store/Get/Delete/List (scrollável), KEK Rotation, Database Info, Cache Statistics.

## CLI Completo

```bash
ssm-cli --help
```

| Comando | Descrição |
|---------|-----------|
| `user register/auth/delete/change-password` | Gerenciamento de usuários |
| `secret store/get/delete/list` | Gerenciamento de segredos |
| `kek rotate` | Rotação manual de KEK |
| `db version` | Mostra versão do schema SQLite |
| `db migrate` | Aplica migrações pendentes |
| `backup create/restore <file>` | Backup/restore criptografado |
| `export [--format json\|csv] [--redact-pii]` | Exporta metadados para stdout |
| `server start [--port] [--host] [--daemonize]` | REST API server (libevent evhttp) |
| `cache-stats` | Estatísticas do cache de wrapping keys |
| `audit-log <username>` | Consulta log de auditoria |
| `env exec <username> <cmd>` | Injeta segredos como env vars |
| `tui` | Interface ncurses interativa |

```bash
ssm-cli tui                     # inicia a interface
ssm-cli --db /path/db tui       # com banco personalizado
ssm-cli backup create vaultine.bak --backup-key <hex64>
ssm-cli export --format json --redact-pii
ssm-cli db version
```

## REST API Server

O Vaultine inclui um servidor HTTP REST via `ssm-cli server start`, implementado com libevent evhttp + jsoncpp. Todas as respostas são JSON com `Content-Type: application/json`.

```bash
ssm-cli server start                    # localhost:8080
ssm-cli server start --port 9090        # porta customizada
ssm-cli server start --host 0.0.0.0     # todas as interfaces
ssm-cli server start --daemonize        # background
ssm-cli server start --daemonize --pidfile /run/ssm-cli.pid
```

### Endpoints

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET` | `/v1/health` | Health check |
| `GET` | `/v1/version` | Versão da API |
| `POST` | `/v1/users/<username>/register` | Registrar usuário |
| `POST` | `/v1/users/<username>/auth` | Autenticar usuário |
| `DELETE` | `/v1/users/<username>` | Deletar usuário |
| `PUT` | `/v1/users/<username>/password` | Trocar senha |
| `GET` | `/v1/users/<username>/secrets` | Listar segredos |
| `POST` | `/v1/users/<username>/secrets` | Armazenar segredo |
| `GET` | `/v1/users/<username>/secrets/<name>` | Recuperar segredo |
| `DELETE` | `/v1/users/<username>/secrets/<name>` | Deletar segredo |
| `POST` | `/v1/users/<username>/kek/rotate` | Rotacionar KEK |
| `POST` | `/v1/backup/create` | Criar backup |
| `POST` | `/v1/backup/restore` | Restaurar backup |
| `GET` | `/v1/audit` | Log de auditoria |
| `GET` | `/v1/export` | Exportar metadados |
| `GET` | `/v1/cache/stats` | Estatísticas do cache |
| `GET` | `/v1/db/version` | Versão do schema |
| `POST` | `/v1/db/migrate` | Migrar schema |

### Exemplo

```bash
# Iniciar servidor
ssm-cli server start --port 8080 &

# Registrar usuário
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"password":"minha-senha"}' \
  http://127.0.0.1:8080/v1/users/alice/register

# Armazenar segredo
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"name":"minha-chave","private_key":"deadbeef01020304"}' \
  http://127.0.0.1:8080/v1/users/alice/secrets

# Recuperar segredo
curl -s http://127.0.0.1:8080/v1/users/alice/secrets/minha-chave
```

### Parâmetros de Query (Audit/Export)

Os endpoints `/v1/audit` e `/v1/export` usam **cabeçalhos HTTP** para filtros:

```bash
curl -s -H "X-Audit-Username: alice" \
  -H "X-Audit-Operation: secret_store" \
  -H "X-Audit-Limit: 50" \
  http://127.0.0.1:8080/v1/audit

curl -s -H "X-Export-Format: csv" \
  -H "X-Export-Redact: true" \
  http://127.0.0.1:8080/v1/export
```

## API Pública

```c
#include <ssm/ssm.h>
```

### Tipos

```c
typedef struct ssm_handle ssm_handle;

typedef enum {
    SSM_OK              = 0,
    SSM_ERR_AUTH        = 1,  // usuário não encontrado ou senha incorreta
    SSM_ERR_NOT_FOUND   = 2,  // segredo não encontrado
    SSM_ERR_EXPIRED     = 3,  // KEK expirado
    SSM_ERR_INTEGRITY   = 4,  // AES-GCM tag mismatch (dados corrompidos)
    SSM_ERR_INTERNAL    = 5   // erro interno (DB, crypto, OOM)
} ssm_status;

// Callback para ssm_secret_list: recebe metadados de cada segredo
typedef void (*ssm_secret_list_cb)(const char* name, const char* description,
                                   const char* updated_at, size_t public_key_len,
                                   void* user_data);
```

### ssm_init / ssm_destroy

```c
ssm_status ssm_init(ssm_handle** out, const char* db_path,
                    const unsigned char* db_key, size_t db_key_len);

ssm_status ssm_destroy(ssm_handle* h);
```

| Parâmetro | Descrição |
|-----------|-----------|
| `db_path` | Caminho do arquivo SQLite (`:memory:` para memória) |
| `db_key` | Chave SQLCipher (opcional; `NULL` = sem encrypt) |

### ssm_user_register / ssm_user_authenticate

```c
ssm_status ssm_user_register(ssm_handle* h, const char* username,
                             const char* password);

ssm_status ssm_user_authenticate(ssm_handle* h, const char* username,
                                 const char* password, int* is_valid);
```

- `ssm_user_register`: hashea a senha (Argon2id), cria usuário, gera KEK, wrapped + armazenado.
- `ssm_user_authenticate`: verifica senha contra hash armazenado. `is_valid=1` se correta.

### ssm_user_delete

```c
ssm_status ssm_user_delete(ssm_handle* h, const char* username, const char* password);
```

Remove permanentemente o usuário e todos os seus dados (KEK + segredos via ON DELETE CASCADE). Requer senha para confirmação.

### ssm_user_change_password

```c
ssm_status ssm_user_change_password(ssm_handle* h, const char* username,
                                    const char* old_password, const char* new_password);
```

Troca a senha do usuário. Atomicidade via `BEGIN IMMEDIATE` / `COMMIT`:
1. Verifica senha antiga.
2. Hash da nova senha (Argon2id).
3. UPDATE `users.password_hash`.
4. Unwrap KEK com wrapping key antiga.
5. Re-wrap KEK com nova wrapping key (derivada do novo hash + mesmo salt).
6. COMMIT (ou ROLLBACK em qualquer falha).

O KEK permanece o mesmo — segredos **não** são re-criptografados.

### ssm_secret_store / ssm_secret_get / ssm_secret_delete / ssm_secret_list

```c
ssm_status ssm_secret_store(ssm_handle* h, const char* username,
    const unsigned char* private_key, size_t private_key_len,
    const unsigned char* public_key, size_t public_key_len,
    const char* name, const char* description);

ssm_status ssm_secret_get(ssm_handle* h, const char* username,
    const char* name,
    unsigned char* private_key_out, size_t* private_key_len_out,
    unsigned char* public_key_out, size_t* public_key_len_out);

ssm_status ssm_secret_delete(ssm_handle* h, const char* username,
                             const char* name);

ssm_status ssm_secret_list(ssm_handle* h, const char* username,
                           ssm_secret_list_cb callback, void* user_data);
```

- `private_key`: **sempre criptografada** com AES-GCM-256 usando o KEK do usuário.
- `public_key`: armazenada **plaintext** (chaves públicas são públicas).
- `name`: identificador único do segredo dentro do escopo do usuário.
- `ssm_secret_list`: enumera segredos via callback com `(name, description, updated_at, public_key_len)`. Verifica expiração do KEK antes de listar.

### ssm_kek_rotate

```c
ssm_status ssm_kek_rotate(ssm_handle* h, const char* username);
```

Gera novo KEK, descriptografa todos os segredos com KEK antigo em memória, re-criptografa com KEK novo. Tudo dentro de uma **transação ACID única** — se qualquer passo falhar, ROLLBACK total.

### ssm_backup_create / ssm_backup_restore

```c
ssm_status ssm_backup_create(ssm_handle* h, const char* backup_path,
                             const unsigned char* backup_key, size_t backup_key_len);

ssm_status ssm_backup_restore(ssm_handle* h, const char* backup_path,
                              const unsigned char* backup_key, size_t backup_key_len);
```

Backup do banco completo com AES-256-GCM + HMAC-SHA256:
- `backup_key`: 32 bytes de chave (hex 64 chars no CLI)
- Formato portável entre máquinas
- Restore valida HMAC + tag GCM antes de substituir o DB

### ssm_export

```c
typedef enum {
    SSM_EXPORT_JSON = 0,
    SSM_EXPORT_CSV = 1
} ssm_export_format;

typedef void (*ssm_export_cb)(const char* chunk, size_t len, void* user_data);

ssm_status ssm_export(ssm_handle* h, ssm_export_format format, int redact_pii,
                      ssm_export_cb callback, void* user_data);
```

Exporta metadados (NÃO segredos) via streaming callback:
- JSON ou CSV
- `redact_pii=1` substitui usernames por IDs anônimos
- Inclui: usuários, segredos (nomes/tamanhos), metadados KEK

### ssm_db_version / ssm_db_migrate

```c
ssm_status ssm_db_version(ssm_handle* h, int* version_out);
ssm_status ssm_db_migrate(ssm_handle* h);
```

- `ssm_db_version`: lê `PRAGMA user_version` do SQLite
- `ssm_db_migrate`: aplica migrações pendentes automaticamente
- Schema v1: schema inicial (4 tabelas). Schema v2: + índice `idx_secrets_user_id`

## Exemplos

### Inicialização e Registro

```c
#include <ssm/ssm.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    ssm_handle* h = NULL;

    // init com banco em memória (sem criptografia em repouso)
    if (ssm_init(&h, ":memory:", NULL, 0) != SSM_OK) {
        fprintf(stderr, "falha ao inicializar\n");
        return 1;
    }

    // registrar usuário
    if (ssm_user_register(h, "alice", "p@ssw0rd") != SSM_OK) {
        fprintf(stderr, "falha ao registrar\n");
        ssm_destroy(h);
        return 1;
    }

    // autenticar
    int valido = 0;
    ssm_user_authenticate(h, "alice", "p@ssw0rd", &valido);
    printf("alice autenticada: %s\n", valido ? "sim" : "não");

    ssm_destroy(h);
    return 0;
}
```

### Armazenar e Recuperar Segredo

```c
#include <ssm/ssm.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    ssm_handle* h = NULL;
    ssm_init(&h, ":memory:", NULL, 0);
    ssm_user_register(h, "bob", "secret");

    // --- armazenar ---
    unsigned char priv[] = "minha-chave-privada-32bytes-aqui!";
    unsigned char pub[]  = "chave-publica-aqui!";

    if (ssm_secret_store(h, "bob",
                         priv, sizeof(priv),
                         pub, sizeof(pub),
                         "minha-chave",
                         "chave RSA para projeto X") == SSM_OK)
        printf("segredo armazenado\n");

    // --- recuperar ---
    unsigned char priv_out[64];
    size_t priv_len = sizeof(priv_out);
    unsigned char pub_out[64];
    size_t pub_len = sizeof(pub_out);

    if (ssm_secret_get(h, "bob", "minha-chave",
                       priv_out, &priv_len,
                       pub_out, &pub_len) == SSM_OK) {
        printf("private_key (%zu bytes) recuperada\n", priv_len);
        printf("public_key  (%zu bytes) recuperada\n",  pub_len);
    }

    // --- deletar ---
    ssm_secret_delete(h, "bob", "minha-chave");

    ssm_destroy(h);
    return 0;
}
```

### Rotação de KEK

```c
#include <ssm/ssm.h>
#include <stdio.h>

int main(void) {
    ssm_handle* h = NULL;
    ssm_init(&h, ":memory:", NULL, 0);
    ssm_user_register(h, "carol", "mypass");

    // armazena alguns segredos...
    unsigned char k1[] = "segredo-importante-1";
    unsigned char k2[] = "segredo-importante-2";
    ssm_secret_store(h, "carol", k1, sizeof(k1), NULL, 0, "key1", NULL);
    ssm_secret_store(h, "carol", k2, sizeof(k2), NULL, 0, "key2", NULL);

    // força rotação do KEK (normalmente automática a cada 90 dias)
    if (ssm_kek_rotate(h, "carol") == SSM_OK)
        printf("KEK rotacionado com sucesso\n");

    // segundos continuam acessíveis com o novo KEK
    unsigned char out[64];
    size_t len = sizeof(out);
    ssm_secret_get(h, "carol", "key1", out, &len, NULL, NULL);

    ssm_destroy(h);
    return 0;
}
```

### Troca de Senha

```c
#include <ssm/ssm.h>
#include <stdio.h>

int main(void) {
    ssm_handle* h = NULL;
    ssm_init(&h, ":memory:", NULL, 0);
    ssm_user_register(h, "dave", "old-password");

    // troca a senha
    if (ssm_user_change_password(h, "dave", "old-password", "new-password") == SSM_OK)
        printf("senha alterada\n");

    // segredos continuam acessíveis com a nova senha
    int valido = 0;
    ssm_user_authenticate(h, "dave", "new-password", &valido);
    printf("autenticado: %s\n", valido ? "sim" : "não");

    ssm_destroy(h);
    return 0;
}
```

### Listar Segredos

```c
#include <ssm/ssm.h>
#include <stdio.h>

void list_cb(const char* name, const char* desc, const char* updated,
             size_t pub_len, void* user_data) {
    int* count = (int*)user_data;
    printf("  %d. %s — %s (pub: %zu bytes, atualizado: %s)\n",
           ++(*count), name, desc ? desc : "(sem descrição)",
           pub_len, updated);
}

int main(void) {
    ssm_handle* h = NULL;
    ssm_init(&h, ":memory:", NULL, 0);
    ssm_user_register(h, "eve", "pass");

    ssm_secret_store(h, "eve", (const unsigned char*)"k1", 2, NULL, 0, "key1", "primeira");
    ssm_secret_store(h, "eve", (const unsigned char*)"k2", 2, NULL, 0, "key2", "segunda");

    int count = 0;
    printf("Segredos de eve:\n");
    ssm_secret_list(h, "eve", list_cb, &count);
    printf("Total: %d\n", count);

    ssm_destroy(h);
    return 0;
}
```

### Backup e Restore

```c
#include <ssm/ssm.h>
#include <stdio.h>

int main(void) {
    ssm_handle* h = NULL;
    ssm_init(&h, "vaultine.db", NULL, 0);
    ssm_user_register(h, "alice", "p@ss");

    // backup key de 32 bytes
    unsigned char key[32] = "meu-backup-key-32bytes-aqui!";
    if (ssm_backup_create(h, "vaultine.bak", key, sizeof(key)) == SSM_OK)
        printf("backup criado\n");

    ssm_destroy(h);

    // restore em outro handle
    ssm_handle* h2 = NULL;
    ssm_init(&h2, "vaultine-restored.db", NULL, 0);
    ssm_backup_restore(h2, "vaultine.bak", key, sizeof(key));

    int valido = 0;
    ssm_user_authenticate(h2, "alice", "p@ss", &valido);
    printf("alice acessível após restore: %s\n", valido ? "sim" : "não");
    ssm_destroy(h2);
    return 0;
}
```

### Exportar Metadados

```c
void export_cb(const char* chunk, size_t len, void* user) {
    fwrite(chunk, 1, len, (FILE*)user);
}

int main(void) {
    ssm_handle* h = NULL;
    ssm_init(&h, ":memory:", NULL, 0);
    ssm_user_register(h, "bob", "pass");

    // JSON para stdout (PII preservado)
    ssm_export(h, SSM_EXPORT_JSON, 0, export_cb, stdout);

    // CSV para stdout (PII redactado)
    // ssm_export(h, SSM_EXPORT_CSV, 1, export_cb, stdout);

    ssm_destroy(h);
    return 0;
}
```

### Deletar Usuário

```c
#include <ssm/ssm.h>
#include <stdio.h>

int main(void) {
    ssm_handle* h = NULL;
    ssm_init(&h, ":memory:", NULL, 0);
    ssm_user_register(h, "frank", "p@ss");

    // deleta conta (requer senha)
    if (ssm_user_delete(h, "frank", "p@ss") == SSM_OK)
        printf("usuário removido (KEK + segredos também)\n");

    ssm_destroy(h);
    return 0;
}
```

### Tratamento de Erros

```c
ssm_status status = ssm_secret_list(h, "unknown-user", list_cb, NULL);

switch (status) {
    case SSM_OK:              break;
    case SSM_ERR_AUTH:        printf("usuário não encontrado ou senha incorreta\n"); break;
    case SSM_ERR_NOT_FOUND:   printf("segredo não existe\n"); break;
    case SSM_ERR_EXPIRED:     printf("KEK expirado — rode ssm_kek_rotate\n"); break;
    case SSM_ERR_INTEGRITY:   printf("dados corrompidos ou KEK incorreto\n"); break;
    case SSM_ERR_INTERNAL:    printf("erro interno\n"); break;
}

// Converter enum para string legível:
printf("status: %s\n", ssm_status_to_string(status));  // "SSM_ERR_AUTH"
```

## Hierarquia Criptográfica

```
Senha do Usuário
    │
    ▼
┌─────────────────────────────────────┐
│ Argon2id (crypto_pwhash_str)        │
│ → password_hash (string ~128B)      │  → usado para autenticação
└─────────────────────────────────────┘
    │
    │  password_hash + salt (16B)
    ▼
┌─────────────────────────────────────┐
│ Argon2id (crypto_pwhash, raw 32B)   │
│ → wrapping_key                      │
└─────────────────────────────────────┘
    │
    │  AES-KW-256 (wrap)
    ▼
┌─────────────────────────────────────┐
│ KEK (256-bit aleatório)             │
│ → wrapped_kek armazenado no DB      │  → descriptografado só em RAM
└─────────────────────────────────────┘
    │
    │  AES-GCM-256 (encrypt)
    ▼
┌─────────────────────────────────────┐
│ Segredos do usuário                 │
│ (private_key criptografada,         │
│  public_key plaintext)              │
└─────────────────────────────────────┘
```

| Etapa | Algoritmo | Detalhe |
|-------|-----------|---------|
| Hash de senha | Argon2id `crypto_pwhash_str` | ~128 bytes, parâmetros + salt embutidos |
| Derivação wrapping key | Argon2id `crypto_pwhash` | `auth_hash + salt` → 32 bytes, opslimit=MODERATE |
| Wrap KEK | AES-KW-256 | `EVP_aes_256_wrap`, padding de 8 bytes |
| Criptografia de segredos | AES-GCM-256 | AEAD: nonce 12B, tag 16B |
| Geração aleatória | `randombytes_buf` (libsodium) | KEK, salts, nonces |

## Ciclo de Vida da KEK

### Validade

- Padrão: **90 dias** (`KEK_DEFAULT_DAYS = 90`), configurável por tenant.
- Toda operação (`ssm_secret_store`, `ssm_secret_get`) verifica `kek_is_expired`.
- Se expirado, retorna `SSM_ERR_EXPIRED`. O usuário deve forçar `ssm_kek_rotate`.

### Rotação

```
1. BEGIN IMMEDIATE (lock exclusivo)
2. Carregar KEK atual + salt do DB
3. Derivar wrapping_key atual (auth_hash + salt_velho)
4. Unwrapp KEK atual
5. Listar TODOS os segredos do usuário
6. Para cada segredo:
   a. AES-GCM decrypt com KEK velho
   b. Gerar novo nonce
   c. AES-GCM encrypt com KEK novo + novo nonce
   d. UPDATE na mesma transação
7. Gerar novo salt
8. Derivar nova wrapping_key (auth_hash + salt_novo)
9. AES-KW wrap do novo KEK
10. Calcular nova data de expiração (now + 90d)
11. UPDATE kek_metadata
12. COMMIT
13. Se QUALQUER passo falhar → ROLLBACK
```

### Segurança

- KEK **nunca** persiste em disco sem wrap.
- Wrapping_key derivada de KDF lento (Argon2id MODERATE) — resistente a brute-force mesmo se o `password_hash` vazar.
- `memset_s` / `secure_erase` em buffers sensíveis após uso.
- Transação ACID única garante atomicidade da rotação.
- `kek_version` (incrementado a cada rotação) protege contra rollback de `kek_metadata`.

## Thread Safety

- `SQLITE_OPEN_FULLMUTEX`: SQLite serializa acesso interno.
- `std::shared_mutex` no `ssm_handle`: protege operações multi-step (especialmente rotação).
- Todas as funções da API pública adquirem `unique_lock` no início.

## Password Validation (v0.2.0)

```c
ssm_status ssm_set_password_validator(ssm_password_validator validator, void* user_data);
```

Registre um callback para validar senhas antes de `ssm_user_register` e `ssm_user_change_password`:

```c
// Validador customizado: exige pelo menos 8 caracteres e um '!'
ssm_status my_validator(const char* pw, void*) {
    return (strlen(pw) >= 8 && strchr(pw, '!')) ? SSM_OK : SSM_ERR_INTERNAL;
}

ssm_set_password_validator(my_validator, NULL);
```

- Default: mínimo **4 caracteres**
- `NULL` restaura o validador default

## Secure Memory (mlock) (v0.2.0)

```cpp
void* secure_alloc(size_t size);                       // malloc + mlock
void  secure_free(void* ptr, size_t size);             // secure_erase + munlock + free
template <typename T> class secure_buffer;              // RAII wrapper
template <typename T> class secure_vector;              // RAII vector
```

Previne que chaves criptográficas sejam swappadas para disco:

```cpp
// KEK nunca será paginada para swap
auto buf = secure_buffer<unsigned char>(32);  // mlocado
crypto_function(buf.data(), buf.size());
// destructor: secure_erase + munlock + free
```

## Cache Statistics (v0.2.0)

```c
typedef struct {
    size_t total_entries;   // SSM_CACHE_MAX = 256
    size_t valid_entries;
    size_t hit_count;
    size_t miss_count;
} ssm_cache_stats;

ssm_status ssm_cache_get_stats(ssm_handle* h, ssm_cache_stats* out);
```

```bash
ssm-cli cache-stats
# Cache Statistics:
#   Total slots:     256
#   Valid entries:   1
#   Hits:            5
#   Misses:          1
#   Hit rate:        83.3%
```

## Audit Log

Cache LRU de 256 entradas no `ssm_handle` que armazena chaves de *wrapping*
(derivadas via Argon2id — a etapa mais cara de cada operação) para evitar
o KDF em operações repetidas no mesmo tenant:

| Operação | Sem cache | Com cache |
|----------|-----------|-----------|
| `ssm_secret_store` (primeira chamada) | ~150ms (KDF + AES-KW + AES-GCM) | ~150ms |
| `ssm_secret_store` (mesmo tenant, após primeira) | ~150ms | **~1µs** (só AES-KW + AES-GCM) |

- Cache é invalidado em `ssm_kek_rotate` (salt muda → wrapping key muda).
- Cache é invalidado em `ssm_user_change_password` (auth_hash muda → wrapping key muda).
- Cache é zerado com `secure_erase` em `ssm_destroy`.
- NÃO armazena o KEK — apenas a wrapping key derivada.

## Audit Log

Tabela `audit_log` registra todas as operações da API com timestamp, user_id,
operação, resultado, alvo e detalhes. Consultável diretamente via SQLite para auditoria forense.

| Coluna | Tipo | Descrição |
|--------|------|-----------|
| `id` | INTEGER | PK AUTOINCREMENT |
| `user_id` | INTEGER | FK → users(id) (0 se não autenticado) |
| `username` | TEXT | Nome do usuário no momento da operação |
| `operation` | TEXT | Nome da operação (ex: `user_register`, `secret_get`) |
| `operation_target` | TEXT | Alvo da operação (ex: nome do secret) |
| `details` | TEXT | Detalhes contextuais ("password mismatch", "KEK expired") |
| `result` | TEXT | Resultado (`SSM_OK`, `SSM_ERR_AUTH`, etc.) |
| `timestamp` | TEXT | ISO 8601 UTC |

## Schema SQLite

### `users`

| Coluna | Tipo | Restrição |
|--------|------|-----------|
| `id` | INTEGER | PK AUTOINCREMENT |
| `username` | TEXT | UNIQUE NOT NULL |
| `password_hash` | BLOB | NOT NULL (Argon2id string) |
| `created_at` | TEXT | DEFAULT CURRENT_TIMESTAMP |

### `kek_metadata`

| Coluna | Tipo | Restrição |
|--------|------|-----------|
| `id` | INTEGER | PK AUTOINCREMENT |
| `user_id` | INTEGER | FK → users(id) ON DELETE CASCADE |
| `wrapped_kek` | BLOB | NOT NULL (AES-KW-256, 40 bytes) |
| `salt` | BLOB | NOT NULL (16 bytes) |
| `expires_at` | TEXT | NOT NULL (ISO 8601 UTC) |
| `kek_version` | INTEGER | NOT NULL DEFAULT 1 (incrementado na rotação) |
| `UNIQUE(user_id)` | | |

### `secrets`

| Coluna | Tipo | Restrição |
|--------|------|-----------|
| `id` | INTEGER | PK AUTOINCREMENT |
| `user_id` | INTEGER | FK → users(id) ON DELETE CASCADE |
| `name` | TEXT | |
| `private_key` | BLOB | NOT NULL (AES-GCM-256) |
| `public_key` | BLOB | NULLABLE (plaintext) |
| `nonce` | BLOB | NOT NULL (12 bytes) |
| `tag` | BLOB | NOT NULL (16 bytes, GCM auth tag) |
| `description` | TEXT | NULLABLE |
| `updated_at` | TEXT | NOT NULL DEFAULT CURRENT_TIMESTAMP |

---

## Bindings

A API pública do Vaultine é escrita em C puro com `extern "C"` e `SSM_EXPORT`,
o que permite chamar a biblioteca de praticamente qualquer linguagem via FFI
(Foreign Function Interface).

```
./build/libssm.so
   │
   ├── Python  (ctypes / cffi)
   ├── Rust    (extern "C")
   ├── Go      (cgo)
   ├── C#      (DllImport + LibraryImport)
   ├── Java    (JNI / JNR-FFI)
   ├── Node.js (node-ffi / napi-rs)
   └── Zig / Nim / Julia / ... (qualquer FFI C)
```

### Características FFI

| Aspecto | Detalhe |
|---------|---------|
| Linkage | `extern "C"` — sem name mangling C++ |
| Handle | `ssm_handle*` — ponteiro opaco (armazenar como `void*` ou `usize`) |
| Thread safety | `std::shared_mutex` interno — chamadas FFI seguras sem locks extra |
| Strings | `const char*` UTF-8 (cópia imediata se precisar retain) |
| Buffers | `unsigned char*` + `size_t` — caller aloca, Vaultine preenche |
| Callbacks | `ssm_secret_list_cb` — `void(*)(const char*,..., void*)` |
| Erros | Retorno `ssm_status` + `ssm_status_to_string()` |

### Gerenciamento de Memória

| Quem aloca | Quem libera | O que |
|------------|-------------|-------|
| **Caller** | **Caller** | Buffer de saída de `ssm_secret_get` (`private_key_out`, `public_key_out`) |
| **Caller** | **Caller** | Struct `ssm_handle*` recebido de `ssm_init` (via `ssm_destroy`) |
| **Vaultine** | **Vaultine** | String retornada por `ssm_status_to_string` (memória estática — não fazer free) |
| **Caller** | — | Strings de entrada (`username`, `password`, `name`) — Vaultine copia internamente |

**`ssm_secret_get`**: Passe `private_key_len_out` com a capacidade do buffer. Se o buffer
for pequeno, a API retorna `SSM_ERR_INTERNAL` e preenche o tamanho necessário.
Estratégia recomendada: alocar 4096 bytes e tratar `SSM_ERR_INTERNAL` como "buffer pequeno".

### Python (ctypes)

Módulo completo em [`bindings/python/ssm.py`](bindings/python/ssm.py):

```python
import ctypes

lib = ctypes.CDLL("./build/libssm.so")

# Configurar tipos
lib.ssm_init.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p,
                         ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
lib.ssm_init.restype = ctypes.c_int

lib.ssm_destroy.argtypes = [ctypes.c_void_p]
lib.ssm_destroy.restype = ctypes.c_int

# Uso
handle = ctypes.c_void_p()
status = lib.ssm_init(ctypes.byref(handle), b":memory:", None, 0)
if status != 0:
    raise RuntimeError(f"ssm_init falhou: {status}")

status = lib.ssm_user_register(handle, b"alice", b"p@ssw0rd")
# ...

lib.ssm_destroy(handle)
```

**Callback (ssm_secret_list):**

```python
CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_char_p,
                            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p)

def list_secrets(handle, username):
    secrets = []
    def cb(name, desc, updated, pub_len, user_data):
        secrets.append((name.decode(), desc.decode() if desc else None))
    cb_ptr = CALLBACK(cb)
    lib.ssm_secret_list(handle, username.encode(), cb_ptr, None)
    return secrets
```

### Rust

Crate completa em [`bindings/rust/vaultine-rs/`](bindings/rust/vaultine-rs/):

```rust
use vaultine::Vaultine;

let v = Vaultine::new(":memory:", None)?;
v.user_register("alice", "p@ss")?;
let ok = v.user_authenticate("alice", "p@ss")?;
v.secret_store("alice", b"my-key", None, "k1", Some("test key"))?;
let list = v.secret_list("alice")?;
v.kek_rotate("alice")?;
// automatic ssm_destroy via Drop
```

Veja [`examples/basic.rs`](bindings/rust/vaultine-rs/examples/basic.rs) e [`src/lib.rs`](bindings/rust/vaultine-rs/src/lib.rs) para API completa com `SecretEntry`, `AuditEntry`, `CacheStats`, `export_metadata`, `db_version`, `backup_create/restore`.

**Build:**
```bash
RUSTFLAGS="-L /path/to/build/src" cargo build
LD_LIBRARY_PATH="/path/to/build/src" cargo test
```

### Go (cgo)

Package completo em [`bindings/go/vaultine/`](bindings/go/vaultine/):

```go
import "github.com/anomalyco/vaultine"

v, err := vaultine.New(":memory:", nil)
v.UserRegister("alice", "p@ss")
ok, _ := v.UserAuthenticate("alice", "p@ss")
v.SecretStore("alice", []byte("my-key"), nil, "k1", "test key")
priv, pub, _ := v.SecretGet("alice", "k1", 4096)
v.SecretList("alice", func(e vaultine.SecretEntry) { /* ... */ })
v.KEKRotate("alice")
v.Destroy()
```

Veja [`examples/main.go`](bindings/go/vaultine/examples/main.go) e [`vaultine.go`](bindings/go/vaultine/vaultine.go) para API completa (`AuditLogQuery`, `CacheStats`, `Export`, `DBVersion`, `DBMigrate`, `BackupCreate`, `BackupRestore`).

**Build:**
```bash
CGO_CFLAGS="-I/path/to/include" CGO_LDFLAGS="-L/path/to/build/src -lssm" go build
LD_LIBRARY_PATH="/path/to/build/src" go test
```

### Node.js (node-ffi)

```javascript
const ffi = require('ffi-napi');

const ssm = ffi.Library('./build/libssm.so', {
    'ssm_init': ['int', ['pointer', 'string', 'pointer', 'size_t']],
    'ssm_destroy': ['int', ['pointer']],
    'ssm_user_register': ['int', ['pointer', 'string', 'string']],
    'ssm_user_authenticate': ['int', ['pointer', 'string', 'string', 'pointer']],
    'ssm_secret_store': ['int', ['pointer', 'string', 'pointer', 'size_t',
                                 'pointer', 'size_t', 'string', 'string']],
    'ssm_secret_get': ['int', ['pointer', 'string', 'string',
                               'pointer', 'pointer', 'pointer', 'pointer']],
    'ssm_secret_delete': ['int', ['pointer', 'string', 'string']],
    'ssm_kek_rotate': ['int', ['pointer', 'string']],
    'ssm_status_to_string': ['string', ['int']],
});

const ref = require('ref-napi');
const handle = ref.alloc(ref.refType(ref.types.void));
ssm.ssm_init(handle, ':memory:', null, 0);
const h = ref.deref(handle);

ssm.ssm_user_register(h, 'alice', 'p@ss');
console.log(ssm.ssm_status_to_string(ssm.ssm_secret_store(
    h, 'alice', Buffer.from('my-key'), 6, null, 0, 'k1', null)));

ssm.ssm_destroy(h);
```
