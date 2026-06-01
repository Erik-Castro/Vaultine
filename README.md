# Vaultine — Gestão de Segredos Multi-Tenant

<p align="center">
  <a href="assets/vaultine-logo.svg"><img src="assets/vaultine-logo.svg" alt="Vaultine Logo" width="200" height="200"></a>
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
```

## Stack

| Componente | Função |
|------------|--------|
| **C++17** | Linguagem |
| **OpenSSL** | AES-KW-256, AES-GCM-256 |
| **libsodium** | Argon2id (hashing + KDF), random_bytes |
| **SQLite3 / SQLCipher** | Persistência (SQLCipher: encrypt at rest; SQLite3 puro: dev) |
| **CMake** | Build system |
| **Google Test** | Testes unitários e integração |

## Build

### Dependências

```bash
# Debian / Ubuntu (produção — SQLCipher real)
apt install libsqlcipher-dev libsodium-dev libssl-dev cmake pkg-config build-essential

# Termux (dev — SQLite3 puro, sem encrypt-at-rest)
pkg install libsodium openssl sqlite cmake ninja
```

### Compilar e Testar

```bash
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### Release Build

```bash
cmake -B build-release -DSSM_VISIBILITY_HIDDEN=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
# Apenas 11 símbolos visíveis no .so (init, destroy, register, authenticate,
#   store, get, delete, list, user_delete, change_password, kek_rotate)
```

### Instalação

```bash
cmake -B build
cmake --build build
cmake --install build --prefix /usr/local
# Produz: lib/libssm.so.0.1.0, include/ssm/ssm.h, lib/cmake/ssm/ssmConfig.cmake
```

Consumir via CMake:

```cmake
find_package(ssm REQUIRED)
target_link_libraries(meu_app PRIVATE ssm::ssm)
```
```

### Lint / Formatação

```bash
# clang-format
find src/ include/ tests/ -name '*.cc' -o -name '*.h' | xargs clang-format -i

# clang-tidy (requer compile_commands.json)
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
run-clang-tidy -p build src/
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

## Wrapping Key Cache

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
operação e resultado. Consultável diretamente via SQLite para auditoria forense.

| Coluna | Tipo | Descrição |
|--------|------|-----------|
| `id` | INTEGER | PK AUTOINCREMENT |
| `user_id` | INTEGER | FK → users(id) (0 se não autenticado) |
| `username` | TEXT | Nome do usuário no momento da operação |
| `operation` | TEXT | Nome da operação (ex: `user_register`, `secret_get`) |
| `status` | TEXT | Resultado (`SSM_OK`, `SSM_ERR_AUTH`, etc.) |
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

```rust
#[link(name = "ssm")]
extern "C" {
    fn ssm_init(out: *mut *mut c_void, db_path: *const c_char,
                db_key: *const u8, db_key_len: usize) -> i32;
    fn ssm_destroy(h: *mut c_void) -> i32;
    fn ssm_user_register(h: *mut c_void, username: *const c_char,
                         password: *const c_char) -> i32;
    fn ssm_secret_get(h: *mut c_void, username: *const c_char, name: *const c_char,
                      priv_out: *mut u8, priv_len: *mut usize,
                      pub_out: *mut u8, pub_len: *mut usize) -> i32;
    fn ssm_status_to_string(status: i32) -> *const c_char;
}

pub struct Vaultine {
    handle: *mut c_void,
}

impl Vaultine {
    pub fn new(db_path: &str, db_key: &[u8]) -> Result<Self, i32> {
        let mut handle = std::ptr::null_mut();
        let path = CString::new(db_path).unwrap();
        let status = unsafe {
            ssm_init(&mut handle, path.as_ptr(), db_key.as_ptr(), db_key.len())
        };
        if status != 0 { return Err(status); }
        Ok(Self { handle })
    }

    pub fn user_register(&self, username: &str, password: &str) -> Result<(), i32> {
        let u = CString::new(username).unwrap();
        let p = CString::new(password).unwrap();
        let st = unsafe { ssm_user_register(self.handle, u.as_ptr(), p.as_ptr()) };
        if st != 0 { Err(st) } else { Ok(()) }
    }

    pub fn secret_get(&self, username: &str, name: &str) -> Result<Vec<u8>, i32> {
        let u = CString::new(username).unwrap();
        let n = CString::new(name).unwrap();
        let mut buf = vec![0u8; 4096];
        let mut len = buf.len();
        let mut pub_buf = vec![0u8; 4096];
        let mut pub_len = pub_buf.len();
        let st = unsafe {
            ssm_secret_get(self.handle, u.as_ptr(), n.as_ptr(),
                           buf.as_mut_ptr(), &mut len,
                           pub_buf.as_mut_ptr(), &mut pub_len)
        };
        if st != 0 { return Err(st); }
        buf.truncate(len);
        Ok(buf)
    }
}

impl Drop for Vaultine {
    fn drop(&mut self) {
        unsafe { ssm_destroy(self.handle); }
    }
}
```

### Go (cgo)

```go
/*
#cgo LDFLAGS: -L./build -lssm
#include "ssm/ssm.h"
*/
import "C"
import "unsafe"

type Vaultine struct {
    handle unsafe.Pointer
}

func New(dbPath string, dbKey []byte) (*Vaultine, error) {
    var h unsafe.Pointer
    cpath := C.CString(dbPath)
    defer C.free(unsafe.Pointer(cpath))
    var keyPtr *C.uchar
    var keyLen C.size_t
    if len(dbKey) > 0 {
        keyPtr = (*C.uchar)(unsafe.Pointer(&dbKey[0]))
        keyLen = C.size_t(len(dbKey))
    }
    st := C.ssm_init(&h, cpath, keyPtr, keyLen)
    if st != C.SSM_OK {
        return nil, fmt.Errorf("ssm_init: %s", C.GoString(C.ssm_status_to_string(st)))
    }
    return &Vaultine{handle: h}, nil
}

func (s *Vaultine) SecretGet(username, name string) ([]byte, error) {
    cu := C.CString(username)
    cn := C.CString(name)
    defer C.free(unsafe.Pointer(cu))
    defer C.free(unsafe.Pointer(cn))
    buf := make([]byte, 4096)
    blen := C.size_t(len(buf))
    st := C.ssm_secret_get(s.handle, cu, cn,
        (*C.uchar)(unsafe.Pointer(&buf[0])), &blen, nil, nil)
    if st != C.SSM_OK {
        return nil, fmt.Errorf("secret_get: %s", C.GoString(C.ssm_status_to_string(st)))
    }
    return buf[:blen], nil
}

func (s *Vaultine) Close() {
    C.ssm_destroy(s.handle)
}
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
