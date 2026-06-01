# SSM — Software Security Module

Biblioteca dinâmica C++ (.so) POSIX para gerenciamento criptográfico de segredos multi-tenant com SQLCipher.

## Índice

- [Visão Geral](#visão-geral)
- [Stack](#stack)
- [Build](#build)
- [API Pública](#api-pública)
- [Exemplos](#exemplos)
- [Hierarquia Criptográfica](#hierarquia-criptográfica)
- [Ciclo de Vida da KEK](#ciclo-de-vida-da-kek)
- [Thread Safety](#thread-safety)
- [Schema SQLite](#schema-sqlite)

---

## Visão Geral

SSM é um cofre de chaves criptográficas multi-tenant. Cada usuário possui um **KEK** (Key Encryption Key) de 256-bit que protege todos os seus segredos. O KEK é armazenado **wrapped** (AES-KW-256) e só é deswrapped em memória durante operações, usando uma chave derivada do hash de autenticação do usuário + salt.

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
Usuário armazena segredo → KEK unwrapped em memória → AES-GCM encrypt → KEK zerado
       │
Usuário lê segredo → KEK unwrapped em memória → AES-GCM decrypt → KEK zerado
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
# Apenas 8 símbolos visíveis no .so
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
    SSM_ERR_AUTH        = 1,  // usuário não encontrado
    SSM_ERR_NOT_FOUND   = 2,  // segredo não encontrado
    SSM_ERR_EXPIRED     = 3,  // KEK expirado
    SSM_ERR_INTEGRITY   = 4,  // AES-GCM tag mismatch (dados corrompidos)
    SSM_ERR_INTERNAL    = 5   // erro interno (DB, crypto, OOM)
} ssm_status;
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

### ssm_secret_store / ssm_secret_get / ssm_secret_delete

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
```

- `private_key`: **sempre criptografada** com AES-GCM-256 usando o KEK do usuário.
- `public_key`: armazenada **plaintext** (chaves públicas são públicas).
- `name`: identificador único do segredo dentro do escopo do usuário.

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

### Tratamento de Erros

```c
ssm_status status = ssm_secret_get(h, "unknown-user", "key",
                                   out, &len, NULL, NULL);

switch (status) {
    case SSM_OK:              break;
    case SSM_ERR_AUTH:        printf("usuário não encontrado\n"); break;
    case SSM_ERR_NOT_FOUND:   printf("segredo não existe\n"); break;
    case SSM_ERR_EXPIRED:     printf("KEK expirado — rode ssm_kek_rotate\n"); break;
    case SSM_ERR_INTEGRITY:   printf("dados corrompidos ou KEK incorreto\n"); break;
    case SSM_ERR_INTERNAL:    printf("erro interno\n"); break;
}
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

## Thread Safety

- `SQLITE_OPEN_FULLMUTEX`: SQLite serializa acesso interno.
- `std::shared_mutex` no `ssm_handle`: protege operações multi-step (especialmente rotação).
- Todas as funções da API pública adquirem `unique_lock` no início.

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
| `updated_at` | TEXT | DEFAULT CURRENT_TIMESTAMP |
