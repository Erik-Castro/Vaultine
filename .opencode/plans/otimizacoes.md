# Plano de Otimizações — Vaultine

## P0 — Bugs / Segurança (7 itens)

### P0.1 — Transaction leak em kek.cc
**Arquivo:** `src/kek/kek.cc:134-148`
**Problema:** `BEGIN IMMEDIATE` executado antes de alocar `secure_buffer`s. Se a alocação falhar, a função retorna sem `ROLLBACK`.
**Correção:** Mover todas as 6 alocações `secure_buffer` para ANTES do `BEGIN IMMEDIATE`. Adicionar `if (sqlite3_exec(...) != SQLITE_OK) return false;`.

### P0.2 — UB const_cast em aes_gcm.cc
**Arquivo:** `src/crypto/aes_gcm.cc:93-94`
**Problema:** `const_cast<unsigned char*>(tag)` — objeto originalmente `const` passado como `void*` para OpenSSL (`EVP_CTRL_GCM_SET_TAG`). UB se o callee escrever.
**Correção:** Copiar tag para `unsigned char tag_copy[tag_len]` local e passar `tag_copy`.

### P0.3 — Json::CharReader leak em ssm_server.cc
**Arquivo:** `cli/ssm_server.cc:92-93`
**Problema:** `r.newCharReader()` aloca no heap, nunca chamado `delete`.
**Correção:** Substituir por `Json::parseFromStream` (que não aloca) ou envolver em `unique_ptr`.

### P0.4 — Integer underflow em fuzz_password.cc
**Arquivo:** `tests/fuzz/fuzz_password.cc:24`
**Problema:** Se `pos >= size`, `avail = size - pos` wrappa para `SIZE_MAX`, causando OOB read em `memcpy`.
**Correção:** Adicionar `if (pos >= size) return {};` no início do lambda `consume_segment`.

### P0.5 — Key separation violada em backup.cc
**Arquivo:** `src/backup/backup.cc:79,96`
**Problema:** Mesma `key` de 32 bytes usada para AES-GCM e HMAC-SHA256.
**Correção:** Derivar `enc_key` e `hmac_key` via `crypto_hash_sha256` com prefixes "enc" e "hmac".

### P0.6 — API enganosa em argon2id.cc
**Arquivo:** `src/crypto/argon2id.h:8-10`, `src/crypto/argon2id.cc:7-10`
**Problema:** `salt`/`salt_len` aceitos mas silenciosamente ignorados. `crypto_pwhash_str` gera salt próprio.
**Correção:** Remover `salt`/`salt_len` da assinatura. Atualizar todos os callers.

### P0.7 — Integer overflow em secure_memory.h
**Arquivo:** `src/utils/secure_memory.h:37,83,109,151,166`
**Problema:** `count * sizeof(T)` wrappa silenciosamente se `count` grande.
**Correção:** Adicionar guarda `if (count > max / sizeof(T)) return nullptr;` antes de cada alocação.

---

## P1 — Performance (8 itens)

### P1.1 — sqlite3_prepare_v2 dentro do loop em kek.cc
**Arquivo:** `src/kek/kek.cc:216`
**Problema:** `sqlite3_prepare_v2` chamado a cada iteração do loop de re-encrypt.
**Correção:** Mover `prepare` para fora do loop; reusar statement com `sqlite3_reset` + `sqlite3_bind_*`.

### P1.2 — Buffers alocados por iteração em kek.cc
**Arquivo:** `src/kek/kek.cc:189,202`
**Problema:** `secure_vector<unsigned char>` alocado a cada iteração.
**Correção:** Pré-alocar `plain_priv` e `new_priv` com tamanho máximo antes do loop.

### P1.3 — URI parsing O(n²) em ssm_server.cc
**Arquivo:** `cli/ssm_server.cc:111-142`
**Problema:** `string::erase(0, pos+1)` recria string a cada segmento.
**Correção:** Usar `std::string_view` com `substr` para splits zero-copy.

### P1.4 — 128KB na stack em ssm_server.cc
**Arquivo:** `cli/ssm_server.cc:334`
**Problema:** `unsigned char priv_buf[65536], pub_buf[65536]` — risco de stack overflow.
**Correção:** Usar `std::vector<unsigned char>` no heap.

### P1.5 — Export strings O(n²)
**Arquivo:** `src/export/export.cc` (múltiplos `emit_*`)
**Problema:** Concatenação `+=` repetida sem `reserve`.
**Correção:** Adicionar `out.reserve(4096)` antes do loop principal de export, ou usar `ostringstream`.

### P1.6 — EVP_CIPHER_CTX alocado/free por chamada
**Arquivo:** `src/crypto/aes_gcm.cc:16,54,65,104`
**Problema:** Cada encrypt/decrypt aloca + libera contexto OpenSSL.
**Correção:** Usar `EVP_CIPHER_CTX_new` + `EVP_CIPHER_CTX_reset()` para reuso via variável thread_local.

### P1.7 — secrets_list sem reserve
**Arquivo:** `src/db/secrets.cc:167`
**Problema:** `vector<secret_row>` realoca múltiplas vezes.
**Correção:** Adicionar `out->reserve(64)` após o `clear()`.

### P1.8 — HMAC verification copia backup inteiro
**Arquivo:** `src/backup/backup.cc:150-158`
**Problema:** Aloca + copia backup inteiro só para HMAC.
**Correção:** Usar `crypto_auth_hmacsha256_update` 3x (header, ciphertext, tag) sem alocação extra.

---

## P2 — Qualidade de Código (17 itens)

### P2.1 — getpass deprecated + password na stack (ssm_cli.cc)
**Arquivo:** `cli/ssm_cli.cc:43,51`
**Problema:** `getpass()` usa buffer estático não wiped; `char buf[4096]` na stack.
**Correção:** Usar `secure_vector<char>` + `sodium_memzero` no final.

### P2.2 — Backup key na stack, nunca wiped (ssm_server.cc)
**Arquivo:** `cli/ssm_server.cc:420,441`
**Problema:** `unsigned char key[32]` no stack dos handlers de backup; não wiped.
**Correção:** Envolver em `secure_vector<unsigned char>`.

### P2.3 — strncpy pode não null-terminar
**Arquivo:** `cli/ssm_server.cc:829`
**Problema:** `strncpy` com n = sizeof-1 ainda pode não null-terminar.
**Correção:** `std::snprintf(g_pidfile, sizeof(g_pidfile), "%s", pidfile)`.

### P2.4 — hex_decode retorna raw new[]
**Arquivo:** `cli/hex_utils.h:35-52`
**Problema:** Retorna `unsigned char*` via `new[]` — caller precisa lembrar `delete[]`.
**Correção:** Mudar retorno para `std::vector<unsigned char>`.

### P2.5 — Raw new[]/delete[] em ssm_cli.cc
**Arquivo:** `cli/ssm_cli.cc:321,340,359,411-435`
**Problema:** 5+ caminhos manuais de `new[]`/`delete[]` — leak-prone.
**Correção:** Substituir por `std::vector<unsigned char>`.

### P2.6 — atoll sem validação
**Arquivo:** `cli/ssm_cli.cc:617-618`, `cli/ssm_server.cc:517-518`
**Problema:** `std::atoll`/`std::atol` sem verificar erro.
**Correção:** Usar `std::from_chars` (C++17) ou `strtoll` com `errno`.

### P2.7 — C-style casts
**Arquivo:** `cli/ssm_server.cc:269,494-497,555-556,588`
**Problema:** `(Json::UInt64)expr` e `(ssm_export_format)expr`.
**Correção:** `static_cast<Json::UInt64>(expr)` e `static_cast<ssm_export_format>(expr)`.

### P2.8 — Wipe manual volatile
**Arquivo:** `cli/ssm_cli.cc:895-898`
**Problema:** Loop `volatile` para wipe — compilador pode otimizar.
**Correção:** Usar `sodium_memzero(priv, priv_len)`.

### P2.9 — secrets_list dead code
**Arquivo:** `src/db/secrets.h:33,35` e `src/db/secrets.cc:148-149`
**Problema:** `secrets_list` é wrapper idêntico a `secrets_list_for_user`, sem callers.
**Correção:** Remover.

### P2.10 — std::size não usado
**Arquivo:** `src/db/migrations.cc:14`
**Problema:** `sizeof(migrations)/sizeof(migrations[0])`.
**Correção:** `std::size(migrations)` de `<iterator>`.

### P2.11 — push_back → emplace_back
**Arquivo:** `cli/ssm_cli.cc:503`
**Problema:** `items->push_back({...})` copia strings.
**Correção:** `items->emplace_back(...)`.

### P2.12 — strdup/free com const_cast
**Arquivo:** `tests/ssm_test.cc:653,665`
**Problema:** `strdup` + `const_cast` + `std::free`.
**Correção:** Usar `std::string` para `path_`.

### P2.13 — sodium_init múltiplas vezes
**Arquivo:** `src/crypto/argon2id.cc:15,28`, `src/kek/kek.cc:27`
**Problema:** `sodium_init()` chamado em cada função.
**Correção:** Chamar uma vez em `ssm_init()` e remover das leaf functions.

### P2.14 — export.h inclui ssm.h inteiro
**Arquivo:** `src/export/export.h:3`
**Problema:** `#include "ssm/ssm.h"` desnecessário.
**Correção:** Forward-declare `ssm_status`, `ssm_export_format`, `ssm_export_cb`.

### P2.15 — benchmark sem check de retorno
**Arquivo:** `tests/bench_ssm.cc`
**Problema:** `ssm_init`, `ssm_user_register`, etc sem verificação.
**Correção:** Adicionar `ASSERT_EQ` nos benchmarks.

### P2.16 — migrations.h raw C array
**Arquivo:** `src/db/migrations.h:32-33`
**Problema:** `extern const Migration migrations[]` + count.
**Correção:** `constexpr std::array<Migration, N>`.

### P2.17 — memset em dados sensíveis
**Arquivo:** `src/backup/backup.cc:114,180,184`
**Problema:** `std::memset` para limpar dados — pode ser otimizado.
**Correção:** Substituir por `sodium_memzero`.

---

## P3 — Build / Infra (3 itens)

### P3.1 — Comentário CMake desatualizado
**Arquivo:** `CMakeLists.txt:9-10`
**Problema:** Comentário sobre visibility "left off during active development".
**Correção:** Atualizar — já é forçado em Release.

### P3.2 — PCH inclui mutex em vez de shared_mutex
**Arquivo:** `src/CMakeLists.txt:39`
**Problema:** `<mutex>` incluído mas código usa `shared_mutex`.
**Correção:** Trocar `<mutex>` por `<shared_mutex>`.

### P3.3 — Timestamp uint32_t (year 2038)
**Arquivo:** `src/backup/backup.cc:71`
**Problema:** `uint32_t` para timestamp no header de backup.
**Correção:** Usar `uint64_t`.

---

## Ordem de Execução Sugerida

1. **P0.4** (1 arquivo, 1 linha)
2. **P0.6** (3 arquivos: header + impl + callers)
3. **P0.2** (1 arquivo, 4 linhas)
4. **P0.3** (1 arquivo, ~5 linhas)
5. **P0.1** (1 arquivo, ~3 linhas)
6. **P0.7** (1 arquivo, ~6 linhas)
7. **P0.5** (1 arquivo, ~15 linhas)
8. P1-P3 em lotes por arquivo (minimiza rebuilds)
