# AGENTS.md — Vaultine

**Projeto:** Biblioteca dinâmica C++ (.so) POSIX para gerenciamento criptográfico de segredos multi-tenant.

## Pilares Metodológicos

- **KISS**: API minimalista, fluxo linear, sem padrões complexos (complexidade = vetor de ataque).
- **TDD**: Testes unitários/integração obrigatórios antes do código. SQLite in-memory para fixtures. Validar: sucesso, tag GCM corrompida, expiração KEK, concorrência massiva.
- **SDD** (Security-Driven Development): Sanitizar entradas (tamanho/formato). `memset_s` em buffers sensíveis após uso. Erros opacos — sem vazar detalhes de implementação.

## Stack

- **C++** → Shared Object (.so) POSIX
- **SQLite + SQLCipher** (criptografia em repouso no arquivo)
- **OpenSSL** (primitivas criptográficas)
- Thread-safety: `SQLITE_OPEN_FULLMUTEX` + `std::shared_mutex`

## Hierarquia Criptográfica

| Etapa | Algoritmo | Detalhe |
|-------|-----------|---------|
| Hash de senha | ARGON2ID | 64 bytes — somente para autenticação |
| Proteção KEK (repouso) | AES-KW-256 | Chave de wrap derivada de: hash_autenticação + salt |
| Criptografia de segredos | AES-GCM-256 | AEAD: tag de 16B, nonce de 12B |
| Rotação KEK | AES-KW-256 → AES-GCM-256 | Re-wrap atômico |

## Ciclo de Vida da KEK

- **Validade:** 90 dias (configurável por tenant)
- **Gatilho:** qualquer operação da API verifica expiração
- **Fluxo de rotação:** gerar nova KEK → descriptografar segredos em memória → re-criptografar com KEK nova → encapsular nova KEK → **transação ACID única** (rollback total se falhar)

## Schema SQLite

### `users`
| Coluna | Tipo | Restrição |
|--------|------|-----------|
| `id` | INTEGER | PK AUTOINCREMENT |
| `username` | TEXT | UNIQUE NOT NULL |
| `password_hash` | BLOB | NOT NULL (Argon2id encoded string, ~128B, embeds salt + params) |
| `created_at` | TEXT | NOT NULL DEFAULT CURRENT_TIMESTAMP |

### `kek_metadata`
| Coluna | Tipo | Restrição |
|--------|------|-----------|
| `id` | INTEGER | PK AUTOINCREMENT |
| `user_id` | INTEGER | FK → users(id) ON DELETE CASCADE |
| `wrapped_kek` | BLOB | NOT NULL (AES-KW-256) |
| `salt` | BLOB | NOT NULL |
| `expires_at` | TEXT | NOT NULL (UTC, default +90d) |

### `audit_log`
| Coluna | Tipo | Restrição |
|--------|------|-----------|
| `id` | INTEGER | PK AUTOINCREMENT |
| `user_id` | INTEGER | NULLABLE |
| `username` | TEXT | NOT NULL |
| `operation` | TEXT | NOT NULL |
| `operation_target` | TEXT | NULLABLE (ex: nome do secret) |
| `details` | TEXT | NULLABLE (ex: motivo do erro) |
| `result` | TEXT | NOT NULL |
| `timestamp` | TEXT | NOT NULL DEFAULT CURRENT_TIMESTAMP |

### `secrets`
| Coluna | Tipo | Restrição |
|--------|------|-----------|
| `id` | INTEGER | PK AUTOINCREMENT |
| `user_id` | INTEGER | FK → users(id) ON DELETE CASCADE |
| `name` | TEXT | NULLABLE |
| `private_key` | BLOB | NOT NULL (AES-GCM-256) |
| `public_key` | BLOB | NULLABLE |
| `nonce` | BLOB | NOT NULL |
| `tag` | BLOB | NOT NULL (16B GCM auth tag) |
| `description` | TEXT | NULLABLE |
| `updated_at` | TEXT | NOT NULL DEFAULT CURRENT_TIMESTAMP |

## API Pública — Novas Features (v0.2)

### Validação de Senha
```c
typedef ssm_status (*ssm_password_validator)(const char* password, void* user_data);
void ssm_set_password_validator(ssm_password_validator validator, void* user_data);
```
- Default: mínimo 4 caracteres
- `NULL` restaura o validador default
- Chamado em `ssm_user_register` e `ssm_user_change_password`

### Cache Statistics
```c
typedef struct {
    size_t total_entries;   // SSM_CACHE_MAX = 256
    size_t valid_entries;   // entradas atualmente válidas
    size_t hit_count;       // acertos cumulativos
    size_t miss_count;      // erros cumulativos
} ssm_cache_stats;

ssm_status ssm_cache_get_stats(ssm_handle* h, ssm_cache_stats* out);
```
- Contadores desde a criação do handle
- Thread-safe (shared_mutex)

### Secure Buffer (mlock)
```cpp
void* secure_alloc(size_t size) noexcept;   // malloc + mlock
void secure_free(void* ptr, size_t size) noexcept;  // munlock + free

template <typename T>
class secure_buffer;  // RAII wrapper sobre secure_alloc/secure_free
```
- Previne swapping de chaves criptográficas para disco
- Destrutor faz `secure_erase` + `munlock` + `free`

### Audit Log — operation_target / details
- `audit_log.operation_target` — nome do secret ou alvo da operação
- `audit_log.details` — detalhes do erro ou contexto adicional
- Populado automaticamente em `secret_store`, `secret_get`, `secret_delete`, `kek_rotate`

## Comandos

### Dependências (sistema)
```bash
# Debian/Ubuntu
apt install libsqlcipher-dev libsodium-dev libssl-dev libncursesw5-dev \
            cmake pkg-config

# Termux
pkg install libsodium openssl sqlite ncursesw cmake ninja

# ou via Vcpkg (alternativa):
cmake -B build -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg.cmake
```

### Build
```bash
cmake -B build
cmake --build build
```

### Testes
```bash
ctest --test-dir build --output-on-failure
# ou direto:
./build/tests/ssm_test
```

### TUI (ncurses)
```bash
ssm-cli tui
```
Menu principal com submenus para todas as operações (user/secret/kek). Navegação com ↑↓, Enter, Esc. Senhas com ocultação `*`.

### Lint / formatação
```bash
# clang-format (formatar todo o código)
find src/ include/ tests/ -name '*.cc' -o -name '*.h' | xargs clang-format -i

# clang-tidy (precisa de compile_commands.json)
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
run-clang-tidy -p build src/
```

### Release build (produção)
```bash
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
# SSM_VISIBILITY_HIDDEN é forçado ON em Release automaticamente
# Apenas símbolos SSM_EXPORT visíveis no .so
```
