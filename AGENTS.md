# AGENTS.md — SSM (Software Security Module)

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

## Comandos

### Dependências (sistema)
```bash
# Debian/Ubuntu
apt install libsqlcipher-dev libsodium-dev libssl-dev cmake pkg-config

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

### Visibility
- API pública: marcada com `SSM_EXPORT` em `include/ssm/ssm.h`
- Internals: `-fvisibility=hidden` via `-DSSM_VISIBILITY_HIDDEN=ON`
- Símbolos internos (`ssm::v1`) invisíveis para quem linkedita o .so
- Dev (default): `OFF` — testes acessam símbolos internos do .so

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
cmake -B build-release -DSSM_VISIBILITY_HIDDEN=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
# Apenas 8 símbolos SSM_EXPORT visíveis no .so
```
