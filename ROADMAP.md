# Vaultine Roadmap 2026

**Visão**: Biblioteca C++ embarcada para gerenciamento criptográfico de segredos multi-tenant — zero dependências externas, pronta para produção.

---

## Current Status: v0.3.1-beta ✅

O core do Vaultine está completo: API C, CLI, TUI, REST API server, bindings (Python/Rust/Go/Node.js). 33 otimizações aplicadas — bugs de segurança, performance, qualidade de código e build.

| Release | Status | O que inclui |
|---------|--------|-------------|
| **v0.1.0-alpha** | ✅ Entregue | API Core, CLI, TUI, Python bindings |
| **v0.2.0-beta** | ✅ Entregue | Segurança (mlock, password validation, audit logs), testes (182), CI/CD, fuzzing, benchmark suite |
| **v0.3.0-beta** | ✅ ENTREGUE | Schema migration, backup/restore, export JSON/CSV, bindings (Rust/Go/Node.js), REST API server |
| **v0.3.1-beta** | ✅ **LANÇADO** | 33 otimizações (P0-P3): 7 bugs, 8 perf, 15 qualidade, 3 build. backup format v2 |
| **v1.0.0-rc** | 🔜 Próximo | Security audit, package managers, Docker, Java bindings, comunidade |

---

## v0.3.1-beta — Otimizações & Correções ✅

### Completado (33 otimizações)
- [x] **P0 — Bugs/Segurança (7/7)**: transaction leak, const_cast UB, Json leak, fuzz underflow, key separation, argon2id API, overflow guards
- [x] **P1 — Performance (8/8)**: prepare fora loop, buffers pré-alocados, string_view URI, stack→heap, EVP_CTX thread_local, streaming HMAC
- [x] **P2 — Qualidade (15/17)**: getpass heap, backup key wiped, snprintf, vector replace, strtoll, static_cast, sodium_memzero, dead code removido, std::size, strdup→string, sodium_init centralizado, export.h forward-declare, migrations.h std::array, benchmark checks
- [x] **P3 — Build (3/3)**: CMake comment, PCH shared_mutex, backup timestamp uint64

### Bloqueado (requer ambiente específico)
| Item | Bloqueio |
|------|----------|
| 🔴 TPM Integration (2.1.1) | Sem hardware TPM no ambiente |
| 🔴 Package Managers (2.3.1) | Recipe files podem ser escritos, sem ambiente para testar |
| 🔴 Docker Image (2.3.2) | Dockerfile pode ser escrito, sem Docker Engine |
| 🔴 Java Bindings | JDK não instalado (OpenJDK 17+ ausente no Termux) |

---

## v1.0.0-rc — Checklist

### 🔐 Segurança & Qualidade
- [ ] **Security audit profissional** (Cure53 / Trail of Bits / NCCGROUP)
  - Requer funding (~$15-50K)
  - Escopo: design criptográfico, memory safety, penetração, threat modeling
- [ ] FIPS 140-2 compliance (opcional, via OpenSSL FIPS provider)

### 📦 Distribuição
- [ ] Debian package (sbuild, `debian/control`)
- [ ] Homebrew formula (`libssm.rb`)
- [ ] Conan recipe
- [ ] Docker image (multi-stage, Docker Hub)
- [ ] CI: automated releases

### 🌍 Community & Ecosystem
- [ ] Java bindings (JNI)
- [ ] GitHub Discussions
- [ ] FAQ section
- [ ] Package registry publication (crates.io, PyPI, npm)
- [ ] Blog / technical posts

---

## Como Contribuir

Veja [CONTRIBUTING.md](./CONTRIBUTING.md) e [AGENTS.md](./AGENTS.md) para setup do ambiente de desenvolvimento.

```bash
git clone https://github.com/Erik-Castro/Vaultine.git
cd Vaultine
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

---

*Vaultine 2026 — do "projeto legal de segurança" para o padrão de ouro em key management embarcado.*
