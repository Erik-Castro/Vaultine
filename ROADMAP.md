# Vaultine Roadmap 2026

**Visão**: Biblioteca C++ embarcada para gerenciamento criptográfico de segredos multi-tenant — zero dependências externas, pronta para produção.

---

## Current Status: v0.3.0-beta — Feature Complete

O core do Vaultine está completo. O que resta é distribuição, bindings para linguagens faltantes, e auditoria de segurança externa.

| Release | Status | O que inclui |
|---------|--------|-------------|
| **v0.1.0-alpha** | ✅ Entregue | API Core, CLI, TUI, Python bindings |
| **v0.2.0-beta** | ✅ Entregue | Segurança (mlock, password validation, audit logs), testes (182), CI/CD, fuzzing, benchmark suite |
| **v0.3.0-beta** | 🟡 **ATUAL** | Schema migration, backup/restore, export JSON/CSV, bindings (Rust/Go/Node.js) |
| **v1.0.0-rc** | 🔜 Próximo | Security audit, package managers, Docker, Java bindings, comunidade |

---

## v0.3.0-beta — Feature Complete ✓

### Completado
- [x] Schema migration (version tracking + rollback)
- [x] Backup/restore (AES-256-GCM + HMAC-SHA256)
- [x] Export JSON/CSV (com PII redaction)
- [x] Bindings: **Rust** (crate `vaultine`, 8 tests)
- [x] Bindings: **Go** (package `vaultine`, 11 tests)
- [x] Bindings: **Node.js** (N-API addon, 25 tests)
- [x] CLI completo (user, secret, kek, cache-stats, env exec, tui)
- [x] 182 testes C, testes de integração para todas as 3 linguagens
- [x] Error message clarity, user enumeration fix

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
