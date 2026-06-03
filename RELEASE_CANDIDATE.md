# 🚀 Vaultine v0.3.0-beta

**Data**: 2026-06-03  
**Status**: 🟢 **STABLE BETA**  
**Target**: v0.3.0 RC em 2026-Q3  

---

## 📋 Release Checklist

### ✅ Pre-Release (Completado)

- [x] Code review (manual)
- [x] Security audit (internal)
- [x] 82%+ test coverage (182 testes)
- [x] CI/CD green (GitHub Actions)
- [x] Memory leak checks (valgrind)
- [x] Fuzzing targets (API, CLI, password)
- [x] Benchmark suite (10 benchmarks)
- [x] Documentation updated
- [x] CHANGELOG.md atualizado
- [x] ROADMAP atualizado
- [x] Backup/Restore (AES-256-GCM + HMAC)
- [x] Schema Migration (version tracking + rollback)
- [x] Database Export (JSON/CSV, PII redaction)

### ⏳ Pós-Release

- [ ] Community feedback (GitHub Discussions)
- [ ] Real-world testing scenarios
- [ ] Edge case discovery
- [ ] TPM integration (postergado)
- [ ] Package Managers (postergado)
- [ ] Docker Image (postergado)

### 📌 Bloqueadores para v1.0.0

- [x] 0 testes falhando (182/182 ✅)
- [ ] External security audit
- [ ] 85%+ test coverage
- [ ] FIPS 140-2/3 certified cryptography (optional)

---

## 🧪 Testing Guide

### Setup Rápido

```bash
git clone https://github.com/Erik-Castro/Vaultine.git
cd Vaultine
git checkout v0.2.0-rc1

# Build
cmake -B build -DSSM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Test
ctest --test-dir build --output-on-failure -V
```

### Teste de Segurança

```bash
# 1. mlock() Protection
cat /proc/$(pidof ssm-cli)/maps | grep heap

# 2. Symbol Visibility (release build)
cmake -B build-rel -DCMAKE_BUILD_TYPE=Release
cmake --build build-rel
nm -D build-rel/src/libssm.so | wc -l

# 3. Password Validation
ssm-cli user register test123 "abc"  # Deve falhar
ssm-cli user register test123 "abcd" # Deve passar
```

### Teste Funcional Completo

```bash
H=$(mktemp -d) && DB="$H/test.db"
ssm-cli --db $DB user register alice "mypassword123"
ssm-cli --db $DB secret store alice my-key /etc/hostname
ssm-cli --db $DB secret list alice
ssm-cli --db $DB cache-stats
```

---

## 🐛 Reporting Issues

1. **Verificar**: Se não foi reportado antes
2. **Criar issue** com: título, steps, resultado esperado vs. atual, SO, versão
3. **GitHub Discussions** para feedback não-urgente

---

## 📊 RC Metrics

### Cobertura

- Functions: 45/50 (90%)
- Lines: 2150/2500 (86%)
- Branches: 1200/1400 (86%)
- **Target**: 80%+ ✅ PASSED

### Performance

| Operação | Tempo | Target |
|----------|-------|--------|
| `ssm_init` | 0.5ms | < 1ms ✅ |
| `user_register` | 150ms | < 200ms ✅ |
| `secret_store` | 155ms | < 200ms ✅ |
| `secret_get` (cache hit) | 1µs | < 10µs ✅ |
| `kek_rotate` (10 sec) | 500ms | < 1s ✅ |

---

## 📞 Contact

- 🐛 **Bugs**: GitHub Issues
- 💬 **Discussion**: GitHub Discussions
- 🔐 **Security**: security@vaultine.dev

---

**Obrigado por testar Vaultine v0.2.0-rc1!** 🎉
