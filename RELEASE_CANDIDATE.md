# 🚀 Vaultine v0.2.0-rc1 Release Candidate

**Data**: 2026-06-01  
**Status**: 🟡 **BETA TESTING**  
**Target**: v0.2.0 Stable em 2026-06-15  

---

## 📋 Release Checklist

### ✅ Pre-Release (Completado)

- [x] Code review (manual)
- [x] Security audit (internal)
- [x] 80%+ test coverage
- [x] CI/CD green (GitHub Actions)
- [x] Memory leak checks (valgrind)
- [x] Documentation updated
- [x] CHANGELOG.md criado
- [x] Roadmap publicado

### ⏳ Durante RC (Em Progresso)

- [ ] Community feedback (GitHub Discussions)
- [ ] Real-world testing scenarios
- [ ] Performance benchmarking
- [ ] Edge case discovery
- [ ] Documentation review

### 📌 Bloqueadores para v0.2.0 Stable

- [ ] 0 testes falhando
- [ ] 0 bloqueadores de segurança encontrados
- [ ] 80%+ test coverage mantido
- [ ] Fuzzing com libFuzzer (recomendado)

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
