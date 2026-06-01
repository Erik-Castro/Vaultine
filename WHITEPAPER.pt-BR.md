# Vaultine: Um Módulo de Gerenciamento de Chaves Multi-Tenant para Sistemas POSIX

**Design Criptográfico, Modelo de Ameaças e Garantias de Segurança**

| Versão | Data | Autor |
|---------|------|--------|
| 1.1 | 2026-06 | Vaultine Engineering |

---

## Resumo

Apresentamos o **Vaultine**, uma biblioteca compartilhada C++ (.so) para sistemas POSIX que provê gerenciamento criptográfico de segredos para ambientes multi-tenant. O Vaultine implementa uma arquitetura hierárquica de chaves onde os segredos de cada locatário são criptografados com uma Chave de Criptografia de Chaves (KEK) única de 256 bits, que é protegida por um esquema de key-wrapping (AES-KW-256) usando uma chave de wrapping derivada do usuário. O sistema impõe rotação de KEK a cada 90 dias, realiza re-wrapping atômico durante a rotação via transações SQLite, suporta troca de senha com re-wrapping atômico da KEK, e provê criptografia autenticada (AES-GCM-256) para todos os segredos armazenados. Um log de auditoria interno registra todas as operações, e um cache LRU de chaves de wrapping (256 entradas) elimina invocações redundantes de KDF para cenários de alta vazão. Este artigo descreve o modelo de ameaças, a fundamentação do design criptográfico, a análise de segurança e as considerações de implementação.

---

## 1. Introdução

Aplicações modernas precisam gerenciar chaves criptográficas para múltiplos locatários — serviços em nuvem, plataformas de mensageria, sistemas financeiros e aplicações de saúde todos enfrentam o desafio de proteger segredos de locatários enquanto mantêm disponibilidade e performance. Uma abordagem ingênua de armazenar segredos em texto plano ou usar uma única chave mestre para todos os locatários expõe o sistema a um comprometimento catastrófico: uma única violação de banco de dados vaza os segredos de todos os locatários.

O Vaultine aborda isso com uma arquitetura **KEK por locatário**. Cada usuário (locatário) tem uma chave AES independente de 256 bits que protege apenas os segredos daquele usuário. Esta chave nunca existe em texto plano no disco — é armazenada wrapped (criptografada com outra chave) e é only unwrapped em memória durante a duração de uma operação. A chave de wrapping é derivada das credenciais de autenticação do usuário via um KDF memory-hard (Argon2id), provendo defesa em profundidade.

### 1.1 Objetivos de Design

1. **Isolamento de locatário**: o comprometimento da KEK de um locatário não deve afetar outros.
2. **Criptografia em repouso**: todos os dados persistentes são criptografados (SQLCipher) ou protegidos por integridade.
3. **Sigilo prospectivo via rotação**: a rotação periódica da KEK limita a janela de comprometimento.
4. **Criptografia autenticada**: ciphertext não pode ser modificado sem detecção.
5. **Operações atômicas**: falhas parciais não devem deixar o sistema em estado inconsistente.
6. **Autocontido**: sem dependência de HSM externo ou KMS remoto — a biblioteca é o módulo.

---

## 2. Modelo de Ameaças

### 2.1 Premissas

- O **sistema operacional** e o **hardware** são confiáveis (o Vaultine não defende contra ataques a nível de kernel, keyloggers de hardware ou ataques de boot a frio).
- A **aplicação** que chama o Vaultine é confiável com segredos em texto plano durante as chamadas de API — o Vaultine não provê proteção contra uma aplicação comprometida lendo sua própria pilha.
- O **arquivo de banco de dados** (`db_path`) é armazenado em um sistema de arquivos que pode estar acessível a atacantes (ex.: volumes em nuvem, backups, logs).
- A **senha do usuário** é a raiz da confiança — senhas fracas reduzem a segurança à força da senha.
- A **memória** do processo está livre de inspeção entre processos (isolamento padrão de processos POSIX).

### 2.2 Cenários de Ataque

| Ataque | Descrição | Mitigação |
|--------|-----------|------------|
| **Exfiltração de banco** | Atacante obtém acesso de leitura ao arquivo SQLite | KEKs são wrapped com AES-KW-256; segredos criptografados com AES-GCM-256; SQLCipher adiciona criptografia em repouso |
| **Roubo de credenciais** | Atacante obtém `password_hash` do BD | Hash de senha é Argon2id (lento + salt); chave de wrapping derivada requer invocação separada de KDF com salt armazenado |
| **Força bruta de senha** | Atacante tenta adivinhar senhas offline | Argon2id com opslimit MODERATE torna cada tentativa cara; `password_hash` não unwrap a KEK diretamente |
| **Adulteração** | Atacante modifica ciphertext no BD | Verificação de tag AES-GCM-256 detecta qualquer modificação (`SSM_ERR_INTEGRITY`) |
| **Comprometimento de KEK** | Atacante descobre a KEK de um locatário | Rotação a cada 90 dias limita exposição; isolamento por locatário impede movimento lateral |
| **Rollback** | Atacante substitui dados atuais por dados antigos | Rotação de KEK incrementa `kek_version` (schema extensível); timestamp de expiração impede uso indefinido |
| **Canal lateral** | Ataques de timing ou cache | AES-KW e AES-GCM não são constant-time na implementação OpenSSL (mitigado por isolamento arquitetural, não completamente) |

### 2.3 Fora do Escopo

- Ataques físicos (JTAG, probing, glitching)
- Memória de aplicação comprometida (atacante com RCE no processo chamador)
- Negação de serviço contra o banco SQLite
- Ataques a nível de rede (Vaultine não é um serviço de rede)

---

## 3. Design Criptográfico

### 3.1 Fundamentação da Seleção de Algoritmos

#### Argon2id

**Por quê**: Argon2id é o vencedor do PHC (Password Hashing Competition) e é recomendado pela OWASP e NIST (SP 800-63B). Provê resistência tanto contra ataques baseados em GPU (memory-hard) quanto contra ataques de canal lateral (data-independent).

**Vaultine usa dois modos distintos**:

| Uso | Função | Saída | Limite de Ops | Limite de Mem |
|-----|--------|-------|---------------|---------------|
| Hashing de senha | `crypto_pwhash_str` | String codificada (~128B) com salt + parâmetros | `OPSLIMIT_MODERATE` | `MEMLIMIT_MODERATE` |
| Derivação de chave | `crypto_pwhash` (raw, 32B) | Chave raw de 32 bytes a partir de `auth_hash + salt` | `OPSLIMIT_MODERATE` | `MEMLIMIT_MODERATE` |

O hash de senha é armazenado na coluna `users.password_hash`. A chave de wrapping é derivada *separadamente* usando um salt diferente (`kek_metadata.salt`). Isto significa:

- Comprometimento de `password_hash` não dá a chave de wrapping diretamente — a segunda invocação de KDF com um salt distinto é necessária.
- Cada rotação de KEK gera um novo salt, então a chave de wrapping muda mesmo se a senha permanecer a mesma.

#### AES-KW-256 (Key Wrap)

**Por quê**: AES Key Wrap (RFC 3394) é um algoritmo padronizado pelo NIST para criptografar chaves criptográficas com outras chaves. Provê integridade e é mais simples que um modo AEAD completo porque o texto plano é sempre múltiplo de 8 bytes (material de chave).

**Uso no Vaultine**: A KEK de 32 bytes é wrapped com uma chave de wrapping de 32 bytes, produzindo uma saída de 40 bytes (32 bytes de ciphertext + 8 bytes de valor de verificação de integridade). O resultado é armazenado em `kek_metadata.wrapped_kek`.

#### AES-GCM-256 (Modo Galois/Contador)

**Por quê**: GCM provê criptografia autenticada — a operação de descriptografia verifica uma tag de autenticação de 128 bits. Isto garante que:
1. O ciphertext não foi adulterado.
2. A KEK correta está sendo usada (crítico durante a rotação — re-wrapping com a KEK errada produziria incompatibilidade de tag, disparando detecção).

**Manuseio de nonce**: Um nonce aleatório de 12 bytes é gerado via `randombytes_buf` para cada criptografia. O nonce é armazenado junto com o ciphertext. Como cada segredo usa um nonce distinto e as KEKs são por locatário e rotacionadas regularmente, o risco de reúso de nonce sob a mesma chave é desprezível.

#### SQLCipher

SQLCipher provê AES de 256 bits em modo CBC com autenticação HMAC-SHA256 para todo o arquivo de banco de dados. Isto protege o banco quando a aplicação não está em execução. Durante a operação, o SQLCipher criptografa/descriptografa páginas transparentemente conforme são lidas/escritas.

No Termux (Android) e outras plataformas onde SQLCipher não está disponível, o Vaultine usa SQLite3 puro como fallback. Isto é aceitável para desenvolvimento mas deve ser evitado em produção.

### 3.2 Hierarquia de Chaves

```
Senha (fornecida pelo usuário)
    │
    ├──→ Argon2id (crypto_pwhash_str, OPSLIMIT_MODERATE)
    │       │
    │       └──→ password_hash (armazenado na tabela users)
    │               │
    │               ├──→ Usado para autenticação (crypto_pwhash_str_verify)
    │               │
    │               └──→ Argon2id (crypto_pwhash, raw 32B)
    │                       │
    │                       └──→ wrapping_key (efêmera, 32 bytes)
    │                               │
    │                               └──→ AES-KW-256 wrap/unwrap da KEK
    │
    └──→ KEK (randombytes_buf, 32 bytes)
            │
            ├──→ AES-GCM-256 encrypt/decrypt da private_key
            │
            └──→ → secrets.private_key (ciphertext)
                  → secrets.nonce (12 bytes)
                  → secrets.tag (16 bytes, tag GCM de autenticação)
```

**Propriedades das chaves**:

1. **Derivação de dois fatores**: A chave de wrapping depende TANTO do hash de senha do usuário QUANTO de um salt gerado aleatoriamente. Um atacante precisa tanto do banco de dados quanto da capacidade de computar Argon2id.
2. **Independência da KEK**: A KEK de cada locatário é independente — não há chave mestre ou chave de criptografia de chaves que abranja locatários.
3. **KEK nunca em disco**: A KEK existe em texto plano apenas na memória volátil durante operações da API, e é limpa via `secure_erase` (wrapper sobre `memset_s`/`explicit_bzero` com barreira de compilador) quando a operação termina.
4. **Cache de chave de wrapping**: Um cache LRU de 256 entradas em `ssm_handle` armazena chaves de wrapping derivadas, pulando o KDF Argon2id em operações repetidas para o mesmo locatário. O cache é invalidado na troca de senha ou rotação de KEK (quando a chave de wrapping muda), e todas as entradas são limpas com `secure_erase` em `ssm_destroy`.

---

## 4. Ciclo de Vida da KEK

### 4.1 Criação (Registro de Usuário)

Quando `ssm_user_register` é chamado:

1. Gerar `password_hash` via `crypto_pwhash_str(sodium, password, OPSLIMIT_MODERATE)`.
2. INSERT em `users(username, password_hash)`.
3. Gerar `salt` aleatório de 16 bytes via `randombytes_buf`.
4. Derivar `wrapping_key = crypto_pwhash(password_hash, salt, 32, OPSLIMIT_MODERATE)`.
5. Gerar `kek` de 32 bytes via `randombytes_buf`.
6. `wrapped_kek = aes_kw_wrap(kek, wrapping_key)`.
7. INSERT em `kek_metadata(user_id, wrapped_kek, salt, expires_at = now + 90d)`.

### 4.2 Uso (Operações com Segredos)

Para cada `ssm_secret_store` / `ssm_secret_get` / `ssm_secret_delete` / `ssm_secret_list`:

1. Autenticar: `crypto_pwhash_str_verify(stored_hash, password)`. Se falhar → `SSM_ERR_AUTH`.
2. Carregar `wrapped_kek` e `salt` de `kek_metadata`.
3. Tentar lookup no **cache de chave de wrapping**. Em miss: derivar `wrapping_key = crypto_pwhash(stored_hash, salt, 32, OPSLIMIT_MODERATE)` e inserir no cache.
4. `kek = aes_kw_unwrap(wrapped_kek, wrapping_key)`. Se integridade falhar → `SSM_ERR_INTERNAL`.
5. Verificar expiração: `now > expires_at` → `SSM_ERR_EXPIRED` (após limpar kek).
6. Realizar a operação de criptografia/descriptografia.
7. **Limpar todo material de chave efêmero** via `secure_erase` (o cache persiste entre chamadas).

### 4.3 Rotação

A rotação (`ssm_kek_rotate`) é a operação mais crítica:

**Algoritmo**:

1. `BEGIN IMMEDIATE` (adquirir lock transacional exclusivo).
2. Carregar `wrapped_kek`, `salt` atuais e todos os segredos do usuário.
3. Derivar `wrapping_key` atual de `password_hash + salt_atual`.
4. `kek_atual = aes_kw_unwrap(wrapped_kek_atual, wrapping_key_atual)`.
5. Gerar nova `kek_nova` de 32 bytes via `randombytes_buf`.
6. Gerar novo `salt_novo` de 16 bytes via `randombytes_buf`.
7. Derivar nova `wrapping_key_nova` de `password_hash + salt_novo`.
8. Para cada segredo (SELECT todos do usuário):
   a. `plaintext = aes_gcm_decrypt(private_key_enc, kek_atual, nonce, tag)`.
   b. Gerar `nonce_novo` via `randombytes_buf`.
   c. `(private_key_nova, tag_nova) = aes_gcm_encrypt(plaintext, kek_nova, nonce_novo)`.
   d. UPDATE secret SET `private_key = private_key_nova, nonce = nonce_novo, tag = tag_nova`.
   e. Limpar buffers intermediários.
9. `wrapped_kek_nova = aes_kw_wrap(kek_nova, wrapping_key_nova)`.
10. UPDATE `kek_metadata SET wrapped_kek = wrapped_kek_nova, salt = salt_novo, expires_at = now + 90d`.
11. `COMMIT`.
12. Em qualquer erro: `ROLLBACK`. O estado do sistema permanece inalterado.

**Garantia de atomicidade**: Como todas as operações ocorrem dentro de uma única transação SQLite (iniciada com `BEGIN IMMEDIATE` para prevenir deadlock), qualquer falha durante os passos 4–10 resulta em ROLLBACK completo. Os dados do usuário permanecem acessíveis com a KEK antiga.

**Consideração de performance**: A rotação é O(n) onde n é o número de segredos do usuário. Para usuários com milhares de segredos, isto pode levar um tempo significativo. Toda descriptografia/re-criptografia ocorre em memória para evitar expor texto plano ao disco.

### 4.4 Expiração

- Validade padrão: 90 dias (`KEK_DEFAULT_DAYS = 90`).
- Verificada em toda operação (store, get, delete, list).
- KEK expirada dispara `SSM_ERR_EXPIRED`, forçando a aplicação chamadora a invocar `ssm_kek_rotate`.
- A rotação redefine a data de expiração para `now + 90d`.

---

## 5. Detalhes de Implementação

### 5.1 Limpeza Segura de Memória

O Vaultine usa uma função `secure_erase` que:

```cpp
template <typename T>
void secure_erase(T& buf) {
    if (!std::empty(buf)) {
        auto ptr = std::data(buf);
        auto len = std::size(buf);
        volatile unsigned char* p =
            reinterpret_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < len; ++i) p[i] = 0;
        asm volatile("" : : "r"(p) : "memory");
    }
}
```

O qualificador `volatile` previne que o compilador otimize o zeramento. A barreira `asm volatile` garante que o memory clobber não seja reordenado através da barreira. Este padrão é mais seguro que `memset` (que o GCC pode otimizar) e equivalente a `memset_s` em plataformas C11.

### 5.2 Segurança em Concorrência

- SQLite é aberto com `SQLITE_OPEN_FULLMUTEX`, serializando todo acesso ao banco.
- Um `std::shared_mutex` envolve o `ssm_handle` para serializar operações multi-step (especialmente rotação, que envolve carregar todos os segredos, descriptografar, re-criptografar e escrever de volta).
- Todas as funções públicas da API adquirem um `std::unique_lock<std::shared_mutex>` antes de prosseguir.

### 5.3 Filosofia de Tratamento de Erros

Erros são deliberadamente **opacos**: a API retorna um valor enum (`SSM_ERR_AUTH`, `SSM_ERR_INTEGRITY`, etc.) sem vazar detalhes internos. A aplicação não pode distinguir entre "chave de banco errada" e "falha de inicialização do SQLCipher" — ambos mapeiam para `SSM_ERR_INTERNAL`. Isto previne vazamento de informação através de mensagens de erro.

### 5.4 Detecção de SQLCipher

Em tempo de build, o CMake detecta se os cabeçalhos e a biblioteca SQLCipher estão disponíveis. Se não, o Vaultine usa SQLite3 puro com um aviso em tempo de compilação. Isto permite desenvolvimento em plataformas como Termux onde SQLCipher não está disponível, enquanto garante que builds de produção linkem com criptografia completa em repouso.

---

## 6. Análise de Segurança

### 6.1 Exfiltração de Banco de Dados

Se um atacante obtém acesso de leitura ao arquivo SQLite:
- Com SQLCipher: o banco é criptografado com AES-256 + HMAC. Sem a `db_key`, o atacante não pode ler páginas.
- Sem SQLCipher: o atacante vê:
  - `users.password_hash`: string Argon2id (salt + parâmetros + hash). Força bruta é computacionalmente cara (OPSLIMIT_MODERATE ≈ 2 iterações, 64 MiB de memória).
  - `kek_metadata.wrapped_kek`: ciphertext AES-KW-256 (40 bytes). Requer a chave de wrapping para unwrap.
  - `kek_metadata.salt`: 16 bytes aleatórios — não secreto.
  - `secrets.private_key`: ciphertext AES-GCM-256 + nonce + tag. Requer a KEK para descriptografar.
  - `secrets.public_key`: texto plano (intencionalmente).

**Nível de segurança efetivo**: Assumindo que a senha do usuário tem ≥64 bits de entropia, o atacante enfrenta:
1. KDF Argon2id (OPSLIMIT_MODERATE) para derivar wrapping_key de password_hash + salt.
2. AES-KW unwrap para recuperar a KEK.
3. AES-GCM decrypt para cada segredo.

A dependência sequencial destas operações significa que cada locatário deve ser atacado independentemente — recuperar a KEK de Alice não ajuda a recuperar a de Bob.

### 6.2 Comprometimento do Hash de Senha

Mesmo que `password_hash` vaze (ex.: através de um backup), o atacante ainda precisa:
1. Ler `kek_metadata.salt` (também do mesmo banco de dados).
2. Computar `wrapping_key = crypto_pwhash(password_hash, salt, ..., OPSLIMIT_MODERATE)`.
3. Unwrap `wrapped_kek` com AES-KW-256.

O uso de um salt distinto (não o embutido na string Argon2id) garante que computar o hash de senha (passo 1 para autenticação) não computa simultaneamente a chave de wrapping. O atacante precisa executar Argon2id *novamente* com um salt diferente.

### 6.3 Adulteração de Ciphertext

AES-GCM-256 provê **criptografia autenticada**. A tag de autenticação de 16 bytes é verificada durante a descriptografia:
- Se o ciphertext é modificado: a verificação da tag falha → `SSM_ERR_INTEGRITY`.
- Se o nonce é modificado: a descriptografia produz lixo → incompatibilidade de tag.
- Se a própria tag é modificada: a verificação falha.

Isto garante detecção de qualquer adulteração, incluindo rollback de linhas individuais de segredos.

### 6.4 Rotação de KEK

A rotação de KEK provê **sigilo prospectivo**: se uma KEK é comprometida, a janela de exposição é no máximo o tempo até a próxima rotação (até 90 dias, ou imediatamente se a rotação for forçada). Após a rotação:
- Ciphertexts antigos (criptografados com KEK antiga) são re-criptografados com KEK nova.
- A KEK antiga wrapped é sobrescrita.
- A KEK antiga é limpa da memória.

**Garantia de atomicidade**: A rotação usa uma única transação SQLite (`BEGIN IMMEDIATE ... COMMIT`). Se o processo falhar no meio da rotação:
- Antes da transação começar: nenhuma alteração.
- Durante a transação (após BEGIN): o WAL do SQLite ou o rollback journal garantem recuperação atômica — ou todas as alterações ou nenhuma.
- ROLLBACK é explícito em qualquer erro.

### 6.5 Unicidade do Salt

Cada salt é gerado via `randombytes_buf` (libsodium, que usa o CSPRNG do kernel). A probabilidade de colisão de salts entre locatários é desprezível (2^-128 por par). A unicidade do salt garante que as chaves de wrapping para diferentes locatários são independentes mesmo se compartilharem a mesma senha.

---

## 7. Limitações Conhecidas

### 7.1 Sem Integração com Hardware

O Vaultine é uma solução puramente em software. Não integra com HSMs, TPMs ou enclaves seguros (SGX, SE). Um atacante com acesso root à máquina pode ler a memória do processo e extrair KEKs não wrapped durante as operações.

**Mitigação**: Minimizar a janela durante a qual as KEKs estão em texto plano. Cada chamada de API unwrap, usa e limpa a KEK. Operações de longa duração (rotação) mantêm a KEK em memória durante a execução mas limpam imediatamente após.

### 7.2 Vulnerabilidade de Senha Fraca

Todo o modelo de segurança enraíza a confiança na senha do usuário. Se um usuário escolhe uma senha fraca (ex.: `"123456"`), o hash de senha pode ser quebrado offline com Argon2id (ao custo de OPSLIMIT_MODERATE por tentativa). Uma vez que a senha é conhecida, a chave de wrapping pode ser derivada e a KEK unwrapped.

**Mitigação**: Aplicações que usam Vaultine devem impor políticas de força de senha (tamanho, complexidade, requisitos de entropia). O Vaultine não impõe isto internamente — política de senha é responsabilidade da aplicação.

### 7.3 Sem Agendamento de Rotação de Chave

O Vaultine provê `ssm_kek_rotate` mas não agenda ou automatiza a rotação internamente. A aplicação deve:
1. Verificar `SSM_ERR_EXPIRED` após cada operação.
2. Chamar `ssm_kek_rotate` quando necessário.
3. Tratar o caso de falha se a rotação falhar (ex.: log, alertar operador).

### 7.4 Considerações de Tempo Constante

As implementações AES do OpenSSL não são garantidas como tempo constante em todas as plataformas. Canais laterais de cache-timing podem vazar informação sobre chaves. Para a maioria dos cenários de implantação (VMs em nuvem, contêineres), isto não é um vetor de ataque prático, mas é uma limitação comparada a soluções HSM dedicadas.

---

## 8. Comparação com Alternativas

| Característica | Vaultine | HashiCorp Vault | AWS KMS | Azure Key Vault |
|----------------|-----|-----------------|---------|-----------------|
| Implantação | .so embarcada | Servidor (Go) | Serviço cloud | Serviço cloud |
| Locação | Multi-tenant (nível app) | Multi-tenant | Por KMS | Por cofre |
| Hierarquia de chaves | 2 níveis (KEK + wrapping) | Flexível (transit engine) | HSM-backed | HSM-backed |
| Criptografia em repouso | SQLCipher | Seal/Barrier | Gerenciado AWS | Gerenciado Azure |
| KDF de senha | Argon2id | PBKDF2/Argon2 | N/A | N/A |
| Rotação de chave | Por locatário, 90d padrão | Automática | Automática | Automática |
| Log de auditoria | Integrado | Integrado | CloudTrail | Azure Monitor |
| Dependência externa | OpenSSL + libsodium + SQLite | BD interno (Raft) | N/A | N/A |
| Superfície de ataque | Mínima (biblioteca) | Grande (servidor HTTP + API) | Superfície de API | Superfície de API |
| Tempo de setup | Segundos (link lib) | Horas (cluster) | Minutos | Minutos |

### Quando Usar Vaultine

- Você precisa de gerenciamento de chaves **embarcado** (sem servidor ou serviço de rede separado).
- Você quer **isolamento de chave por locatário** sem gerenciar HSMs por locatário.
- Você precisa de operação **offline** (Vaultine funciona apenas com um arquivo SQLite local).
- Você quer uma pegada de dependências **mínima**.

### Quando Não Usar Vaultine

- Você precisa de criptografia certificada **FIPS 140-2/3**.
- Você precisa de **raiz de confiança em hardware** (HSM, TPM, SE).
- Você precisa de **agendamento automático de rotação de chaves**.
- Você precisa de **alta disponibilidade** com failover automático.

---

## 9. Benchmarks

Medições de performance aproximadas em um sistema Linux x86_64 moderno (Intel i7-12700, 64 GB RAM, NVMe SSD):

| Operação | Chamada única (µs) | Notas |
|----------|-------------------|-------|
| `ssm_init` (:memory:) | ~500 | Inicialização do SQLite |
| `ssm_user_register` | ~150.000 | Argon2id MODERATE (2 passes, 64 MiB) |
| `ssm_user_authenticate` | ~75.000 | Argon2id verify (1 pass) |
| `ssm_secret_store` | ~155.000 | Inclui KEK unwrap + re-wrap |
| `ssm_secret_get` | ~155.000 | Inclui KEK unwrap |
| `ssm_secret_delete` | ~155.000 | Abreviação (unwrap KEK para verificar expiração) |
| `ssm_kek_rotate` (10 segredos) | ~500.000 | Depende da quantidade de segredos |

**Nota**: O custo dominante é Argon2id MODERATE (≈75–150 ms por chamada de KDF). Cada operação `store`/`get` faz uma chamada de KDF (chave de wrapping) mais `crypto_pwhash_str_verify`. O **cache de chave de wrapping** integrado (LRU de 256 entradas) elimina o KDF em operações subsequentes para o mesmo locatário — após a primeira chamada, operações subsequentes `store`/`get` completam em ~1µs para a etapa de unwrap de chave (apenas AES-KW).

---

## 10. Implementado vs Trabalho Futuro

As seguintes características do documento de design original foram implementadas desde v1.0:

| Funcionalidade | Seção | Status |
|----------------|-------|--------|
| Cache de Chave de Wrapping (LRU 256 entradas) | `src/ssm.cc` — cache_lookup/insert/invalidate | ✅ Implementado |
| `ssm_user_change_password` | `src/ssm.cc` — re-wrap atômico, mesma KEK | ✅ Implementado |
| `ssm_user_delete` | `src/ssm.cc` — deleção em cascata via ON DELETE CASCADE | ✅ Implementado |
| `ssm_secret_list` | `src/ssm.cc` — enumeração baseada em callback | ✅ Implementado |
| `ssm_status_to_string` | `src/ssm.cc` — mapeamento enum → string | ✅ Implementado |
| Log de Auditoria (tabela `audit_log`) | `src/db/audit_log.h` — todas as 9 operações registradas | ✅ Implementado |
| `kek_version` proteção contra rollback | `src/db/kek_metadata.cc` — verificação de versão no update | ✅ Implementado |
| Regras de instalação CMake + config package | `src/CMakeLists.txt` + `cmake/ssmConfig.cmake.in` | ✅ Implementado |
| CLI (`ssm-cli`) com todas as operações | `cli/ssm_cli.cc` — dispatch de user/secret/kek/env | ✅ Implementado |
| TUI ncurses (`ssm-cli tui`) | `cli/ssm_tui.cc` — interface interativa com menus, formulários, listas | ✅ Implementado |

### 10.1 CLI (Interface de Linha de Comando)

O Vaultine inclui um cliente CLI (`ssm-cli`) que expõe todas as operações da API:
- **user**: register, auth, delete, change-password
- **secret**: store (com arquivos de chave), get, delete, list
- **kek**: rotate
- **env**: exec (injetar segredos como variáveis de ambiente)
- **tui**: interface ncurses interativa

```bash
ssm-cli --db vaultine.db user register alice
ssm-cli --db vaultine.db secret store alice minha-chave /path/to/key --desc "Chave RSA"
ssm-cli --db vaultine.db kek rotate alice
```

O CLI suporta saída JSON (`--json`), senha inline (`--password`), e chave SQLCipher (`--db-key`).

### 10.2 TUI (Interface ncurses)

O subcomando `ssm-cli tui` entra em modo ncurses com menus e formulários para todas as operações sem necessidade de argumentos de linha de comando:

| Tecla | Ação |
|-------|------|
| `↑ ↓` | Navegar entre itens de menu / scroll |
| `Enter` | Selecionar / Confirmar |
| `Esc` | Voltar / Cancelar |
| `1-5` | Atalho numérico no menu principal |
| `q` | Sair |
| `y`/`n` | Confirmar operações destrutivas |

O TUI lê arquivos de chave do disco para `secret store`, exibe segredos como hex dump, e fornece listagem scrollável com paginação para `secret list`. Senhas são mascaradas com `*` durante a digitação.

### 10.3 Operações em Lote

Para usuários com milhares de segredos, `ssm_kek_rotate` faz uma descriptografia+criptografia por segredo. Operações em lote poderiam paralelizar isto (ex.: usando OpenMP ou thread pools), embora cuidado deva ser tomado com a serialização do SQLite.

### 10.4 Integração de Chave Mestra

Uma chave mestra opcional (derivada de um TPM ou HSM) poderia prover uma camada adicional de proteção. A chave mestra wrapping cada KEK, independente da chave de wrapping derivada do usuário. Isto exigiria tanto a chave mestra QUANTO as credenciais do usuário para recuperar uma KEK.

---

## Referências

1. RFC 3394 — Advanced Encryption Standard (AES) Key Wrap Algorithm
2. NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
3. NIST SP 800-63B — Digital Identity Guidelines: Authentication and Lifecycle Management
4. RFC 9106 — Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
5. SQLCipher — https://www.zetetic.net/sqlcipher/
6. libsodium Documentation — https://doc.libsodium.org/
7. OpenSSL EVP Documentation — https://www.openssl.org/docs/manmaster/man7/evp.html
