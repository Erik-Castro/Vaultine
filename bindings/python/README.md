# Vaultine Python Bindings

Binding Python (ctypes) para a biblioteca Vaultine (`libssm.so`).

## Requisitos

- Python ≥ 3.8
- libssm.so compilada (`cmake -B build && cmake --build build` no diretório raiz do projeto)

## Uso

```python
from ssm import SSMHandle, SSMError

with SSMHandle(":memory:") as ssm:
    ssm.user_register("alice", "p@ss")
    ssm.secret_store("alice", b"my-key", name="k1")
    priv, pub = ssm.secret_get("alice", "k1")
    print(priv)
```

## Caminho da .so

O binding busca `libssm.so` em:
1. `./build/src/libssm.so` (padrão build CMake local)
2. `./build/libssm.so`
3. `./libssm.so`
4. `/usr/local/lib/libssm.so`
5. `ctypes.util.find_library("ssm")` (LD_LIBRARY_PATH)

Ou passe explicitamente:

```python
with SSMHandle("app.db", lib_path="/opt/ssm/lib/libssm.so") as ssm:
    ...
```

## Exemplo completo

```bash
python bindings/python/example.py
```

## API

### `SSMHandle(db_path=":memory:", db_key=None, lib_path=None)`

Context manager que encapsula `ssm_init`/`ssm_destroy`.

| Método | Descrição |
|--------|-----------|
| `user_register(username, password)` | Registra novo usuário |
| `user_authenticate(username, password) → bool` | Verifica senha |
| `user_delete(username, password)` | Remove usuário + dados |
| `user_change_password(username, old, new)` | Troca senha |
| `secret_store(username, private_key, public_key=None, name="", description=None)` | Armazena segredo |
| `secret_get(username, name) → (private_key, public_key)` | Recupera segredo |
| `secret_delete(username, name)` | Remove segredo |
| `secret_list(username) → iterator[(name, desc, updated_at, pub_len)]` | Lista segredos |
| `kek_rotate(username)` | Rotaciona KEK |

### `SSMError(status, operation)`

Exceção lançada quando uma chamada retorna status ≠ 0.

- `e.status` — enum `SSMStatus` (OK, ERR_AUTH, ERR_NOT_FOUND, ERR_EXPIRED, ERR_INTEGRITY, ERR_INTERNAL)
- `e.operation` — nome da operação que falhou
- `str(e)` — `"SSM_ERR_* (code=N)"`

### `ssm_status_to_string(status) → str`

Converte código numérico para string legível.
