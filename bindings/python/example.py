"""
SSM Python binding — exemplos de uso.
"""
from ssm import SSMHandle, SSMError


def demo_lifecycle():
    print("=== SSM Lifecycle Demo ===\n")

    with SSMHandle(":memory:") as ssm:
        # register
        ssm.user_register("alice", "p@ssw0rd")
        print("1. alice registrada")

        # authenticate
        ok = ssm.user_authenticate("alice", "p@ssw0rd")
        print(f"2. autenticação: {ok}")

        # store secrets
        ssm.secret_store("alice", b"chave-privada-001",
                         public_key=b"chave-publica-001",
                         name="rsa-key", description="RSA 4096 para TLS")
        print("3. segredo 'rsa-key' armazenado")

        ssm.secret_store("alice", b"outro-segredo", name="token-api")
        print("4. segredo 'token-api' armazenado")

        # list secrets
        print("\n5. Listando segredos de alice:")
        for name, desc, updated, pub_len in ssm.secret_list("alice"):
            desc_str = desc or "(sem descrição)"
            print(f"   - {name}: {desc_str} (pub: {pub_len}B, updated: {updated})")

        # get secret
        priv, pub = ssm.secret_get("alice", "rsa-key")
        print(f"\n6. secret_get 'rsa-key': priv={priv} pub={pub}")

        # change password
        ssm.user_change_password("alice", "p@ssw0rd", "nova-senha")
        ok = ssm.user_authenticate("alice", "nova-senha")
        print(f"7. senha alterada, nova autenticação: {ok}")

        # access after password change
        priv2, _ = ssm.secret_get("alice", "rsa-key")
        print(f"8. acesso pós-troca: {priv2}")

        # KEK rotation
        ssm.kek_rotate("alice")
        print("9. KEK rotacionado")

        # access after rotation
        priv3, _ = ssm.secret_get("alice", "rsa-key")
        print(f"10. acesso pós-rotação: {priv3}")

        # delete secret
        ssm.secret_delete("alice", "token-api")
        print("11. segredo 'token-api' deletado")

        # delete user
        ssm.user_delete("alice", "nova-senha")
        print("12. usuário alice deletado (KEK + segredos removidos)")

    print("\n=== FIM ===")


def demo_error_handling():
    print("\n=== Error Handling Demo ===\n")

    with SSMHandle(":memory:") as ssm:
        try:
            ssm.user_register("bob", "123")
            ssm.secret_get("bob", "nao-existe")
        except SSMError as e:
            print(f"  SSMError capturado: {e}")
            print(f"  status={e.status.name} operation={e.operation}")


def demo_tenant_isolation():
    print("\n=== Tenant Isolation Demo ===\n")

    with SSMHandle(":memory:") as ssm:
        ssm.user_register("alice", "pass1")
        ssm.user_register("bob", "pass2")

        ssm.secret_store("alice", b"alice-data", name="k1")
        ssm.secret_store("bob", b"bob-data", name="k1")

        p_alice, _ = ssm.secret_get("alice", "k1")
        p_bob, _ = ssm.secret_get("bob", "k1")
        print(f"  alice: {p_alice}")
        print(f"  bob:   {p_bob}")
        print(f"  isolado: {p_alice != p_bob}")

        # bob não vê segredos de alice
        try:
            ssm.secret_get("bob", "k1")
            print("  bob viu k1 (OK, é dele)")
        except SSMError:
            pass

        names = [n for n, _, _, _ in ssm.secret_list("alice")]
        names_bob = [n for n, _, _, _ in ssm.secret_list("bob")]
        print(f"  alice secrets: {names}")
        print(f"  bob secrets:   {names_bob}")


if __name__ == "__main__":
    demo_lifecycle()
    demo_error_handling()
    demo_tenant_isolation()
