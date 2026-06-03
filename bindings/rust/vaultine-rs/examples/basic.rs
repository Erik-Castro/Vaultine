use vaultine::Vaultine;

fn main() {
    let v = Vaultine::new(":memory:", None).expect("ssm_init");

    v.user_register("alice", "p@ss").expect("register");
    println!("alice registered");

    let ok = v.user_authenticate("alice", "p@ss").expect("auth");
    println!("alice authenticated: {ok}");

    v.secret_store("alice", b"my-secret-key", None, "k1", Some("test key"))
        .expect("store");
    println!("secret k1 stored");

    let (priv_key, pub_key) = v.secret_get("alice", "k1", 4096).expect("get");
    println!(
        "got secret: {} bytes (pub: {})",
        priv_key.len(),
        if pub_key.is_some() { "yes" } else { "no" }
    );

    let list = v.secret_list("alice").expect("list");
    println!("alice has {} secrets", list.len());

    v.kek_rotate("alice").expect("rotate");
    println!("KEK rotated");

    let ver = v.db_version().expect("version");
    println!("db schema version: {ver}");

    let meta = v.export_metadata(vaultine::ExportFormat::Json, false).expect("export");
    println!("metadata:\n{meta}");

    // automatic ssm_destroy via Drop
    println!("done");
}
