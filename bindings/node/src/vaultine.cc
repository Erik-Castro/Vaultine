#include <node_api.h>
#include <ssm/ssm.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------

struct VaultineInstance {
    ssm_handle* handle = nullptr;
};

static void throw_status(napi_env env, int status) {
    napi_throw_error(env, NULL, ssm_status_to_string((ssm_status)status));
}

#define CHECK_NAPI(env, call)                                             \
    do {                                                                  \
        napi_status _napi_s = (call);                                     \
        if (_napi_s != napi_ok) {                                         \
            napi_throw_error((env), NULL,                                 \
                             "N-API call failed: " #call);                \
            return NULL;                                                  \
        }                                                                 \
    } while (false)

#define CHECK_SSM(env, rc)                  \
    do {                                    \
        if ((rc) != 0) {                    \
            throw_status((env), (rc));       \
            return NULL;                    \
        }                                   \
    } while (false)

static VaultineInstance* unwrap(napi_env env, napi_callback_info info,
                                napi_value* out_self) {
    napi_value self;
    CHECK_NAPI(env, napi_get_cb_info(env, info, NULL, NULL, &self, NULL));
    if (out_self) *out_self = self;
    VaultineInstance* vi;
    CHECK_NAPI(env, napi_unwrap(env, self, (void**)&vi));
    if (!vi || !vi->handle) {
        napi_throw_error(env, NULL, "Vaultine handle is closed");
        return NULL;
    }
    return vi;
}

// -----------------------------------------------------------------------
// Constructor / Destructor
// -----------------------------------------------------------------------

static void finalize_vaultine(napi_env /*env*/, void* data, void* /*hint*/) {
    auto* vi = static_cast<VaultineInstance*>(data);
    if (vi->handle) {
        ssm_destroy(vi->handle);
        vi->handle = nullptr;
    }
    delete vi;
}

static napi_value js_new(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_value self;
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, &self, NULL));

    char db_path[4096] = ":memory:";
    if (argc > 0) {
        CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], db_path,
                                                     sizeof(db_path), NULL));
    }

    unsigned char db_key[64];
    size_t db_key_len = 0;
    if (argc > 1) {
        void* key_data;
        size_t key_size;
        CHECK_NAPI(env, napi_get_buffer_info(env, args[1], &key_data, &key_size));
        if (key_size > sizeof(db_key)) key_size = sizeof(db_key);
        std::memcpy(db_key, key_data, key_size);
        db_key_len = key_size;
    }

    auto* vi = new (std::nothrow) VaultineInstance;
    if (!vi) {
        napi_throw_error(env, NULL, "Out of memory");
        return NULL;
    }

    int rc = ssm_init(&vi->handle, db_path,
                      db_key_len > 0 ? db_key : NULL, db_key_len);
    if (rc != 0) {
        delete vi;
        throw_status(env, rc);
        return NULL;
    }

    CHECK_NAPI(env, napi_wrap(env, self, vi, finalize_vaultine, NULL, NULL));
    return self;
}

static napi_value js_destroy(napi_env env, napi_callback_info info) {
    napi_value self;
    auto* vi = unwrap(env, info, &self);
    if (!vi) return NULL;
    if (vi->handle) {
        ssm_destroy(vi->handle);
        vi->handle = nullptr;
    }
    void* dummy;
    CHECK_NAPI(env, napi_remove_wrap(env, self, &dummy));
    return NULL;
}

// -----------------------------------------------------------------------
// User operations
// -----------------------------------------------------------------------

static napi_value js_user_register(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256], password[256];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], username,
                                                sizeof(username), NULL));
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[1], password,
                                                sizeof(password), NULL));
    CHECK_SSM(env, ssm_user_register(vi->handle, username, password));
    return NULL;
}

static napi_value js_user_authenticate(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256], password[256];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], username,
                                                sizeof(username), NULL));
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[1], password,
                                                sizeof(password), NULL));
    int is_valid = 0;
    CHECK_SSM(env, ssm_user_authenticate(vi->handle, username, password, &is_valid));

    napi_value result;
    CHECK_NAPI(env, napi_get_boolean(env, is_valid != 0, &result));
    return result;
}

static napi_value js_user_delete(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256], password[256];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], username,
                                                sizeof(username), NULL));
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[1], password,
                                                sizeof(password), NULL));
    CHECK_SSM(env, ssm_user_delete(vi->handle, username, password));
    return NULL;
}

static napi_value js_user_change_password(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256], old_pw[256], new_pw[256];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], username,
                                                sizeof(username), NULL));
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[1], old_pw,
                                                sizeof(old_pw), NULL));
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[2], new_pw,
                                                sizeof(new_pw), NULL));
    CHECK_SSM(env, ssm_user_change_password(vi->handle, username, old_pw, new_pw));
    return NULL;
}

// -----------------------------------------------------------------------
// Secret operations
// -----------------------------------------------------------------------

static napi_value js_secret_store(napi_env env, napi_callback_info info) {
    size_t argc = 5;
    napi_value args[5];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256], name[256];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], username,
                                                sizeof(username), NULL));
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[3], name,
                                                sizeof(name), NULL));

    void* priv_data;
    size_t priv_len;
    CHECK_NAPI(env, napi_get_buffer_info(env, args[1], &priv_data, &priv_len));

    void* pub_data = NULL;
    size_t pub_len = 0;
    napi_valuetype t;
    CHECK_NAPI(env, napi_typeof(env, args[2], &t));
    if (t == napi_object) {
        CHECK_NAPI(env, napi_get_buffer_info(env, args[2], &pub_data, &pub_len));
    }

    char desc[1024] = "";
    if (argc >= 5) {
        CHECK_NAPI(env, napi_get_value_string_utf8(env, args[4], desc,
                                                     sizeof(desc), NULL));
    }

    CHECK_SSM(env, ssm_secret_store(vi->handle, username,
                                    (unsigned char*)priv_data, priv_len,
                                    (unsigned char*)pub_data, pub_len,
                                    name, desc[0] ? desc : NULL));
    return NULL;
}

static napi_value js_secret_get(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256], name[256];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], username,
                                                sizeof(username), NULL));
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[1], name,
                                                sizeof(name), NULL));

    int max_size = 65536;
    if (argc >= 3) {
        CHECK_NAPI(env, napi_get_value_int32(env, args[2], &max_size));
        if (max_size <= 0) max_size = 65536;
    }

    size_t priv_len = (size_t)max_size;
    size_t pub_len = (size_t)max_size;
    auto* priv_buf = new unsigned char[priv_len];
    auto* pub_buf = new unsigned char[pub_len];

    int rc = ssm_secret_get(vi->handle, username, name,
                            priv_buf, &priv_len,
                            pub_buf, &pub_len);

    if (rc == SSM_ERR_INTERNAL && priv_len > (size_t)max_size) {
        delete[] priv_buf;
        delete[] pub_buf;
        max_size = (int)priv_len;
        priv_len = (size_t)max_size;
        pub_len = (size_t)max_size;
        priv_buf = new unsigned char[priv_len];
        pub_buf = new unsigned char[pub_len];
        rc = ssm_secret_get(vi->handle, username, name,
                            priv_buf, &priv_len,
                            pub_buf, &pub_len);
    }

    if (rc != 0) {
        delete[] priv_buf;
        delete[] pub_buf;
        throw_status(env, rc);
        return NULL;
    }

    napi_value result;
    CHECK_NAPI(env, napi_create_object(env, &result));

    napi_value priv_val;
    CHECK_NAPI(env, napi_create_buffer_copy(env, priv_len, priv_buf,
                                             NULL, &priv_val));
    CHECK_NAPI(env, napi_set_named_property(env, result, "privateKey", priv_val));

    if (pub_len > 0) {
        napi_value pub_val;
        CHECK_NAPI(env, napi_create_buffer_copy(env, pub_len, pub_buf,
                                                 NULL, &pub_val));
        CHECK_NAPI(env, napi_set_named_property(env, result, "publicKey", pub_val));
    }

    delete[] priv_buf;
    delete[] pub_buf;
    return result;
}

static napi_value js_secret_delete(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256], name[256];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], username,
                                                sizeof(username), NULL));
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[1], name,
                                                sizeof(name), NULL));
    CHECK_SSM(env, ssm_secret_delete(vi->handle, username, name));
    return NULL;
}

// -----------------------------------------------------------------------
// Secret list (callback → array)
// -----------------------------------------------------------------------

struct ListCtx {
    std::vector<char*> names;
    std::vector<char*> descs;
    std::vector<char*> updateds;
    std::vector<size_t> pub_lens;
};

static void list_cb(const char* name, const char* desc, const char* updated,
                    size_t pub_len, void* user_data) {
    auto* ctx = static_cast<ListCtx*>(user_data);
    ctx->names.push_back(strdup(name));
    ctx->descs.push_back(desc ? strdup(desc) : NULL);
    ctx->updateds.push_back(strdup(updated));
    ctx->pub_lens.push_back(pub_len);
}

static napi_value js_secret_list(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], username,
                                                sizeof(username), NULL));

    ListCtx ctx;
    int rc = ssm_secret_list(vi->handle, username, list_cb, &ctx);
    if (rc != 0) {
        for (auto* p : ctx.names) free(p);
        for (auto* p : ctx.descs) free(p);
        for (auto* p : ctx.updateds) free(p);
        throw_status(env, rc);
        return NULL;
    }

    napi_value arr;
    CHECK_NAPI(env, napi_create_array_with_length(env, ctx.names.size(), &arr));

    for (size_t i = 0; i < ctx.names.size(); ++i) {
        napi_value obj;
        CHECK_NAPI(env, napi_create_object(env, &obj));

        napi_value v;
        CHECK_NAPI(env, napi_create_string_utf8(env, ctx.names[i],
                                                  NAPI_AUTO_LENGTH, &v));
        CHECK_NAPI(env, napi_set_named_property(env, obj, "name", v));

        if (ctx.descs[i]) {
            CHECK_NAPI(env, napi_create_string_utf8(env, ctx.descs[i],
                                                      NAPI_AUTO_LENGTH, &v));
            CHECK_NAPI(env, napi_set_named_property(env, obj, "description", v));
        }

        CHECK_NAPI(env, napi_create_string_utf8(env, ctx.updateds[i],
                                                  NAPI_AUTO_LENGTH, &v));
        CHECK_NAPI(env, napi_set_named_property(env, obj, "updatedAt", v));

        CHECK_NAPI(env, napi_create_uint32(env, (uint32_t)ctx.pub_lens[i], &v));
        CHECK_NAPI(env, napi_set_named_property(env, obj, "pubKeyLen", v));

        CHECK_NAPI(env, napi_set_element(env, arr, (uint32_t)i, obj));
    }

    for (auto* p : ctx.names) free(p);
    for (auto* p : ctx.descs) free(p);
    for (auto* p : ctx.updateds) free(p);

    return arr;
}

// -----------------------------------------------------------------------
// KEK
// -----------------------------------------------------------------------

static napi_value js_kek_rotate(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], username,
                                                sizeof(username), NULL));
    CHECK_SSM(env, ssm_kek_rotate(vi->handle, username));
    return NULL;
}

// -----------------------------------------------------------------------
// Backup / Restore
// -----------------------------------------------------------------------

static napi_value js_backup_create(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char backup_path[4096];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], backup_path,
                                                sizeof(backup_path), NULL));

    void* key_data;
    size_t key_len;
    CHECK_NAPI(env, napi_get_buffer_info(env, args[1], &key_data, &key_len));

    CHECK_SSM(env, ssm_backup_create(vi->handle, backup_path,
                                     (unsigned char*)key_data, key_len));
    return NULL;
}

static napi_value js_backup_restore(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char backup_path[4096];
    CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], backup_path,
                                                sizeof(backup_path), NULL));

    void* key_data;
    size_t key_len;
    CHECK_NAPI(env, napi_get_buffer_info(env, args[1], &key_data, &key_len));

    CHECK_SSM(env, ssm_backup_restore(vi->handle, backup_path,
                                      (unsigned char*)key_data, key_len));
    return NULL;
}

// -----------------------------------------------------------------------
// Export (callback → string)
// -----------------------------------------------------------------------

struct ExportCtx {
    std::vector<char> data;
};

static void export_cb(const char* chunk, size_t len, void* user_data) {
    auto* ctx = static_cast<ExportCtx*>(user_data);
    ctx->data.insert(ctx->data.end(), chunk, chunk + len);
}

static napi_value js_export(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char fmt_str[16] = "json";
    if (argc >= 1) {
        CHECK_NAPI(env, napi_get_value_string_utf8(env, args[0], fmt_str,
                                                     sizeof(fmt_str), NULL));
    }
    int format = (std::strcmp(fmt_str, "csv") == 0) ? 1 : 0;

    int redact_pii = 0;
    if (argc >= 2) {
        CHECK_NAPI(env, napi_get_value_bool(env, args[1], (bool*)&redact_pii));
    }

    ExportCtx ctx;
    int rc = ssm_export(vi->handle, (ssm_export_format)format,
                        redact_pii, export_cb, &ctx);
    if (rc != 0) {
        throw_status(env, rc);
        return NULL;
    }

    napi_value result;
    CHECK_NAPI(env, napi_create_string_utf8(env, ctx.data.data(),
                                             ctx.data.size(), &result));
    return result;
}

// -----------------------------------------------------------------------
// DB version / migrate
// -----------------------------------------------------------------------

static napi_value js_db_version(napi_env env, napi_callback_info info) {
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    int version = 0;
    CHECK_SSM(env, ssm_db_version(vi->handle, &version));

    napi_value result;
    CHECK_NAPI(env, napi_create_int32(env, version, &result));
    return result;
}

static napi_value js_db_migrate(napi_env env, napi_callback_info info) {
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;
    CHECK_SSM(env, ssm_db_migrate(vi->handle));
    return NULL;
}

// -----------------------------------------------------------------------
// Cache stats
// -----------------------------------------------------------------------

static napi_value js_cache_stats(napi_env env, napi_callback_info info) {
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    ssm_cache_stats stats;
    CHECK_SSM(env, ssm_cache_get_stats(vi->handle, &stats));

    napi_value result;
    CHECK_NAPI(env, napi_create_object(env, &result));

    auto set_u32 = [&](const char* key, uint32_t val) -> void {
        napi_value v;
        if (napi_create_uint32(env, val, &v) != napi_ok) return;
        napi_set_named_property(env, result, key, v);
    };
    set_u32("totalEntries", (uint32_t)stats.total_entries);
    set_u32("validEntries", (uint32_t)stats.valid_entries);
    set_u32("hitCount", (uint32_t)stats.hit_count);
    set_u32("missCount", (uint32_t)stats.miss_count);

    return result;
}

// -----------------------------------------------------------------------
// Audit log query (callback → array)
// -----------------------------------------------------------------------

struct AuditCtx {
    std::vector<int64_t> ids;
    std::vector<int64_t> user_ids;
    std::vector<char*> usernames;
    std::vector<char*> operations;
    std::vector<char*> targets;
    std::vector<char*> details;
    std::vector<char*> results;
    std::vector<char*> timestamps;
};

static void audit_cb(int64_t id, int64_t user_id,
                     const char* username, const char* operation,
                     const char* target, const char* detail,
                     const char* result, const char* timestamp,
                     void* user_data) {
    auto* ctx = static_cast<AuditCtx*>(user_data);
    ctx->ids.push_back(id);
    ctx->user_ids.push_back(user_id);
    ctx->usernames.push_back(strdup(username));
    ctx->operations.push_back(strdup(operation));
    ctx->targets.push_back(strdup(target ? target : ""));
    ctx->details.push_back(strdup(detail ? detail : ""));
    ctx->results.push_back(strdup(result));
    ctx->timestamps.push_back(strdup(timestamp));
}

static napi_value js_audit_log_query(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    CHECK_NAPI(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    auto* vi = unwrap(env, info, NULL);
    if (!vi) return NULL;

    char username[256] = "", operation[256] = "", result_filter[256] = "";
    int64_t limit = 100, offset = 0;

    if (argc >= 1) {
        napi_value opt = args[0];
        napi_valuetype t;
        CHECK_NAPI(env, napi_typeof(env, opt, &t));
        if (t == napi_object) {
            auto get_str = [&](const char* key, char* out, size_t out_sz) -> void {
                napi_value v;
                bool has;
                if (napi_has_named_property(env, opt, key, &has) != napi_ok) return;
                if (has) {
                    if (napi_get_named_property(env, opt, key, &v) != napi_ok) return;
                    napi_get_value_string_utf8(env, v, out, out_sz, NULL);
                }
            };
            auto get_i64 = [&](const char* key, int64_t* out) -> void {
                napi_value v;
                bool has;
                if (napi_has_named_property(env, opt, key, &has) != napi_ok) return;
                if (has) {
                    if (napi_get_named_property(env, opt, key, &v) != napi_ok) return;
                    napi_get_value_int64(env, v, out);
                }
            };
            get_str("username", username, sizeof(username));
            get_str("operation", operation, sizeof(operation));
            get_str("result", result_filter, sizeof(result_filter));
            get_i64("limit", &limit);
            get_i64("offset", &offset);
        }
    }

    AuditCtx ctx;
    int rc = ssm_audit_log_query(vi->handle,
                                 username[0] ? username : NULL,
                                 operation[0] ? operation : NULL,
                                 result_filter[0] ? result_filter : NULL,
                                 limit, offset,
                                 audit_cb, &ctx);
    if (rc != 0) {
        for (auto* p : ctx.usernames) free(p);
        for (auto* p : ctx.operations) free(p);
        for (auto* p : ctx.targets) free(p);
        for (auto* p : ctx.details) free(p);
        for (auto* p : ctx.results) free(p);
        for (auto* p : ctx.timestamps) free(p);
        throw_status(env, rc);
        return NULL;
    }

    napi_value arr;
    CHECK_NAPI(env, napi_create_array_with_length(env, ctx.ids.size(), &arr));

    for (size_t i = 0; i < ctx.ids.size(); ++i) {
        napi_value obj;
        CHECK_NAPI(env, napi_create_object(env, &obj));

        napi_value v;
        CHECK_NAPI(env, napi_create_int64(env, ctx.ids[i], &v));
        CHECK_NAPI(env, napi_set_named_property(env, obj, "id", v));
        CHECK_NAPI(env, napi_create_int64(env, ctx.user_ids[i], &v));
        CHECK_NAPI(env, napi_set_named_property(env, obj, "userId", v));

        auto set_str = [&](const char* key, const char* val) -> void {
            napi_value tmp;
            if (napi_create_string_utf8(env, val, NAPI_AUTO_LENGTH, &tmp) != napi_ok) return;
            napi_set_named_property(env, obj, key, tmp);
        };
        set_str("username", ctx.usernames[i]);
        set_str("operation", ctx.operations[i]);
        set_str("operationTarget", ctx.targets[i]);
        set_str("details", ctx.details[i]);
        set_str("result", ctx.results[i]);
        set_str("timestamp", ctx.timestamps[i]);

        CHECK_NAPI(env, napi_set_element(env, arr, (uint32_t)i, obj));
    }

    for (auto* p : ctx.usernames) free(p);
    for (auto* p : ctx.operations) free(p);
    for (auto* p : ctx.targets) free(p);
    for (auto* p : ctx.details) free(p);
    for (auto* p : ctx.results) free(p);
    for (auto* p : ctx.timestamps) free(p);

    return arr;
}

// -----------------------------------------------------------------------
// Module registration
// -----------------------------------------------------------------------

static napi_value js_new_vaultine(napi_env env, napi_callback_info info) {
    return js_new(env, info);
}

NAPI_MODULE_INIT() {
    napi_value constructor;

    napi_property_descriptor methods[] = {
        { "destroy", NULL, js_destroy, NULL, NULL, NULL, napi_enumerable, NULL },
        { "userRegister", NULL, js_user_register, NULL, NULL, NULL, napi_enumerable, NULL },
        { "userAuthenticate", NULL, js_user_authenticate, NULL, NULL, NULL, napi_enumerable, NULL },
        { "userDelete", NULL, js_user_delete, NULL, NULL, NULL, napi_enumerable, NULL },
        { "userChangePassword", NULL, js_user_change_password, NULL, NULL, NULL, napi_enumerable, NULL },
        { "secretStore", NULL, js_secret_store, NULL, NULL, NULL, napi_enumerable, NULL },
        { "secretGet", NULL, js_secret_get, NULL, NULL, NULL, napi_enumerable, NULL },
        { "secretDelete", NULL, js_secret_delete, NULL, NULL, NULL, napi_enumerable, NULL },
        { "secretList", NULL, js_secret_list, NULL, NULL, NULL, napi_enumerable, NULL },
        { "kekRotate", NULL, js_kek_rotate, NULL, NULL, NULL, napi_enumerable, NULL },
        { "backupCreate", NULL, js_backup_create, NULL, NULL, NULL, napi_enumerable, NULL },
        { "backupRestore", NULL, js_backup_restore, NULL, NULL, NULL, napi_enumerable, NULL },
        { "export", NULL, js_export, NULL, NULL, NULL, napi_enumerable, NULL },
        { "dbVersion", NULL, js_db_version, NULL, NULL, NULL, napi_enumerable, NULL },
        { "dbMigrate", NULL, js_db_migrate, NULL, NULL, NULL, napi_enumerable, NULL },
        { "cacheStats", NULL, js_cache_stats, NULL, NULL, NULL, napi_enumerable, NULL },
        { "auditLogQuery", NULL, js_audit_log_query, NULL, NULL, NULL, napi_enumerable, NULL },
    };

    CHECK_NAPI(env, napi_define_class(env, "Vaultine", NAPI_AUTO_LENGTH,
                                      js_new_vaultine, NULL,
                                      sizeof(methods) / sizeof(methods[0]),
                                      methods, &constructor));

    CHECK_NAPI(env, napi_set_named_property(env, exports, "Vaultine", constructor));
    return exports;
}
