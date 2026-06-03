#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>

#include <json/json.h>

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define HTTP_CREATED 201

#include "hex_utils.h"
#include "ssm/ssm.h"
#include "ssm_server.h"

// -------------------------------------------------------------------
// Globals
// -------------------------------------------------------------------
static const char* g_prog = "ssm-cli";
extern const char* g_db_path;
extern unsigned char g_db_key[32];
extern size_t g_db_key_len;

static struct event_base* g_base = nullptr;
static struct evhttp* g_http = nullptr;
static ssm_handle* g_h = nullptr;
static char g_pidfile[4096] = {};

// -------------------------------------------------------------------
// JSON helpers
// -------------------------------------------------------------------
static std::string json_string(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    return Json::writeString(w, v);
}

static void reply_json(struct evhttp_request* req, int code, const Json::Value& v) {
    std::string body = json_string(v);
    struct evbuffer* buf = evbuffer_new();
    if (!buf) {
        evhttp_send_error(req, HTTP_INTERNAL, "out of memory");
        return;
    }
    evbuffer_add(buf, body.data(), body.size());
    struct evkeyvalq* hdrs = evhttp_request_get_output_headers(req);
    evhttp_add_header(hdrs, "Content-Type", "application/json");
    evhttp_send_reply(req, code, nullptr, buf);
    evbuffer_free(buf);
}

static void reply_ok(struct evhttp_request* req, const Json::Value& v) {
    reply_json(req, HTTP_OK, v);
}

static void reply_created(struct evhttp_request* req, const Json::Value& v) {
    reply_json(req, HTTP_CREATED, v);
}

static void reply_error(struct evhttp_request* req, int code, const char* msg) {
    Json::Value v;
    v["error"] = msg;
    reply_json(req, code, v);
}

static void reply_status(struct evhttp_request* req, int code, const char* op, ssm_status st) {
    Json::Value v;
    v["error"] = ssm_status_to_string(st);
    v["operation"] = op;
    reply_json(req, code, v);
}

// -------------------------------------------------------------------
// JSON body parsing
// -------------------------------------------------------------------
static bool parse_body(struct evhttp_request* req, Json::Value& out) {
    struct evbuffer* buf = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(buf);
    if (len == 0) {
        out = Json::Value();
        return true;
    }
    std::vector<char> data(len + 1);
    evbuffer_copyout(buf, data.data(), len);
    data[len] = '\0';

    Json::CharReaderBuilder r;
    std::string errs;
    auto reader = r.newCharReader();
    return reader->parse(data.data(), data.data() + len, &out, &errs);
}

// -------------------------------------------------------------------
// URI routing
// -------------------------------------------------------------------
struct RouteMatch {
    std::string username;
    std::string resource;
    bool matched = false;
};

static RouteMatch match_user_route(const char* uri,
                                   bool require_resource = false) {
    RouteMatch m;
    // Expected: /v1/users/<username>[/<resource>]
    // Skip leading /
    while (*uri == '/') ++uri;
    std::string s(uri);

    // Split by /
    std::vector<std::string> parts;
    size_t pos = 0;
    while ((pos = s.find('/')) != std::string::npos) {
        parts.push_back(s.substr(0, pos));
        s.erase(0, pos + 1);
    }
    if (!s.empty()) parts.push_back(s);

    // Check: v1 / users / <username> [/ <resource>]
    if (parts.size() < 3) return m;
    if (parts[0] != "v1") return m;
    if (parts[1] != "users") return m;

    m.username = parts[2];
    if (parts.size() >= 4) m.resource = parts[3];
    if (parts.size() >= 5) m.resource += "/" + parts[4]; // for secrets/:name
    m.matched = true;

    if (require_resource && m.resource.empty())
        m.matched = false;

    return m;
}

// -------------------------------------------------------------------
// Handler: GET /v1/health
// -------------------------------------------------------------------
static void handle_health(struct evhttp_request* req) {
    Json::Value v;
    v["status"] = "ok";
    v["version"] = "0.3.0-beta";
    reply_ok(req, v);
}

// -------------------------------------------------------------------
// Handler: GET /v1/version
// -------------------------------------------------------------------
static void handle_version(struct evhttp_request* req) {
    Json::Value v;
    v["version"] = "0.3.0-beta";
    v["api"] = "v1";
    reply_ok(req, v);
}

// -------------------------------------------------------------------
// User handlers
// -------------------------------------------------------------------
static void handle_user_register_req(struct evhttp_request* req, const RouteMatch& m) {
    Json::Value body;
    if (!parse_body(req, body) || !body.isMember("password")) {
        reply_error(req, HTTP_BADREQUEST, "body must contain 'password'");
        return;
    }
    ssm_status st = ssm_user_register(g_h, m.username.c_str(),
                                       body["password"].asCString());
    if (st != SSM_OK) {
        reply_status(req, HTTP_BADREQUEST, "user_register", st);
        return;
    }
    Json::Value v;
    v["status"] = "OK";
    v["username"] = m.username;
    reply_created(req, v);
}

static void handle_user_auth_req(struct evhttp_request* req, const RouteMatch& m) {
    Json::Value body;
    if (!parse_body(req, body) || !body.isMember("password")) {
        reply_error(req, HTTP_BADREQUEST, "body must contain 'password'");
        return;
    }
    int is_valid = 0;
    ssm_status st = ssm_user_authenticate(g_h, m.username.c_str(),
                                          body["password"].asCString(), &is_valid);
    if (st != SSM_OK) {
        reply_status(req, HTTP_INTERNAL, "user_authenticate", st);
        return;
    }
    Json::Value v;
    v["authenticated"] = is_valid != 0;
    reply_ok(req, v);
}

static void handle_user_delete_req(struct evhttp_request* req, const RouteMatch& m) {
    Json::Value body;
    if (!parse_body(req, body) || !body.isMember("password")) {
        reply_error(req, HTTP_BADREQUEST, "body must contain 'password'");
        return;
    }
    ssm_status st = ssm_user_delete(g_h, m.username.c_str(),
                                    body["password"].asCString());
    if (st != SSM_OK) {
        reply_status(req, HTTP_BADREQUEST, "user_delete", st);
        return;
    }
    Json::Value v;
    v["status"] = "OK";
    reply_ok(req, v);
}

static void handle_user_change_password_req(struct evhttp_request* req, const RouteMatch& m) {
    Json::Value body;
    if (!parse_body(req, body) || !body.isMember("old_password") ||
        !body.isMember("new_password")) {
        reply_error(req, HTTP_BADREQUEST,
                    "body must contain 'old_password' and 'new_password'");
        return;
    }
    ssm_status st = ssm_user_change_password(g_h, m.username.c_str(),
                                             body["old_password"].asCString(),
                                             body["new_password"].asCString());
    if (st != SSM_OK) {
        reply_status(req, HTTP_BADREQUEST, "user_change_password", st);
        return;
    }
    Json::Value v;
    v["status"] = "OK";
    reply_ok(req, v);
}

// -------------------------------------------------------------------
// Secret handlers
// -------------------------------------------------------------------
static void handle_secret_list_req(struct evhttp_request* req, const RouteMatch& m) {
    struct ListCtx {
        std::vector<std::string> names, descs, updateds;
        std::vector<size_t> pub_lens;
    };
    ListCtx ctx;
    auto cb = [](const char* name, const char* desc, const char* updated,
                 size_t pub_len, void* user) {
        auto* c = static_cast<ListCtx*>(user);
        c->names.push_back(name);
        c->descs.push_back(desc ? desc : "");
        c->updateds.push_back(updated);
        c->pub_lens.push_back(pub_len);
    };
    ssm_status st = ssm_secret_list(g_h, m.username.c_str(), cb, &ctx);
    if (st != SSM_OK) {
        reply_status(req, HTTP_BADREQUEST, "secret_list", st);
        return;
    }
    Json::Value arr(Json::arrayValue);
    for (size_t i = 0; i < ctx.names.size(); ++i) {
        Json::Value item;
        item["name"] = ctx.names[i];
        if (!ctx.descs[i].empty()) item["description"] = ctx.descs[i];
        item["updatedAt"] = ctx.updateds[i];
        item["pubKeyLen"] = (Json::UInt64)ctx.pub_lens[i];
        arr.append(item);
    }
    reply_ok(req, arr);
}

static void handle_secret_store_req(struct evhttp_request* req, const RouteMatch& m) {
    Json::Value body;
    if (!parse_body(req, body) || !body.isMember("name") ||
        !body.isMember("private_key")) {
        reply_error(req, HTTP_BADREQUEST,
                    "body must contain 'name' and 'private_key'");
        return;
    }

    std::string name = body["name"].asString();
    std::string priv_hex = body["private_key"].asString();
    std::string pub_hex = body.get("public_key", "").asString();
    std::string desc = body.get("description", "").asString();

    // Decode hex keys
    unsigned char* priv_bytes = nullptr;
    size_t priv_len = 0;
    if (!hex_decode(priv_hex.c_str(), priv_hex.size(), &priv_bytes, &priv_len)) {
        reply_error(req, HTTP_BADREQUEST, "private_key: invalid hex");
        return;
    }
    unsigned char* pub_bytes = nullptr;
    size_t pub_len = 0;
    if (!pub_hex.empty() &&
        !hex_decode(pub_hex.c_str(), pub_hex.size(), &pub_bytes, &pub_len)) {
        delete[] priv_bytes;
        reply_error(req, HTTP_BADREQUEST, "public_key: invalid hex");
        return;
    }

    ssm_status st = ssm_secret_store(g_h, m.username.c_str(),
                                     priv_bytes, priv_len,
                                     pub_bytes, pub_len,
                                     name.c_str(),
                                     desc.empty() ? nullptr : desc.c_str());
    delete[] priv_bytes;
    delete[] pub_bytes;

    if (st != SSM_OK) {
        reply_status(req, HTTP_BADREQUEST, "secret_store", st);
        return;
    }
    Json::Value v;
    v["status"] = "OK";
    v["name"] = name;
    reply_created(req, v);
}

static void handle_secret_get_req(struct evhttp_request* req, const RouteMatch& m) {
    // resource is "secrets/<name>" — extract name
    std::string res = m.resource;
    std::string secret_name;
    if (res.find("secrets/") == 0)
        secret_name = res.substr(8);

    if (secret_name.empty()) {
        reply_error(req, HTTP_NOTFOUND, "secret name required");
        return;
    }

    unsigned char priv_buf[65536], pub_buf[65536];
    size_t priv_len = sizeof(priv_buf), pub_len = sizeof(pub_buf);
    ssm_status st = ssm_secret_get(g_h, m.username.c_str(), secret_name.c_str(),
                                   priv_buf, &priv_len, pub_buf, &pub_len);
    if (st == SSM_ERR_INTERNAL && priv_len > sizeof(priv_buf)) {
        // Retry with correct size — need dynamic allocation
        size_t new_priv_len = priv_len;
        size_t new_pub_len = pub_len;
        auto* new_priv = new unsigned char[new_priv_len];
        auto* new_pub = new unsigned char[new_pub_len];
        st = ssm_secret_get(g_h, m.username.c_str(), secret_name.c_str(),
                            new_priv, &new_priv_len, new_pub, &new_pub_len);
        if (st == SSM_OK) {
            Json::Value v;
            v["private_key"] = hex_encode(new_priv, new_priv_len);
            if (new_pub_len > 0)
                v["public_key"] = hex_encode(new_pub, new_pub_len);
            delete[] new_priv;
            delete[] new_pub;
            reply_ok(req, v);
            return;
        }
        delete[] new_priv;
        delete[] new_pub;
    }

    if (st != SSM_OK) {
        int code = (st == SSM_ERR_NOT_FOUND || st == SSM_ERR_AUTH) ? HTTP_NOTFOUND : HTTP_BADREQUEST;
        reply_status(req, code, "secret_get", st);
        return;
    }

    Json::Value v;
    v["private_key"] = hex_encode(priv_buf, priv_len);
    if (pub_len > 0)
        v["public_key"] = hex_encode(pub_buf, pub_len);
    reply_ok(req, v);
}

static void handle_secret_delete_req(struct evhttp_request* req, const RouteMatch& m) {
    std::string res = m.resource;
    std::string secret_name;
    if (res.find("secrets/") == 0)
        secret_name = res.substr(8);

    if (secret_name.empty()) {
        reply_error(req, HTTP_NOTFOUND, "secret name required");
        return;
    }

    ssm_status st = ssm_secret_delete(g_h, m.username.c_str(), secret_name.c_str());
    if (st != SSM_OK) {
        reply_status(req, HTTP_BADREQUEST, "secret_delete", st);
        return;
    }
    Json::Value v;
    v["status"] = "OK";
    reply_ok(req, v);
}

// -------------------------------------------------------------------
// KEK handler
// -------------------------------------------------------------------
static void handle_kek_rotate_req(struct evhttp_request* req, const RouteMatch& m) {
    ssm_status st = ssm_kek_rotate(g_h, m.username.c_str());
    if (st != SSM_OK) {
        reply_status(req, HTTP_BADREQUEST, "kek_rotate", st);
        return;
    }
    Json::Value v;
    v["status"] = "OK";
    reply_ok(req, v);
}

// -------------------------------------------------------------------
// Backup handlers
// -------------------------------------------------------------------
static void handle_backup_create_req(struct evhttp_request* req) {
    Json::Value body;
    if (!parse_body(req, body) || !body.isMember("path") || !body.isMember("key_hex")) {
        reply_error(req, HTTP_BADREQUEST, "body must contain 'path' and 'key_hex'");
        return;
    }
    std::string path = body["path"].asString();
    unsigned char key[32];
    size_t key_len = 0;
    if (!hex_decode(body["key_hex"].asCString(), key, &key_len) || key_len != 32) {
        reply_error(req, HTTP_BADREQUEST, "key_hex must be 64 hex chars (32 bytes)");
        return;
    }
    ssm_status st = ssm_backup_create(g_h, path.c_str(), key, key_len);
    if (st != SSM_OK) {
        reply_status(req, HTTP_INTERNAL, "backup_create", st);
        return;
    }
    Json::Value v;
    v["status"] = "OK";
    reply_created(req, v);
}

static void handle_backup_restore_req(struct evhttp_request* req) {
    Json::Value body;
    if (!parse_body(req, body) || !body.isMember("path") || !body.isMember("key_hex")) {
        reply_error(req, HTTP_BADREQUEST, "body must contain 'path' and 'key_hex'");
        return;
    }
    std::string path = body["path"].asString();
    unsigned char key[32];
    size_t key_len = 0;
    if (!hex_decode(body["key_hex"].asCString(), key, &key_len) || key_len != 32) {
        reply_error(req, HTTP_BADREQUEST, "key_hex must be 64 hex chars (32 bytes)");
        return;
    }
    ssm_status st = ssm_backup_restore(g_h, path.c_str(), key, key_len);
    if (st != SSM_OK) {
        reply_status(req, HTTP_INTERNAL, "backup_restore", st);
        return;
    }
    Json::Value v;
    v["status"] = "OK";
    reply_ok(req, v);
}

// -------------------------------------------------------------------
// DB handlers
// -------------------------------------------------------------------
static void handle_db_version_req(struct evhttp_request* req) {
    int version = 0;
    ssm_status st = ssm_db_version(g_h, &version);
    if (st != SSM_OK) {
        reply_status(req, HTTP_INTERNAL, "db_version", st);
        return;
    }
    Json::Value v;
    v["version"] = version;
    reply_ok(req, v);
}

static void handle_db_migrate_req(struct evhttp_request* req) {
    ssm_status st = ssm_db_migrate(g_h);
    if (st != SSM_OK) {
        reply_status(req, HTTP_INTERNAL, "db_migrate", st);
        return;
    }
    Json::Value v;
    v["status"] = "OK";
    reply_ok(req, v);
}

// -------------------------------------------------------------------
// Cache stats handler
// -------------------------------------------------------------------
static void handle_cache_stats_req(struct evhttp_request* req) {
    ssm_cache_stats stats;
    ssm_status st = ssm_cache_get_stats(g_h, &stats);
    if (st != SSM_OK) {
        reply_status(req, HTTP_INTERNAL, "cache_stats", st);
        return;
    }
    Json::Value v;
    v["totalEntries"] = (Json::UInt64)stats.total_entries;
    v["validEntries"] = (Json::UInt64)stats.valid_entries;
    v["hitCount"] = (Json::UInt64)stats.hit_count;
    v["missCount"] = (Json::UInt64)stats.miss_count;
    reply_ok(req, v);
}

// -------------------------------------------------------------------
// Audit log handler
// -------------------------------------------------------------------
static void handle_audit_log_req(struct evhttp_request* req) {
    const char* username = evhttp_find_header(evhttp_request_get_input_headers(req),
                                              "X-Audit-Username");
    const char* operation = evhttp_find_header(evhttp_request_get_input_headers(req),
                                               "X-Audit-Operation");
    const char* result_filter = evhttp_find_header(evhttp_request_get_input_headers(req),
                                                   "X-Audit-Result");
    const char* limit_str = evhttp_find_header(evhttp_request_get_input_headers(req),
                                               "X-Audit-Limit");
    const char* offset_str = evhttp_find_header(evhttp_request_get_input_headers(req),
                                                "X-Audit-Offset");

    int64_t limit = 100, offset = 0;
    if (limit_str) limit = std::atol(limit_str);
    if (offset_str) offset = std::atol(offset_str);

    struct AuditCtx {
        std::vector<int64_t> ids, user_ids;
        std::vector<std::string> usernames, operations, targets, details, results, timestamps;
    };
    AuditCtx ctx;

    auto cb = [](int64_t id, int64_t user_id, const char* username,
                 const char* operation, const char* target, const char* detail,
                 const char* result, const char* timestamp, void* user) {
        auto* c = static_cast<AuditCtx*>(user);
        c->ids.push_back(id);
        c->user_ids.push_back(user_id);
        c->usernames.push_back(username ? username : "");
        c->operations.push_back(operation ? operation : "");
        c->targets.push_back(target ? target : "");
        c->details.push_back(detail ? detail : "");
        c->results.push_back(result ? result : "");
        c->timestamps.push_back(timestamp ? timestamp : "");
    };

    ssm_status st = ssm_audit_log_query(
        g_h,
        username ? username : nullptr,
        operation ? operation : nullptr,
        result_filter ? result_filter : nullptr,
        limit, offset, cb, &ctx);

    if (st != SSM_OK) {
        reply_status(req, HTTP_INTERNAL, "audit_log_query", st);
        return;
    }

    Json::Value arr(Json::arrayValue);
    for (size_t i = 0; i < ctx.ids.size(); ++i) {
        Json::Value item;
        item["id"] = (Json::Int64)ctx.ids[i];
        item["userId"] = (Json::Int64)ctx.user_ids[i];
        item["username"] = ctx.usernames[i];
        item["operation"] = ctx.operations[i];
        item["operationTarget"] = ctx.targets[i];
        item["details"] = ctx.details[i];
        item["result"] = ctx.results[i];
        item["timestamp"] = ctx.timestamps[i];
        arr.append(item);
    }
    reply_ok(req, arr);
}

// -------------------------------------------------------------------
// Export handler
// -------------------------------------------------------------------
static void handle_export_req(struct evhttp_request* req) {
    const char* fmt = evhttp_find_header(evhttp_request_get_input_headers(req),
                                         "X-Export-Format");
    const char* redact = evhttp_find_header(evhttp_request_get_input_headers(req),
                                            "X-Export-Redact");

    int format = 0; // json
    if (fmt && std::strcmp(fmt, "csv") == 0) format = 1;
    int redact_pii = (redact && std::strcmp(redact, "true") == 0) ? 1 : 0;

    struct ExportCtx { std::vector<char> data; };
    ExportCtx ctx;
    auto cb = [](const char* chunk, size_t len, void* user) {
        auto* c = static_cast<ExportCtx*>(user);
        c->data.insert(c->data.end(), chunk, chunk + len);
    };

    ssm_status st = ssm_export(g_h, (ssm_export_format)format, redact_pii, cb, &ctx);
    if (st != SSM_OK) {
        reply_status(req, HTTP_INTERNAL, "export", st);
        return;
    }

    struct evbuffer* buf = evbuffer_new();
    evbuffer_add(buf, ctx.data.data(), ctx.data.size());
    struct evkeyvalq* hdrs = evhttp_request_get_output_headers(req);
    evhttp_add_header(hdrs, "Content-Type",
                      format == 0 ? "application/json" : "text/csv");
    evhttp_send_reply(req, HTTP_OK, nullptr, buf);
    evbuffer_free(buf);
}

// -------------------------------------------------------------------
// Main dispatch
// -------------------------------------------------------------------
static void request_handler(struct evhttp_request* req, void*) {
    const char* uri = evhttp_request_get_uri(req);
    enum evhttp_cmd_type method = evhttp_request_get_command(req);

    // Strip query string for routing
    std::string path_only(uri);
    size_t qpos = path_only.find('?');
    if (qpos != std::string::npos) path_only = path_only.substr(0, qpos);

    // Health and version (no auth needed)
    if (path_only == "/v1/health" && method == EVHTTP_REQ_GET) {
        handle_health(req);
        return;
    }
    if (path_only == "/v1/version" && method == EVHTTP_REQ_GET) {
        handle_version(req);
        return;
    }

    // Export (no auth needed)
    if (path_only == "/v1/export" && method == EVHTTP_REQ_GET) {
        handle_export_req(req);
        return;
    }

    // DB routes
    if (path_only == "/v1/db/version" && method == EVHTTP_REQ_GET) {
        handle_db_version_req(req);
        return;
    }
    if (path_only == "/v1/db/migrate" && method == EVHTTP_REQ_POST) {
        handle_db_migrate_req(req);
        return;
    }

    // Cache stats
    if (path_only == "/v1/cache/stats" && method == EVHTTP_REQ_GET) {
        handle_cache_stats_req(req);
        return;
    }

    // Audit log
    if (path_only == "/v1/audit" && method == EVHTTP_REQ_GET) {
        handle_audit_log_req(req);
        return;
    }

    // Backup
    if (path_only == "/v1/backup/create" && method == EVHTTP_REQ_POST) {
        handle_backup_create_req(req);
        return;
    }
    if (path_only == "/v1/backup/restore" && method == EVHTTP_REQ_POST) {
        handle_backup_restore_req(req);
        return;
    }

    // User routes
    RouteMatch m = match_user_route(path_only.c_str());
    if (!m.matched) {
        reply_error(req, HTTP_NOTFOUND, "not found");
        return;
    }

    if (m.resource.empty()) {
        // /v1/users/<username>
        if (method == EVHTTP_REQ_POST) {
            // Need to check if register or auth
            Json::Value body;
            parse_body(req, body);
            // By default, if it has a password, try register
            // Actually the URI should distinguish: register and auth both POST to /v1/users/<username>
            // We need to differentiate. Let me use a sub-resource approach instead.
            reply_error(req, HTTP_NOTFOUND, "use /v1/users/<username>/register or /auth");
            return;
        }
        if (method == EVHTTP_REQ_DELETE) {
            handle_user_delete_req(req, m);
            return;
        }
        reply_error(req, HTTP_BADMETHOD, "method not allowed");
        return;
    }

    // /v1/users/<username>/<resource>
    if (m.resource == "register") {
        if (method != EVHTTP_REQ_POST) { reply_error(req, HTTP_BADMETHOD, "use POST"); return; }
        handle_user_register_req(req, m);
        return;
    }
    if (m.resource == "auth") {
        if (method != EVHTTP_REQ_POST) { reply_error(req, HTTP_BADMETHOD, "use POST"); return; }
        handle_user_auth_req(req, m);
        return;
    }
    if (m.resource == "password") {
        if (method != EVHTTP_REQ_PUT) { reply_error(req, HTTP_BADMETHOD, "use PUT"); return; }
        handle_user_change_password_req(req, m);
        return;
    }
    if (m.resource.find("kek/rotate") == 0) {
        if (method != EVHTTP_REQ_POST) { reply_error(req, HTTP_BADMETHOD, "use POST"); return; }
        handle_kek_rotate_req(req, m);
        return;
    }
    if (m.resource == "secrets") {
        if (method == EVHTTP_REQ_GET) {
            handle_secret_list_req(req, m);
            return;
        }
        if (method == EVHTTP_REQ_POST) {
            handle_secret_store_req(req, m);
            return;
        }
        reply_error(req, HTTP_BADMETHOD, "use GET or POST");
        return;
    }
    if (m.resource.find("secrets/") == 0) {
        if (method == EVHTTP_REQ_GET) {
            handle_secret_get_req(req, m);
            return;
        }
        if (method == EVHTTP_REQ_DELETE) {
            handle_secret_delete_req(req, m);
            return;
        }
        reply_error(req, HTTP_BADMETHOD, "use GET or DELETE");
        return;
    }

    reply_error(req, HTTP_NOTFOUND, "not found");
}

// -------------------------------------------------------------------
// Signal handling
// -------------------------------------------------------------------
static void signal_cb(evutil_socket_t, short, void*) {
    if (g_base)
        event_base_loopbreak(g_base);
}

// -------------------------------------------------------------------
// Daemonize
// -------------------------------------------------------------------
static void daemonize(const char* pidfile) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid > 0)
        exit(0);

    if (setsid() < 0) {
        perror("setsid");
        exit(1);
    }

    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid > 0)
        exit(0);

    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }

    umask(077);
    chdir("/");

    if (pidfile && pidfile[0]) {
        FILE* f = fopen(pidfile, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());
            fclose(f);
        }
    }
}

// -------------------------------------------------------------------
// Server entry point
// -------------------------------------------------------------------
int handle_server_start(int argc, char** argv) {
    int port = 8080;
    const char* host = "127.0.0.1";
    bool do_daemonize = false;
    const char* pidfile = "./ssm-cli.pid";

    for (int i = 0; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (std::strcmp(argv[i], "--daemonize") == 0)
            do_daemonize = true;
        else if (std::strcmp(argv[i], "--pidfile") == 0 && i + 1 < argc)
            pidfile = argv[++i];
        else {
            fprintf(stderr, "%s: unknown option '%s' for server start\n", g_prog, argv[i]);
            return 1;
        }
    }

    // Open database
    ssm_status st = ssm_init(&g_h, g_db_path,
                             g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK) {
        fprintf(stderr, "%s: failed to open database: %s\n",
                g_prog, ssm_status_to_string(st));
        return 1;
    }

    fprintf(stderr, "%s: server starting on %s:%d\n", g_prog, host, port);

    if (pidfile && pidfile[0])
        std::strncpy(g_pidfile, pidfile, sizeof(g_pidfile) - 1);

    if (do_daemonize) {
        fprintf(stderr, "%s: daemonizing...\n", g_prog);
        daemonize(pidfile);
    }

    // Create event base
    g_base = event_base_new();
    if (!g_base) {
        fprintf(stderr, "%s: failed to create event base\n", g_prog);
        ssm_destroy(g_h);
        return 1;
    }

    // Create HTTP server
    g_http = evhttp_new(g_base);
    if (!g_http) {
        fprintf(stderr, "%s: failed to create HTTP server\n", g_prog);
        ssm_destroy(g_h);
        event_base_free(g_base);
        return 1;
    }

    evhttp_set_gencb(g_http, request_handler, nullptr);
    evhttp_set_timeout(g_http, 30);
    evhttp_set_max_body_size(g_http, 10 * 1024 * 1024); // 10MB

    if (evhttp_bind_socket(g_http, host, port) != 0) {
        fprintf(stderr, "%s: failed to bind to %s:%d\n", g_prog, host, port);
        evhttp_free(g_http);
        ssm_destroy(g_h);
        event_base_free(g_base);
        return 1;
    }

    // Signal handlers
    struct event* sig_int = evsignal_new(g_base, SIGINT, signal_cb, nullptr);
    struct event* sig_term = evsignal_new(g_base, SIGTERM, signal_cb, nullptr);
    event_add(sig_int, nullptr);
    event_add(sig_term, nullptr);

    if (do_daemonize) {
        // After daemonize, stderr is /dev/null, so log to syslog or pidfile
        // For now, just suppress further stderr output
    } else {
        printf("%s: listening on http://%s:%d\n", g_prog, host, port);
        printf("%s: press Ctrl+C to stop\n", g_prog);
    }

    // Event loop
    event_base_dispatch(g_base);

    // Cleanup
    fprintf(stderr, "\n%s: shutting down...\n", g_prog);

    if (g_pidfile[0])
        std::remove(g_pidfile);

    event_free(sig_int);
    event_free(sig_term);
    evhttp_free(g_http);
    ssm_destroy(g_h);
    event_base_free(g_base);

    fprintf(stderr, "%s: stopped\n", g_prog);
    return 0;
}
