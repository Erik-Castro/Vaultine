#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include <json/json.h>

#include <sodium.h>

#include "hex_utils.h"
#include "ssm/ssm.h"
#include "ssm_server.h"

// -------------------------------------------------------------------
// Globals
// -------------------------------------------------------------------
static const char* g_prog = "ssm-cli";
const char* g_db_path = "./ssm.db";
unsigned char g_db_key[32];
size_t g_db_key_len = 0;
static unsigned char g_backup_key[32];
static size_t g_backup_key_len = 0;
static bool g_json = false;
static std::string g_password;

// -------------------------------------------------------------------
// Config file
// -------------------------------------------------------------------
static std::string g_cfg_db_path;
static std::string g_cfg_password;
static std::string g_cfg_db_key_hex;
static std::string g_cfg_backup_key_hex;

struct ConfigFile {
    bool json = false;
    bool loaded = false;
};

static ConfigFile load_config() {
    ConfigFile cf;
    const char* paths[] = {"./vaultine.json", nullptr};

    const char* home = std::getenv("HOME");
    std::string homepath;
    if (home) {
        homepath = std::string(home) + "/.vaultinerc";
        paths[1] = homepath.c_str();
    }

    for (const char* path : paths) {
        if (!path)
            continue;
        struct stat st;
        if (stat(path, &st) != 0)
            continue;

        std::ifstream ifs(path);
        if (!ifs.is_open())
            continue;

        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errors;
        if (!Json::parseFromStream(builder, ifs, &root, &errors))
            continue;

        cf.loaded = true;
        if (root.isMember("db") && root["db"].isString())
            g_cfg_db_path = root["db"].asString();
        if (root.isMember("db_key") && root["db_key"].isString())
            g_cfg_db_key_hex = root["db_key"].asString();
        if (root.isMember("password") && root["password"].isString())
            g_cfg_password = root["password"].asString();
        if (root.isMember("backup_key") && root["backup_key"].isString())
            g_cfg_backup_key_hex = root["backup_key"].asString();
        if (root.isMember("json") && root["json"].isBool())
            cf.json = root["json"].asBool();
        break;
    }
    return cf;
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------
[[noreturn]] static void die(const char* msg) {
    fprintf(stderr, "%s: error: %s\n", g_prog, msg);
    exit(1);
}

[[noreturn]] static void die_status(ssm_status st, const char* op) {
    fprintf(stderr, "%s: %s: %s\n", g_prog, op, ssm_status_to_string(st));
    exit(1);
}

static std::string read_password(const char* prompt) {
    if (!isatty(STDIN_FILENO)) {
        std::vector<char> buf(4096);
        if (!fgets(buf.data(), static_cast<int>(buf.size()), stdin))
            die("failed to read password");
        size_t len = std::strlen(buf.data());
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
            --len;
        }
        std::string result(buf.data(), len);
        sodium_memzero(buf.data(), buf.size());
        return result;
    }
    char* pw = getpass(prompt);
    if (!pw)
        die("getpass failed");
    std::string result(pw);
    sodium_memzero(pw, std::strlen(pw));
    return result;
}

static std::string prompt_password(const char* username) {
    if (!g_password.empty())
        return g_password;
    char prompt[256];
    std::snprintf(prompt, sizeof(prompt), "password for %s: ", username);
    return read_password(prompt);
}

// -------------------------------------------------------------------
// Help / version
// -------------------------------------------------------------------
static void print_version() { printf("ssm-cli version 0.1.0\n"); }

static void print_usage() {
    printf(
        "Usage: %s [options] <command> [args...]\n"
        "\n"
        "Options:\n"
        "  --db <path>       SQLite database path (default: ./ssm.db)\n"
        "  --db-key <hex>    SQLCipher hex key (optional)\n"
        "  --password <str>  Password for all operations (non-interactive)\n"
        "  --backup-key <hex> 64 hex chars (32 bytes) — required for backup commands\n"
        "  --json            Machine-readable JSON output\n"
        "  --help            Show this help\n"
        "  --version         Show version\n"
        "\n"
        "Commands:\n"
        "  user register <username>\n"
        "  user auth <username>\n"
        "  user delete <username>\n"
        "  user change-password <username>\n"
        "  secret store <username> <name> <key_file> [--pub <pub_file>]\n"
        "                [--desc <description>]\n"
        "  secret get <username> <name> [--out <file>] [--pub-out <file>]\n"
        "  secret delete <username> <name>\n"
        "  secret list <username>\n"
        "  kek rotate <username>\n"
        "  cache-stats      Show cache statistics\n"
        "  audit-log <username>  Query audit log (optional: --operation, --result,\n"
        "                        --limit, --offset)\n"
        "  backup create/restore <file>\n"
        "                   Encrypted backup (use --backup-key <hex64>)\n"
        "  db version|migrate\n"
        "                   Database schema version and migration\n"
        "  export [--format json|csv] [--redact-pii]\n"
        "                   Export metadata (JSON/CSV) to stdout\n"
        "  tui              Interactive terminal interface\n"
        "  env exec <username> [--] <command> [args...]\n"
        "  server start [--port <n>] [--host <addr>] [--daemonize]\n"
        "              [--pidfile <path>]\n"
        "  completion [bash|zsh]  Generate shell completion script\n"
        "  help [command]\n"
        "\n"
        "Config file (auto-detected):\n"
        "  ./vaultine.json or ~/.vaultinerc  JSON config (CLI flags override)\n",
        g_prog);
}

static void print_help_user() {
    printf(
        "user commands:\n"
        "  register <username>      Register a new user (interactive password)\n"
        "  auth <username>          Verify credentials (exit 0 on success)\n"
        "  delete <username>        Delete user + all data (confirm + password)\n"
        "  change-password <user>   Change password interactively\n");
}

static void print_help_secret() {
    printf(
        "secret commands:\n"
        "  store <user> <name> <key_file>   Store a secret from file\n"
        "    --pub <pub_file>               Optional public key\n"
        "    --desc <description>           Optional description\n"
        "  get <user> <name>               Retrieve secret to stdout\n"
        "    --out <file>                   Write private key to file\n"
        "    --pub-out <file>               Write public key to file\n"
        "  delete <user> <name>             Delete a secret\n"
        "  list <user>                      List all secrets\n");
}

static void print_help_kek() {
    printf(
        "kek commands:\n"
        "  rotate <username>           Force KEK rotation\n");
}

// -------------------------------------------------------------------
// Command handlers
// -------------------------------------------------------------------
static int handle_user_register(int argc, char** argv) {
    if (argc < 1) {
        print_help_user();
        return 1;
    }
    const char* username = argv[0];
    std::string pw = prompt_password(username);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    st = ssm_user_register(h, username, pw.c_str());
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "user register");
    printf("OK: user '%s' registered\n", username);
    return 0;
}

static int handle_user_auth(int argc, char** argv) {
    if (argc < 1) {
        print_help_user();
        return 1;
    }
    const char* username = argv[0];
    std::string pw = prompt_password(username);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    int valid = 0;
    st = ssm_user_authenticate(h, username, pw.c_str(), &valid);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "user auth");
    if (g_json)
        printf("{\"authenticated\":%s}\n", valid ? "true" : "false");
    else
        printf("%s\n", valid ? "OK: authenticated" : "FAIL: invalid credentials");
    return valid ? 0 : 1;
}

static int handle_user_delete(int argc, char** argv) {
    if (argc < 1) {
        print_help_user();
        return 1;
    }
    const char* username = argv[0];

    fprintf(stderr,
            "WARNING: this will permanently delete user '%s' "
            "and all their data.\n",
            username);
    fprintf(stderr, "Type 'yes' to confirm: ");
    char confirm[64];
    if (!fgets(confirm, sizeof(confirm), stdin))
        die("read failed");
    if (std::strcmp(confirm, "yes\n") != 0) {
        printf("aborted\n");
        return 1;
    }

    std::string pw = prompt_password(username);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    st = ssm_user_delete(h, username, pw.c_str());
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "user delete");
    printf("OK: user '%s' and all data deleted\n", username);
    return 0;
}

static int handle_user_change_password(int argc, char** argv) {
    if (argc < 1) {
        print_help_user();
        return 1;
    }
    const char* username = argv[0];

    std::string old_pw = prompt_password(username);
    char prompt[256];
    std::snprintf(prompt, sizeof(prompt), "New password for %s: ", username);
    std::string new_pw = read_password(prompt);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    st = ssm_user_change_password(h, username, old_pw.c_str(), new_pw.c_str());
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "change password");
    printf("OK: password changed for '%s'\n", username);
    return 0;
}

// -------------------------------------------------------------------
// export handler
// -------------------------------------------------------------------
static int handle_export(int argc, char** argv) {
    ssm_export_format fmt = SSM_EXPORT_JSON;
    int redact_pii = 0;

    for (int i = 0; i < argc; ++i) {
        if (std::strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            if (std::strcmp(argv[++i], "csv") == 0)
                fmt = SSM_EXPORT_CSV;
        } else if (std::strcmp(argv[i], "--redact-pii") == 0) {
            redact_pii = 1;
        } else {
            fprintf(stderr, "error: unknown export option '%s'\n", argv[i]);
            return 1;
        }
    }

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    st = ssm_export(h, fmt, redact_pii,
                    [](const char* chunk, size_t len, void*) {
                        fwrite(chunk, 1, len, stdout);
                    },
                    nullptr);
    ssm_destroy(h);

    if (st != SSM_OK)
        die_status(st, "export");

    return 0;
}

// -------------------------------------------------------------------
// secret handlers
// -------------------------------------------------------------------
static int handle_secret_store(int argc, char** argv) {
    if (argc < 3) {
        print_help_secret();
        return 1;
    }
    const char* username = argv[0];
    const char* name = argv[1];
    const char* key_path = argv[2];
    const char* pub_path = nullptr;
    const char* description = nullptr;

    // parse optional flags after positional args
    for (int i = 3; i < argc; ++i) {
        if (std::strcmp(argv[i], "--pub") == 0 && i + 1 < argc) {
            pub_path = argv[++i];
        } else if (std::strcmp(argv[i], "--desc") == 0 && i + 1 < argc) {
            description = argv[++i];
        }
    }

    // read key file
    FILE* fk = std::fopen(key_path, "rb");
    if (!fk) {
        perror("fopen key_file");
        return 1;
    }
    std::fseek(fk, 0, SEEK_END);
    long klen = std::ftell(fk);
    std::fseek(fk, 0, SEEK_SET);
    if (klen <= 0) {
        fclose(fk);
        die("empty key file");
    }
    std::vector<unsigned char> key_buf(static_cast<size_t>(klen));
    if (std::fread(key_buf.data(), 1, key_buf.size(), fk) != key_buf.size()) {
        fclose(fk);
        die("fread key_file failed");
    }
    fclose(fk);

    // read optional public key
    std::vector<unsigned char> pub_buf;
    if (pub_path) {
        FILE* fp = std::fopen(pub_path, "rb");
        if (!fp) {
            perror("fopen pub_file");
            return 1;
        }
        std::fseek(fp, 0, SEEK_END);
        long plen = std::ftell(fp);
        std::fseek(fp, 0, SEEK_SET);
        if (plen > 0) {
            pub_buf.resize(static_cast<size_t>(plen));
            if (std::fread(pub_buf.data(), 1, pub_buf.size(), fp) != pub_buf.size()) {
                fclose(fp);
                die("fread pub_file failed");
            }
        }
        fclose(fp);
    }

    std::string pw = prompt_password(username);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    st = ssm_secret_store(h, username, key_buf.data(), key_buf.size(), pub_buf.data(),
                          pub_buf.size(), name, description);

    ssm_destroy(h);

    if (st != SSM_OK)
        die_status(st, "secret store");
    printf("OK: secret '%s' stored for '%s'\n", name, username);
    return 0;
}

struct get_ctx {
    const char* out_path;
    const char* pub_out_path;
    unsigned char* priv;
    size_t priv_len;
    unsigned char* pub;
    size_t pub_len;
};

static int handle_secret_get(int argc, char** argv) {
    if (argc < 2) {
        print_help_secret();
        return 1;
    }
    const char* username = argv[0];
    const char* name = argv[1];
    const char* out_path = nullptr;
    const char* pub_out_path = nullptr;

    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_path = argv[++i];
        else if (std::strcmp(argv[i], "--pub-out") == 0 && i + 1 < argc)
            pub_out_path = argv[++i];
    }

    std::string pw = prompt_password(username);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    // try with generous buffer, retry if needed
    std::vector<unsigned char> priv;
    std::vector<unsigned char> pub;
    {
        size_t priv_cap = 65536;
        size_t pub_cap = 65536;
        priv.resize(priv_cap);
        pub.resize(pub_cap);
        size_t priv_len = priv_cap;
        size_t pub_len = pub_cap;
        st = ssm_secret_get(h, username, name, priv.data(), &priv_len, pub.data(), &pub_len);
        if (st == SSM_ERR_INTERNAL && priv_len > priv_cap) {
            priv.resize(priv_len);
            pub.resize(pub_len);
            priv_len = priv.size();
            pub_len = pub.size();
            st = ssm_secret_get(h, username, name, priv.data(), &priv_len, pub.data(), &pub_len);
        }
        priv.resize(priv_len);
        pub.resize(pub_len);
    }
    ssm_destroy(h);

    if (st != SSM_OK)
        die_status(st, "secret get");

    if (out_path) {
        FILE* f = std::fopen(out_path, "wb");
        if (!f) {
            perror("fopen --out");
            return 1;
        }
        std::fwrite(priv.data(), 1, priv.size(), f);
        std::fclose(f);
        printf("OK: private key (%zu bytes) written to %s\n", priv.size(), out_path);
    } else {
        std::fwrite(priv.data(), 1, priv.size(), stdout);
        std::fputc('\n', stdout);
    }

    if (pub_out_path && !pub.empty()) {
        FILE* f = std::fopen(pub_out_path, "wb");
        if (!f) {
            perror("fopen --pub-out");
            return 1;
        }
        std::fwrite(pub.data(), 1, pub.size(), f);
        std::fclose(f);
        printf("OK: public key (%zu bytes) written to %s\n", pub.size(), pub_out_path);
    }

    return 0;
}

static int handle_secret_delete(int argc, char** argv) {
    if (argc < 2) {
        print_help_secret();
        return 1;
    }
    const char* username = argv[0];
    const char* name = argv[1];
    std::string pw = prompt_password(username);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");
    st = ssm_secret_delete(h, username, name);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "secret delete");
    printf("OK: secret '%s' deleted\n", name);
    return 0;
}

struct list_item {
    std::string name;
    std::string desc;
    std::string updated_at;
    size_t pub_len;
};

static void list_callback(const char* name, const char* description, const char* updated_at,
                          size_t public_key_len, void* user_data) {
    auto* items = static_cast<std::vector<list_item>*>(user_data);
    items->push_back({name ? name : "", description ? description : "",
                      updated_at ? updated_at : "", public_key_len});
}

static int handle_secret_list(int argc, char** argv) {
    if (argc < 1) {
        print_help_secret();
        return 1;
    }
    const char* username = argv[0];
    std::string pw = prompt_password(username);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    std::vector<list_item> items;
    st = ssm_secret_list(h, username, list_callback, &items);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "secret list");

    if (g_json) {
        printf("[");
        for (size_t i = 0; i < items.size(); ++i) {
            if (i > 0)
                printf(",");
            printf(
                "{\"name\":\"%s\",\"description\":\"%s\","
                "\"updated_at\":\"%s\",\"public_key_len\":%zu}",
                items[i].name.c_str(), items[i].desc.c_str(), items[i].updated_at.c_str(),
                items[i].pub_len);
        }
        printf("]\n");
    } else {
        if (items.empty()) {
            printf("no secrets for '%s'\n", username);
        } else {
            for (auto& item : items) {
                printf("%-30s  %s  pub:%zuB  %s\n", item.name.c_str(), item.desc.c_str(),
                       item.pub_len, item.updated_at.c_str());
            }
        }
    }
    return 0;
}

// -------------------------------------------------------------------
// kek handlers
// -------------------------------------------------------------------
static int handle_kek_rotate(int argc, char** argv) {
    if (argc < 1) {
        print_help_kek();
        return 1;
    }
    const char* username = argv[0];
    std::string pw = prompt_password(username);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");
    st = ssm_kek_rotate(h, username);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "kek rotate");
    printf("OK: KEK rotated for '%s'\n", username);
    return 0;
}

// -------------------------------------------------------------------
// audit-log handler
// -------------------------------------------------------------------
struct audit_item {
    std::string username;
    std::string operation;
    std::string target;
    std::string details;
    std::string result;
    std::string timestamp;
};

static void audit_callback(int64_t id, int64_t user_id, const char* username, const char* operation,
                           const char* operation_target, const char* details, const char* result,
                           const char* timestamp, void* user_data) {
    auto* items = static_cast<std::vector<audit_item>*>(user_data);
    (void) id;
    (void) user_id;
    items->push_back({username ? username : "", operation ? operation : "",
                      operation_target ? operation_target : "", details ? details : "",
                      result ? result : "", timestamp ? timestamp : ""});
}

static int handle_audit_log(int argc, char** argv) {
    if (argc < 1) {
        fprintf(stderr,
                "usage: %s audit-log <username> [--operation <op>] "
                "[--result <res>] [--limit <n>] [--offset <n>]\n",
                g_prog);
        return 1;
    }
    const char* username = argv[0];
    const char* operation = nullptr;
    const char* result = nullptr;
    int64_t limit = 100;
    int64_t offset = 0;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--operation") == 0 && i + 1 < argc)
            operation = argv[++i];
        else if (std::strcmp(argv[i], "--result") == 0 && i + 1 < argc)
            result = argv[++i];
        else if (std::strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            char* end = nullptr;
            long long v = std::strtoll(argv[++i], &end, 10);
            if (end != argv[i] && v >= 0) limit = v;
        } else if (std::strcmp(argv[i], "--offset") == 0 && i + 1 < argc) {
            char* end = nullptr;
            long long v = std::strtoll(argv[++i], &end, 10);
            if (end != argv[i] && v >= 0) offset = v;
        }
    }

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    std::vector<audit_item> items;
    st = ssm_audit_log_query(h, username, operation, result, limit, offset, audit_callback, &items);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "audit-log query");

    if (g_json) {
        printf("[");
        for (size_t i = 0; i < items.size(); ++i) {
            if (i > 0)
                printf(",");
            printf(
                "{\"username\":\"%s\",\"operation\":\"%s\","
                "\"target\":\"%s\",\"details\":%s,\"result\":\"%s\","
                "\"timestamp\":\"%s\"}",
                items[i].username.c_str(), items[i].operation.c_str(), items[i].target.c_str(),
                items[i].details.c_str(), items[i].result.c_str(), items[i].timestamp.c_str());
        }
        printf("]\n");
    } else {
        if (items.empty()) {
            printf("no audit log entries for '%s'\n", username);
        } else {
            printf("%-20s %-18s %-12s %s\n", "operation", "target", "result", "timestamp");
            printf("%-20s %-18s %-12s %s\n", "---------", "------", "------", "---------");
            for (auto& item : items) {
                printf("%-20s %-18s %-12s %s\n", item.operation.c_str(), item.target.c_str(),
                       item.result.c_str(), item.timestamp.c_str());
            }
            printf("(%zu entries)\n", items.size());
        }
    }
    return 0;
}

// -------------------------------------------------------------------
// cache-stats handler
// -------------------------------------------------------------------
static int handle_cache_stats(int /*argc*/, char** /*argv*/) {
    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    ssm_cache_stats stats{};
    st = ssm_cache_get_stats(h, &stats);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "cache stats");

    if (g_json) {
        printf(
            "{\"total_entries\":%zu,\"valid_entries\":%zu,"
            "\"hit_count\":%zu,\"miss_count\":%zu}\n",
            stats.total_entries, stats.valid_entries, stats.hit_count, stats.miss_count);
    } else {
        double hit_rate = (stats.hit_count + stats.miss_count) > 0
                              ? (100.0 * stats.hit_count) / (stats.hit_count + stats.miss_count)
                              : 0.0;
        printf("Cache Statistics:\n");
        printf("  Total slots:     %zu\n", stats.total_entries);
        printf("  Valid entries:   %zu\n", stats.valid_entries);
        printf("  Hits:            %zu\n", stats.hit_count);
        printf("  Misses:          %zu\n", stats.miss_count);
        printf("  Hit rate:        %.1f%%\n", hit_rate);
    }
    return 0;
}

// -------------------------------------------------------------------
// backup handlers
// -------------------------------------------------------------------
static void print_help_backup() {
    printf(
        "backup commands:\n"
        "  create <file>              Create encrypted backup of the database\n"
        "                             Requires --backup-key (hex, 64 chars for 32 bytes)\n"
        "  restore <file>             Restore database from encrypted backup\n"
        "                             Requires --backup-key (same key used for create)\n");
}

static int handle_backup_create(int argc, char** argv) {
    if (argc < 1) {
        print_help_backup();
        return 1;
    }
    if (g_backup_key_len != 32) {
        fprintf(stderr, "error: --backup-key is required (64 hex chars)\n");
        return 1;
    }
    const char* backup_path = argv[0];

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    st = ssm_backup_create(h, backup_path, g_backup_key, g_backup_key_len);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "backup create");
    printf("OK: backup written to %s\n", backup_path);
    return 0;
}

static int handle_backup_restore(int argc, char** argv) {
    if (argc < 1) {
        print_help_backup();
        return 1;
    }
    if (g_backup_key_len != 32) {
        fprintf(stderr, "error: --backup-key is required (64 hex chars)\n");
        return 1;
    }
    const char* backup_path = argv[0];

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    st = ssm_backup_restore(h, backup_path, g_backup_key, g_backup_key_len);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "backup restore");
    printf("OK: database restored from %s\n", backup_path);
    return 0;
}

// -------------------------------------------------------------------
// env handlers
// -------------------------------------------------------------------
static void print_help_env() {
    printf(
        "env commands:\n"
        "  exec <username> [--] <command> [args...]\n"
        "               Inject secrets as env vars and exec command\n");
}

static const char BASE64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const unsigned char* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        unsigned b0 = data[i];
        unsigned b1 = i + 1 < len ? data[i + 1] : 0;
        unsigned b2 = i + 2 < len ? data[i + 2] : 0;
        unsigned triple = (b0 << 16) | (b1 << 8) | b2;
        out += BASE64_TABLE[(triple >> 18) & 0x3F];
        out += BASE64_TABLE[(triple >> 12) & 0x3F];
        out += i + 1 < len ? BASE64_TABLE[(triple >> 6) & 0x3F] : '=';
        out += i + 2 < len ? BASE64_TABLE[triple & 0x3F] : '=';
    }
    return out;
}

static bool is_printable(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = data[i];
        if (c == 0)
            return false;
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r')
            return false;
        if (c >= 0x7F)
            return false;
    }
    return true;
}

static std::string sanitize_env_name(const char* name) {
    std::string result = "SSM_";
    for (const char* p = name; *p; ++p) {
        char c = *p;
        if (c >= 'a' && c <= 'z')
            result += static_cast<char>(c - 32);
        else if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
            result += c;
        else
            result += '_';
    }
    return result;
}

static int handle_env_exec(int argc, char** argv) {
    if (argc < 2) {
        print_help_env();
        return 1;
    }
    const char* username = argv[0];

    // find command args (after optional -- separator)
    int cmd_start = 1;
    if (std::strcmp(argv[1], "--") == 0)
        cmd_start = 2;
    if (cmd_start >= argc) {
        print_help_env();
        return 1;
    }
    int cmd_argc = argc - cmd_start;
    char** cmd_argv = argv + cmd_start;

    std::string pw = prompt_password(username);

    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    int valid = 0;
    st = ssm_user_authenticate(h, username, pw.c_str(), &valid);
    if (st != SSM_OK)
        die_status(st, "user auth");
    if (!valid)
        die("authentication failed");

    // collect secret names
    struct env_item {
        std::string name;
        std::string env_name;
    };
    std::vector<env_item> names;

    auto cb = [](const char* name, const char*, const char*, size_t, void* user) {
        auto* v = static_cast<std::vector<env_item>*>(user);
        v->push_back({name ? name : "", ""});
    };
    st = ssm_secret_list(h, username, cb, &names);
    if (st != SSM_OK)
        die_status(st, "secret list");

    // fetch and set each secret
    for (auto& item : names) {
        item.env_name = sanitize_env_name(item.name.c_str());

        std::vector<unsigned char> priv;
        {
            size_t priv_cap = 65536;
            size_t priv_len = priv_cap;
            size_t pub_len = 0;
            priv.resize(priv_cap);
            st = ssm_secret_get(h, username, item.name.c_str(), priv.data(), &priv_len, nullptr,
                                &pub_len);
            if (st == SSM_ERR_INTERNAL && priv_len > priv_cap) {
                priv.resize(priv_len);
                priv_len = priv.size();
                st = ssm_secret_get(h, username, item.name.c_str(), priv.data(), &priv_len, nullptr,
                                    &pub_len);
            }
            priv.resize(priv_len);
        }
        if (st != SSM_OK) {
            fprintf(stderr, "warning: skipping '%s': %s\n", item.name.c_str(),
                    ssm_status_to_string(st));
            continue;
        }

        std::string val;
        if (is_printable(priv.data(), priv.size())) {
            val.assign(reinterpret_cast<const char*>(priv.data()), priv.size());
            setenv(item.env_name.c_str(), val.c_str(), 1);
        } else {
            val = base64_encode(priv.data(), priv.size());
            setenv(item.env_name.c_str(), val.c_str(), 1);
            std::string enc_name = item.env_name + "_ENC";
            setenv(enc_name.c_str(), "base64", 1);
        }

        sodium_memzero(priv.data(), priv.size());
    }

    ssm_destroy(h);

    char count_str[16];
    std::snprintf(count_str, sizeof(count_str), "%zu", names.size());
    setenv("SSM_COUNT", count_str, 1);

    execvp(cmd_argv[0], cmd_argv);
    // if exec returns, it failed
    perror("execvp");
    return 1;
}

// -------------------------------------------------------------------
// db handlers
// -------------------------------------------------------------------
static void print_help_db() {
    printf(
        "db commands:\n"
        "  version          Show current database schema version\n"
        "  migrate          Manually trigger schema migration\n");
}

static void print_help_server() {
    printf(
        "server commands:\n"
        "  start            Start REST API server\n"
        "    --port <n>     Port to listen on (default: 8080)\n"
        "    --host <addr>  Host address to bind (default: 127.0.0.1)\n"
        "    --daemonize    Fork to background\n"
        "    --pidfile <p>  PID file path (default: ./ssm-cli.pid)\n");
}

static int handle_db_version(int /*argc*/, char** /*argv*/) {
    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    int version = 0;
    st = ssm_db_version(h, &version);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "db version");

    printf("schema version: %d\n", version);
    return 0;
}

static int handle_db_migrate(int /*argc*/, char** /*argv*/) {
    ssm_handle* h = nullptr;
    ssm_status st = ssm_init(&h, g_db_path, g_db_key_len ? g_db_key : nullptr, g_db_key_len);
    if (st != SSM_OK)
        die_status(st, "ssm_init");

    st = ssm_db_migrate(h);
    ssm_destroy(h);
    if (st != SSM_OK)
        die_status(st, "db migrate");

    printf("OK: schema migration complete\n");
    return 0;
}

// -------------------------------------------------------------------
// dispatch
// -------------------------------------------------------------------
struct cmd_map {
    const char* name;
    int (*handler)(int, char**);
};

static const cmd_map user_cmds[] = {
    {"register", handle_user_register},
    {"auth", handle_user_auth},
    {"delete", handle_user_delete},
    {"change-password", handle_user_change_password},
    {nullptr, nullptr},
};

static const cmd_map secret_cmds[] = {
    {"store", handle_secret_store}, {"get", handle_secret_get}, {"delete", handle_secret_delete},
    {"list", handle_secret_list},   {nullptr, nullptr},
};

static const cmd_map kek_cmds[] = {
    {"rotate", handle_kek_rotate},
    {nullptr, nullptr},
};

static const cmd_map backup_cmds[] = {
    {"create", handle_backup_create},
    {"restore", handle_backup_restore},
    {nullptr, nullptr},
};

static const cmd_map env_cmds[] = {
    {"exec", handle_env_exec},
    {nullptr, nullptr},
};

static const cmd_map db_cmds[] = {
    {"version", handle_db_version},
    {"migrate", handle_db_migrate},
    {nullptr, nullptr},
};

static const cmd_map server_cmds[] = {
    {"start", handle_server_start},
    {nullptr, nullptr},
};

static int dispatch(const cmd_map* cmds, int argc, char** argv) {
    if (argc < 1)
        return 1;
    for (int i = 0; cmds[i].name; ++i) {
        if (std::strcmp(argv[0], cmds[i].name) == 0)
            return cmds[i].handler(argc - 1, argv + 1);
    }
    fprintf(stderr, "%s: unknown subcommand '%s'\n", g_prog, argv[0]);
    return 1;
}

// -------------------------------------------------------------------
// TUI handler (forward decl from ssm_tui.cc)
// -------------------------------------------------------------------
int handle_tui(int argc, char** argv);

// -------------------------------------------------------------------
// main
// -------------------------------------------------------------------
int main(int argc, char** argv) {
    // parse global options
    enum { OPT_JSON = 256, OPT_PASSWORD, OPT_BACKUP_KEY };
    static struct option long_opts[] = {
        {"db", required_argument, nullptr, 'd'},
        {"db-key", required_argument, nullptr, 'k'},
        {"password", required_argument, nullptr, OPT_PASSWORD},
        {"backup-key", required_argument, nullptr, OPT_BACKUP_KEY},
        {"json", no_argument, nullptr, OPT_JSON},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'v'},
        {nullptr, 0, nullptr, 0},
    };

    // Load config file before arg parsing (CLI flags override)
    ConfigFile cf = load_config();
    if (!g_cfg_db_path.empty())
        g_db_path = g_cfg_db_path.c_str();
    if (!g_cfg_db_key_hex.empty()) {
        if (!hex_decode(g_cfg_db_key_hex.c_str(), g_db_key, &g_db_key_len))
            die("invalid db_key in config file");
    }
    if (!g_cfg_password.empty())
        g_password = g_cfg_password;
    if (!g_cfg_backup_key_hex.empty()) {
        if (!hex_decode(g_cfg_backup_key_hex.c_str(), g_backup_key, &g_backup_key_len) || g_backup_key_len != 32)
            die("invalid backup_key in config file (must be 64 hex chars)");
    }
    if (cf.json)
        g_json = true;

    int opt;
    while ((opt = getopt_long(argc, argv, "+h", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'd':
                g_db_path = optarg;
                break;
            case 'k':
                if (!hex_decode(optarg, g_db_key, &g_db_key_len))
                    die("invalid --db-key (must be hex, up to 64 chars)");
                break;
            case OPT_PASSWORD:
                g_password = optarg;
                break;
            case OPT_BACKUP_KEY:
                if (!hex_decode(optarg, g_backup_key, &g_backup_key_len) || g_backup_key_len != 32)
                    die("--backup-key must be 64 hex chars (32 bytes)");
                break;
            case OPT_JSON:
                g_json = true;
                break;
            case 'v':
                print_version();
                return 0;
            case 'h':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }

    if (optind >= argc) {
        print_usage();
        return 1;
    }

    const char* cmd = argv[optind];
    int remaining = argc - optind - 1;
    char** cmd_argv = argv + optind + 1;

    if (std::strcmp(cmd, "help") == 0) {
        if (remaining >= 1) {
            if (std::strcmp(cmd_argv[0], "user") == 0)
                print_help_user();
            else if (std::strcmp(cmd_argv[0], "secret") == 0)
                print_help_secret();
            else if (std::strcmp(cmd_argv[0], "kek") == 0)
                print_help_kek();
            else if (std::strcmp(cmd_argv[0], "backup") == 0)
                print_help_backup();
            else if (std::strcmp(cmd_argv[0], "env") == 0)
                print_help_env();
            else if (std::strcmp(cmd_argv[0], "db") == 0)
                print_help_db();
            else if (std::strcmp(cmd_argv[0], "server") == 0)
                print_help_server();
            else
                print_usage();
        } else {
            print_usage();
        }
        return 0;
    }

    if (std::strcmp(cmd, "user") == 0)
        return dispatch(user_cmds, remaining, cmd_argv);
    if (std::strcmp(cmd, "secret") == 0)
        return dispatch(secret_cmds, remaining, cmd_argv);
    if (std::strcmp(cmd, "kek") == 0)
        return dispatch(kek_cmds, remaining, cmd_argv);
    if (std::strcmp(cmd, "backup") == 0)
        return dispatch(backup_cmds, remaining, cmd_argv);
    if (std::strcmp(cmd, "env") == 0)
        return dispatch(env_cmds, remaining, cmd_argv);
    if (std::strcmp(cmd, "completion") == 0) {
        const char* shell = (remaining >= 1) ? cmd_argv[0] : "bash";
        if (std::strcmp(shell, "bash") == 0) {
            printf("_ssm_cli_completions()\n");
            printf("{\n");
            printf("    local cur prev words cword\n");
            printf("    _init_completion || return\n");
            printf("\n");
            printf("    local commands=\"user secret kek cache-stats audit-log backup db export tui env server help\"\n");
            printf("    local user_sub=\"register auth delete change-password\"\n");
            printf("    local secret_sub=\"store get delete list\"\n");
            printf("    local backup_sub=\"create restore\"\n");
            printf("    local db_sub=\"version migrate\"\n");
            printf("    local env_sub=\"exec\"\n");
            printf("    local server_sub=\"start\"\n");
            printf("\n");
            printf("    if [[ $cword -eq 1 ]]; then\n");
            printf("        COMPREPLY=($(compgen -W \"$commands\" -- \"$cur\"))\n");
            printf("        return\n");
            printf("    fi\n");
            printf("    case $prev in\n");
            printf("        --db|--db-key|--password|--backup-key) return ;;\n");
            printf("        --format) COMPREPLY=($(compgen -W \"json csv\" -- \"$cur\")); return ;;\n");
            printf("    esac\n");
            printf("    case ${words[1]} in\n");
            printf("        user) [[ $cword -eq 2 ]] && COMPREPLY=($(compgen -W \"$user_sub\" -- \"$cur\")) ;;\n");
            printf("        secret) [[ $cword -eq 2 ]] && COMPREPLY=($(compgen -W \"$secret_sub\" -- \"$cur\")) ;;\n");
            printf("        kek) [[ $cword -eq 2 ]] && COMPREPLY=($(compgen -W rotate -- \"$cur\")) ;;\n");
            printf("        backup) [[ $cword -eq 2 ]] && COMPREPLY=($(compgen -W \"$backup_sub\" -- \"$cur\")); [[ $cword -eq 3 ]] && COMPREPLY=($(compgen -f -- \"$cur\")) ;;\n");
            printf("        db) [[ $cword -eq 2 ]] && COMPREPLY=($(compgen -W \"$db_sub\" -- \"$cur\")) ;;\n");
            printf("        env) [[ $cword -eq 2 ]] && COMPREPLY=($(compgen -W \"$env_sub\" -- \"$cur\")) ;;\n");
            printf("        server) [[ $cword -eq 2 ]] && COMPREPLY=($(compgen -W \"$server_sub\" -- \"$cur\")) ;;\n");
            printf("    esac\n");
            printf("}\n");
            printf("complete -F _ssm_cli_completions ssm-cli\n");
        } else if (std::strcmp(shell, "zsh") == 0) {
            printf("#compdef ssm-cli\n");
            printf("_ssm_cli() {\n");
            printf("    _arguments -C \\\n");
            printf("        '--db[DB path]:file:_files' \\\n");
            printf("        '--db-key[DB hex key]' \\\n");
            printf("        '--password[Password]' \\\n");
            printf("        '--backup-key[64 hex chars]' \\\n");
            printf("        '--json[JSON output]' \\\n");
            printf("        '--help' '--version' \\\n");
            printf("        '1: :(user secret kek cache-stats audit-log backup db export tui env server help)' \\\n");
            printf("        '*::arg:->args'\n");
            printf("    case $state in\n");
            printf("        args)\n");
            printf("            case $words[1] in\n");
            printf("                user) _describe 'user' '((register:Register auth:Authenticate delete:Delete change-password:Change\\ password))' ;;\n");
            printf("                secret) _describe 'secret' '((store:Store get:Get delete:Delete list:List))' ;;\n");
            printf("                kek) _values 'kek' rotate ;;\n");
            printf("                backup) _describe 'backup' '((create:Create restore:Restore))' ;;\n");
            printf("                db) _values 'db' version migrate ;;\n");
            printf("                env) _values 'env' exec ;;\n");
            printf("                server) _values 'server' start ;;\n");
            printf("            esac ;;\n");
            printf("    esac\n");
            printf("}\n");
            printf("_ssm_cli\n");
        } else {
            fprintf(stderr, "unknown shell '%s'. Try 'bash' or 'zsh'\n", shell);
            return 1;
        }
        return 0;
    }
    if (std::strcmp(cmd, "tui") == 0)
        return handle_tui(remaining, cmd_argv);
    if (std::strcmp(cmd, "server") == 0)
        return dispatch(server_cmds, remaining, cmd_argv);
    if (std::strcmp(cmd, "cache-stats") == 0)
        return handle_cache_stats(remaining, cmd_argv);
    if (std::strcmp(cmd, "audit-log") == 0)
        return handle_audit_log(remaining, cmd_argv);
    if (std::strcmp(cmd, "export") == 0)
        return handle_export(remaining, cmd_argv);
    if (std::strcmp(cmd, "db") == 0)
        return dispatch(db_cmds, remaining, cmd_argv);

    fprintf(stderr, "%s: unknown command '%s'. Try --help\n", g_prog, cmd);
    return 1;
}
