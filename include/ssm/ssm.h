#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define SSM_EXPORT __attribute__((visibility("default")))
#else
#define SSM_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ssm_handle ssm_handle;

typedef enum {
    SSM_OK = 0,
    SSM_ERR_AUTH = 1,
    SSM_ERR_NOT_FOUND = 2,
    SSM_ERR_EXPIRED = 3,
    SSM_ERR_INTEGRITY = 4,
    SSM_ERR_INTERNAL = 5
} ssm_status;

SSM_EXPORT ssm_status ssm_init(ssm_handle** out, const char* db_path, const unsigned char* db_key,
                               size_t db_key_len);

SSM_EXPORT ssm_status ssm_destroy(ssm_handle* h);

SSM_EXPORT ssm_status ssm_user_register(ssm_handle* h, const char* username, const char* password);

SSM_EXPORT ssm_status ssm_user_authenticate(ssm_handle* h, const char* username,
                                            const char* password, int* is_valid);

SSM_EXPORT ssm_status ssm_user_delete(ssm_handle* h, const char* username, const char* password);

SSM_EXPORT ssm_status ssm_user_change_password(ssm_handle* h, const char* username,
                                               const char* old_password, const char* new_password);

SSM_EXPORT ssm_status ssm_secret_store(ssm_handle* h, const char* username,
                                       const unsigned char* private_key, size_t private_key_len,
                                       const unsigned char* public_key, size_t public_key_len,
                                       const char* name, const char* description);

SSM_EXPORT ssm_status ssm_secret_get(ssm_handle* h, const char* username, const char* name,
                                     unsigned char* private_key_out, size_t* private_key_len_out,
                                     unsigned char* public_key_out, size_t* public_key_len_out);

SSM_EXPORT ssm_status ssm_secret_delete(ssm_handle* h, const char* username, const char* name);

typedef void (*ssm_secret_list_cb)(const char* name, const char* description,
                                   const char* updated_at, size_t public_key_len, void* user_data);

typedef ssm_status (*ssm_password_validator)(const char* password, void* user_data);

SSM_EXPORT void ssm_set_password_validator(ssm_password_validator validator, void* user_data);

SSM_EXPORT ssm_status ssm_secret_list(ssm_handle* h, const char* username,
                                      ssm_secret_list_cb callback, void* user_data);

SSM_EXPORT ssm_status ssm_kek_rotate(ssm_handle* h, const char* username);

typedef struct {
    size_t total_entries;
    size_t valid_entries;
    size_t hit_count;
    size_t miss_count;
} ssm_cache_stats;

SSM_EXPORT ssm_status ssm_cache_get_stats(ssm_handle* h, ssm_cache_stats* out);

typedef void (*ssm_audit_log_cb)(int64_t id, int64_t user_id, const char* username,
                                 const char* operation, const char* operation_target,
                                 const char* details, const char* result, const char* timestamp,
                                 void* user_data);

SSM_EXPORT ssm_status ssm_audit_log_query(ssm_handle* h, const char* username,
                                          const char* operation, const char* result, int64_t limit,
                                          int64_t offset, ssm_audit_log_cb callback,
                                          void* user_data);

SSM_EXPORT ssm_status ssm_backup_create(ssm_handle* h, const char* backup_path,
                                        const unsigned char* backup_key, size_t backup_key_len);

SSM_EXPORT ssm_status ssm_backup_restore(ssm_handle* h, const char* backup_path,
                                         const unsigned char* backup_key, size_t backup_key_len);

typedef enum {
    SSM_EXPORT_JSON = 0,
    SSM_EXPORT_CSV = 1
} ssm_export_format;

typedef void (*ssm_export_cb)(const char* chunk, size_t len, void* user_data);

SSM_EXPORT ssm_status ssm_export(ssm_handle* h, ssm_export_format format, int redact_pii,
                                 ssm_export_cb callback, void* user_data);

SSM_EXPORT ssm_status ssm_db_version(ssm_handle* h, int* version_out);

SSM_EXPORT ssm_status ssm_db_migrate(ssm_handle* h);

SSM_EXPORT const char* ssm_status_to_string(ssm_status status);

#ifdef __cplusplus
}
#endif
