#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ssm_handle ssm_handle;

typedef enum {
    SSM_OK              = 0,
    SSM_ERR_AUTH        = 1,
    SSM_ERR_NOT_FOUND   = 2,
    SSM_ERR_EXPIRED     = 3,
    SSM_ERR_INTEGRITY   = 4,
    SSM_ERR_INTERNAL    = 5
} ssm_status;

ssm_status ssm_init(ssm_handle** out, const char* db_path,
                    const unsigned char* db_key, size_t db_key_len);

ssm_status ssm_destroy(ssm_handle* h);

ssm_status ssm_user_register(ssm_handle* h, const char* username,
                             const char* password);

ssm_status ssm_user_authenticate(ssm_handle* h, const char* username,
                                 const char* password, int* is_valid);

ssm_status ssm_secret_store(ssm_handle* h, const char* username,
    const unsigned char* private_key, size_t private_key_len,
    const unsigned char* public_key, size_t public_key_len,
    const char* name, const char* description);

ssm_status ssm_secret_get(ssm_handle* h, const char* username,
    const char* name, unsigned char* private_key_out, size_t* private_key_len_out,
    unsigned char* public_key_out, size_t* public_key_len_out);

ssm_status ssm_secret_delete(ssm_handle* h, const char* username,
                             const char* name);

ssm_status ssm_kek_rotate(ssm_handle* h, const char* username);

#ifdef __cplusplus
}
#endif
