#include "ssm/ssm.h"

struct ssm_handle {};

ssm_status ssm_init(ssm_handle** out, const char* db_path,
                    const unsigned char* db_key, size_t db_key_len)
{
    (void)db_path;
    (void)db_key;
    (void)db_key_len;
    *out = new ssm_handle{};
    return SSM_OK;
}

ssm_status ssm_destroy(ssm_handle* h)
{
    delete h;
    return SSM_OK;
}

ssm_status ssm_user_register(ssm_handle* h, const char* username,
                             const char* password)
{
    (void)h;
    (void)username;
    (void)password;
    return SSM_ERR_INTERNAL;
}

ssm_status ssm_user_authenticate(ssm_handle* h, const char* username,
                                 const char* password, int* is_valid)
{
    (void)h;
    (void)username;
    (void)password;
    (void)is_valid;
    return SSM_ERR_INTERNAL;
}

ssm_status ssm_secret_store(ssm_handle* h, const char* username,
    const unsigned char* private_key, size_t private_key_len,
    const unsigned char* public_key, size_t public_key_len,
    const char* name, const char* description)
{
    (void)h;
    (void)username;
    (void)private_key;
    (void)private_key_len;
    (void)public_key;
    (void)public_key_len;
    (void)name;
    (void)description;
    return SSM_ERR_INTERNAL;
}

ssm_status ssm_secret_get(ssm_handle* h, const char* username,
    const char* name, unsigned char* private_key_out, size_t* private_key_len_out,
    unsigned char* public_key_out, size_t* public_key_len_out)
{
    (void)h;
    (void)username;
    (void)name;
    (void)private_key_out;
    (void)private_key_len_out;
    (void)public_key_out;
    (void)public_key_len_out;
    return SSM_ERR_INTERNAL;
}

ssm_status ssm_secret_delete(ssm_handle* h, const char* username,
                             const char* name)
{
    (void)h;
    (void)username;
    (void)name;
    return SSM_ERR_INTERNAL;
}

ssm_status ssm_kek_rotate(ssm_handle* h, const char* username)
{
    (void)h;
    (void)username;
    return SSM_ERR_INTERNAL;
}
