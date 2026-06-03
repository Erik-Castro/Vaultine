#pragma once

#include <stddef.h>

// Forward declarations from ssm/ssm.h — avoids pulling in entire public API
#if defined(__cplusplus)
extern "C" {
#endif
enum ssm_status_e : int;
typedef enum ssm_status_e ssm_status;
enum ssm_export_format_e : int;
typedef enum ssm_export_format_e ssm_export_format;
typedef void (*ssm_export_cb)(const char*, size_t, void*);
#if defined(__cplusplus)
}
#endif

#include <sqlcipher.h>

namespace ssm::v1 {

ssm_status export_metadata(sqlite3* db, ssm_export_format format, int redact_pii,
                           ssm_export_cb callback, void* user_data);

}  // namespace ssm::v1
