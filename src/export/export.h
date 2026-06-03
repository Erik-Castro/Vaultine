#pragma once

#include "ssm/ssm.h"

#include <sqlcipher.h>

namespace ssm::v1 {

ssm_status export_metadata(sqlite3* db, ssm_export_format format, int redact_pii,
                           ssm_export_cb callback, void* user_data);

}  // namespace ssm::v1
