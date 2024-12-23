/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef GRD_ERROR_H
#define GRD_ERROR_H

#include "grd_type_export.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Error category
#define GRD_OK 0

// Error category
#define GRD_NOT_SUPPORT (-1000)
#define GRD_OVER_LIMIT (-2000)
#define GRD_INVALID_ARGS (-3000)
#define GRD_SYSTEM_ERR (-4000)
#define GRD_FAILED_FILE_OPERATION (-5000)
#define GRD_INVALID_FILE_FORMAT (-6000)
#define GRD_INSUFFICIENT_SPACE (-7000)
#define GRD_INNER_ERR (-8000)
#define GRD_RESOURCE_BUSY (-9000)

#define GRD_NO_DATA (-11000)
#define GRD_FAILED_MEMORY_ALLOCATE (-13000)
#define GRD_FAILED_MEMORY_RELEASE (-14000)
#define GRD_DATA_CONFLICT (-16000)
#define GRD_DATA_MISMATCH (-17000)
#define GRD_NOT_AVAILABLE (-19000)
#define GRD_ACTIVE_TRANSACTION (-20000)
#define GRD_UNIQUE_VIOLATION (-21000)
#define GRD_DUPLICATE_TABLE (-22000)
#define GRD_UNDEFINED_TABLE (-23000)
#define GRD_INVALID_BIND_VALUE (-36000)
#define GRD_INVALID_FORMAT (-37000)
#define GRD_REBUILD_DATABASE (-38000)
#define GRD_TIME_OUT (-39000)
#define GRD_DB_INSTANCE_ABNORMAL (-40000)
#define GRD_DISK_SPACE_FULL (-41000)
#define GRD_CRC_CHECK_DISABLED (-42000)
#define GRD_PERMISSION_DENIED (-43000)
#define GRD_SYNC_PREREQUISITES_ABNORMAL (-44000)
#define GRD_DATA_CORRUPTED (-45000)
#define GRD_DB_BUSY (-46000)
#define GRD_CALC_MODE_SET_PERMISSION_DENIED (-47000)

// not support
#define GRD_JSON_OPERATION_NOT_SUPPORT (-5001001)
#define GRD_MODEL_NOT_SUPPORT (-5001002)
#define GRD_FEATURE_NOT_SUPPORTED (-5001003)

// Exceed limit
#define GRD_JSON_LEN_LIMIT (-5002001)

// Invalid parameter
#define GRD_FIELD_TYPE_NOT_MATCH (-5003001)
#define GRD_LARGE_JSON_NEST (-5003002)
#define GRD_INVALID_JSON_TYPE (-5003003)
#define GRD_INVALID_CONFIG_VALUE (-5003004)
#define GRD_INVALID_OPERATOR (-5003005)
#define GRD_INVALID_PROJECTION_FIELD (-5003006)
#define GRD_INVALID_PROJECTION_VALUE (-5003007)
#define GRD_ARRAY_INDEX_NOT_FOUND (-5003008)
#define GRD_NAME_TOO_LONG (-5003025)
#define GRD_INVALID_TABLE_DEFINITION (-5003026)
#define GRD_WRONG_STMT_OBJECT (-5003027)
#define GRD_SEMANTIC_ERROR (-5003028)
#define GRD_SYNTAX_ERROR (-5003029)

// System err
#define GRD_JSON_LIB_HANDLE_FAILED (-5004001)

// no data
#define GRD_COLLECTION_NOT_FOUND (-5011001)
#define GRD_RECORD_NOT_FOUND (-5011002)
#define GRD_FIELD_NOT_FOUND (-5011004)

// data conflicted
#define GRD_COLLECTION_CONFLICT (-5016001)
#define GRD_KEY_CONFLICT (-5016002)
#define GRD_FIELD_TYPE_CONFLICT (-5016003)

// Cursor or ResultSet not available
#define GRD_RESULT_SET_NOT_AVAILABLE (-5019001)

// violation
#define GRD_PRIMARY_KEY_VIOLATION (-5021001)
#define GRD_RESTRICT_VIOLATION (-5021002)
#define GRD_CONSTRAINT_CHECK_VIOLATION (-5021003)

// Invalid format
#define GRD_INVALID_JSON_FORMAT (-5037001)
#define GRD_INVALID_KEY_FORMAT (-5037002)
#define GRD_INVALID_COLLECTION_NAME (-5037003)

#define GRD_CIPHER_ERROR (-48000)
#define GRD_PASSWORD_NEED_REKEY (-48001)
#define GRD_PASSWORD_UNMATCHED (-48002)

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // GRD_ERROR_H