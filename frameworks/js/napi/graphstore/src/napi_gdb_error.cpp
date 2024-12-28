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

#include "napi_gdb_error.h"

#include <algorithm>

#include "aip_errors.h"

namespace OHOS::GraphStoreJsKit {
using namespace DistributedDataAip;
static constexpr JsErrorCode JS_ERROR_CODE_MSGS[] = {
    { E_INVALID_ARGS, 401, "Parameter error." },
    { E_GRD_DATA_CORRUPTED, 31300001, "Database corrupted." },
    { E_GRD_DB_INSTANCE_ABNORMAL, 31300002, "Already closed." },
    { E_GRD_DB_BUSY, 31300003, "The database is busy." },
    { E_GRD_FAILED_MEMORY_ALLOCATE, 31300004, "The database is out of memory." },
    { E_GRD_DISK_SPACE_FULL, 31300005, "The database is full." },
    { E_GRD_DUPLICATE_TABLE, 31300006, "Duplicate type or properties name of vertex and edge." },
    { E_GRD_DUPLICATE_OBJECT, 31300006, "Duplicate type or properties name of vertex and edge." },
    { E_GRD_DUPLICATE_COLUMN, 31300006, "Duplicate type or properties name of vertex and edge." },
    { E_GRD_UNDEFINE_COLUMN, 31300007, "The type or properties of vertex and edge is not defined." },
    { E_GRD_UNDEFINED_OBJECT, 31300007, "The type or properties of vertex and edge is not defined." },
    { E_GRD_UNDEFINED_TABLE, 31300007, "The type or properties of vertex and edge is not defined." },
    { E_GRD_PRIMARY_KEY_VIOLATION, 31300008,
        "The type or properties name of vertex and edge does not conform to constraint." },
    { E_GRD_RESTRICT_VIOLATION, 31300008,
        "The type or properties name of vertex and edge does not conform to constraint." },
    { E_GRD_CONSTRAINT_CHECK_VIOLATION, 31300008,
        "The type or properties name of vertex and edge does not conform to constraint." },
    { E_GRD_SYNTAX_ERROR, 31300009, "The GQL statement syntax error." },
    { E_GRD_SEMANTIC_ERROR, 31300010, "The GQL statement semantic error." },
    { E_GRD_OVER_LIMIT, 31300012, "The number of types or properties of vertex and edge exceeds the upper limit." },
    { E_GRD_NAME_TOO_LONG, 31300013, "A conflicting constraint already exists." },
    { E_GRD_NOT_SUPPORT, 31300010, "The GQL statement semantic error." },
    { E_GRD_INVALID_ARGS, 401, "Parameter error." },
    { E_GRD_INVALID_ARGS, 31300010, "The GQL statement semantic error." },
    { E_GRD_INSUFFICIENT_SPACE, 31300005, "The database is full." },
    { E_GRD_RESOURCE_BUSY, 31300003, "The database is busy." },
    { E_GRD_PASSWORD_UNMATCHED, 401, "Password error." },
    { E_GRD_PASSWORD_NEED_REKEY, 401, "Password error." },
    { E_GRD_INVALID_TABLE_DEFINITION, 31300010, "The GQL statement semantic error." },
    { E_GRD_DATA_CONFLICT, 31300013, "A conflicting constraint already exists." },
    { E_GRD_INVALID_FORMAT, 31300010, "The GQL statement semantic error." },
    { E_GRD_TIME_OUT, 31300003, "The database is busy." },
    { E_DATABASE_BUSY, 31300003, "The database is busy." },
    { E_GRD_INVALID_CONFIG_VALUE, 401, "Store config parameter error." },
    { E_GRD_INVALID_CONFIG_VALUE, 31300015, "Config changed." },
    { E_GRD_REQUEST_TIME_OUT, 31300003, "The database is busy." },
    { E_GRD_EXCEEDED_LIMIT, 31300013, "A conflicting constraint already exists." },
    { E_GRD_SCHEMA_CHANGED, 31300015, "Config changed." },
    { E_GRD_FIELD_OVERFLOW, 31300010, "The GQL statement semantic error." },
    { E_GRD_DIVISION_BY_ZERO, 31300009, "The GQL statement syntax error." },
    { E_GQL_LENGTH_OVER_LIMIT, 401, "The GQL statement is too long." },
    { E_DBPATH_ACCESS_FAILED, 401, "Database path error." },
    { E_CONFIG_INVALID_CHANGE, 401, "Store config parameter error." },
};

std::optional<JsErrorCode> GetJsErrorCode(int32_t errorCode)
{
    auto jsErrorCode = JsErrorCode{ errorCode, -1, "" };
    auto iter = std::lower_bound(JS_ERROR_CODE_MSGS,
        JS_ERROR_CODE_MSGS + sizeof(JS_ERROR_CODE_MSGS) / sizeof(JS_ERROR_CODE_MSGS[0]), jsErrorCode,
        [](const JsErrorCode &jsErrorCode1, const JsErrorCode &jsErrorCode2) {
            return jsErrorCode1.status < jsErrorCode2.status;
        });
    if (iter < JS_ERROR_CODE_MSGS + sizeof(JS_ERROR_CODE_MSGS) / sizeof(JS_ERROR_CODE_MSGS[0]) &&
        iter->status == errorCode) {
        return *iter;
    }
    return std::nullopt;
}
} // namespace OHOS::GraphStoreJsKit