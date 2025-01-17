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
    { E_DATABASE_BUSY, 31300003, "The database is busy." },
    { E_GRD_FAILED_MEMORY_ALLOCATE, 31300004, "The database is out of memory." },
    { E_GRD_DISK_SPACE_FULL, 31300005, "The database is full." },
    { E_GRD_DUPLICATE_PARAM, 31300006,
        "A duplicate graph name, vertex or edge type, or vertex or edge property name exists." },
    { E_GRD_UNDEFINED_PARAM, 31300007,
        "The graph name, vertex or edge type, or vertex or edge property is not defined." },
    { E_GRD_INVALID_NAME, 31300008,
        "The graph name, vertex or edge type, or vertex or edge property name does not conform to constraints." },
    { E_GRD_SYNTAX_ERROR, 31300009, "The GQL statement syntax error." },
    { E_GRD_SEMANTIC_ERROR, 31300010, "The GQL statement semantic error." },
    { E_GRD_OVER_LIMIT, 31300012,
        "The number of graph names, vertex or edge types, or vertex or edge properties exceeds the limit." },
    { E_GRD_DATA_CONFLICT, 31300013, "A conflicting constraint already exists." },
    { E_DBPATH_ACCESS_FAILED, 31300014, "Invalid database path." },
    { E_CONFIG_INVALID_CHANGE, 31300015, "Config changed." },
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