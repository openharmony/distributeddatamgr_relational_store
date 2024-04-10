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

#include "napi_rdb_error.h"

#include <algorithm>

namespace OHOS {
namespace RelationalStoreJsKit {
using JsErrorCode = OHOS::RelationalStoreJsKit::JsErrorCode;
static constexpr JsErrorCode JS_ERROR_CODE_MSGS[] = {
    { NativeRdb::E_NOT_SUPPORTED, 801, "Capability not supported." },
    { NativeRdb::E_INCORRECT_SQL, 14800018, "Incorrect SQL. Grammar errors or violation of constraints." },
    { NativeRdb::E_NOT_SELECT, 14800019, "The SQL must be a query statement." },
    { NativeRdb::E_OUT_RANGE, 14800020, "The column index is invalid." },
    { NativeRdb::E_INVALID_FILE_PATH, 14800010, "Invalid database path." },
    { E_RESULT_GOTO_ERROR, 14800012, "The result set is empty or the specified location is invalid." },
    { NativeRdb::E_INVALID_STATEMENT, 14800013, "The column value is null or the column type is incompatible." },
    { NativeRdb::E_NOT_INIT,  14800013, "The column value is null or the column type is incompatible." },
    { NativeRdb::E_ALREADY_CLOSED, 14800014, "The resultSet has been closed." },
    { NativeRdb::E_DATABASE_BUSY, 14800015, "The database does not respond." },
    { NativeRdb::E_WAL_SIZE_OVER_LIMIT, 14800047, "The WAL file size over default limit." },
    { NativeRdb::E_GET_DATAOBSMGRCLIENT_FAIL, 14801050, "Failed to get DataObsMgrClient." },
    { NativeRdb::E_TYPE_MISMATCH, 14800051, "The type of the distributed table does not match." },
    { NativeRdb::E_DATABASE_FULL, 14800052, "database or disk is full." },
    { NativeRdb::E_ATTACHED_DATABASE_EXIST, 14800016, "The database is already attached." },
    { NativeRdb::E_DATABASE_CORRUPT, E_DATABASE_CORRUPT, "Failed to open database by database corrupted." },
    { E_NOT_STAGE_MODE, 14801001, "Only supported in stage mode." },
    { E_DATA_GROUP_ID_INVALID, 14801002, "The data group id is invalid." },
};

const std::optional<JsErrorCode> GetJsErrorCode(int32_t errorCode)
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

} // namespace RelationalStoreJsKit
} // namespace OHOS