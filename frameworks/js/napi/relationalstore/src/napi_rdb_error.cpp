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
    { E_NOT_STAGE_MODE, 14801001, "Only supported in stage mode." },
    { E_DATA_GROUP_ID_INVALID, 14801002, "The data group id is invalid." },
    { NativeRdb::E_NOT_SELECT, 14800019, "The SQL must be a query statement." },
    { NativeRdb::E_COLUMN_OUT_RANGE, 14800013, "Column out of bounds." },
    { NativeRdb::E_INVALID_FILE_PATH, 14800010, "Invalid database path." },
    { NativeRdb::E_ROW_OUT_RANGE, 14800012, "Row out of bounds." },
    { NativeRdb::E_NO_ROW_IN_QUERY, 14800018, "No data meets the condition." },
    { NativeRdb::E_ALREADY_CLOSED, 14800014, "Already closed." },
    { NativeRdb::E_DATABASE_BUSY, 14800015, "The database does not respond." },
    { NativeRdb::E_WAL_SIZE_OVER_LIMIT, 14800047, "The WAL file size over default limit." },
    { NativeRdb::E_GET_DATAOBSMGRCLIENT_FAIL, 14801050, "Failed to get DataObsMgrClient." },
    { NativeRdb::E_TYPE_MISMATCH, 14800051, "The type of the distributed table does not match." },
    { NativeRdb::E_SQLITE_FULL, 14800029, "SQLite: The database is full." },
    { NativeRdb::E_ATTACHED_DATABASE_EXIST, 14800016, "The database is already attached." },
    { NativeRdb::E_SQLITE_ERROR, 14800021, "SQLite: Generic error." },
    { NativeRdb::E_SQLITE_CORRUPT, 14800011, "Database corrupted." },
    { NativeRdb::E_SQLITE_ABORT, 14800022, "SQLite: Callback routine requested an abort." },
    { NativeRdb::E_SQLITE_PERM, 14800023, "SQLite: Access permission denied." },
    { NativeRdb::E_SQLITE_BUSY, 14800024, "SQLite: The database file is locked." },
    { NativeRdb::E_SQLITE_LOCKED, 14800025, "SQLite: A table in the database is locked." },
    { NativeRdb::E_SQLITE_NOMEM, 14800026, "SQLite: The database is out of memory." },
    { NativeRdb::E_SQLITE_READONLY, 14800027, "SQLite: Attempt to write a readonly database." },
    { NativeRdb::E_SQLITE_IOERR, 14800028, "SQLite: Some kind of disk I/O error occurred." },
    { NativeRdb::E_SQLITE_CANTOPEN, 14800030, "SQLite: Unable to open the database file." },
    { NativeRdb::E_SQLITE_TOOBIG, 14800031, "SQLite: TEXT or BLOB exceeds size limit." },
    { NativeRdb::E_SQLITE_CONSTRAINT, 14800032, "SQLite: Abort due to constraint violation." },
    { NativeRdb::E_SQLITE_MISMATCH, 14800033, "SQLite: Data type mismatch." },
    { NativeRdb::E_SQLITE_MISUSE, 14800034, "SQLite: Library used incorrectly." },
    { NativeRdb::E_CONFIG_INVALID_CHANGE, 14800017, "Config changed." },
    { NativeRdb::E_NOT_SUPPORTED, 801, "Capability not supported." },
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