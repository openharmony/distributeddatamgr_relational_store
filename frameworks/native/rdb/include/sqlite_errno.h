/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_SQLITE_ERRNO_H
#define NATIVE_RDB_SQLITE_ERRNO_H

#include <sqlite3sym.h>

#include <map>

#include "rdb_errno.h"

#ifndef SQLITE_META_RECOVERED
#define SQLITE_META_RECOVERED 66
#endif
namespace OHOS {
namespace NativeRdb {
struct SQLiteErrorCode {
    int sqliteError;
    int rdbError;
};
static constexpr SQLiteErrorCode SQLiteErrorCodes[] = {
    { SQLITE_ERROR, E_SQLITE_ERROR },
    { SQLITE_PERM, E_SQLITE_PERM },
    { SQLITE_ABORT, E_SQLITE_ABORT },
    { SQLITE_BUSY, E_SQLITE_BUSY },
    { SQLITE_LOCKED, E_SQLITE_LOCKED },
    { SQLITE_NOMEM, E_SQLITE_NOMEM },
    { SQLITE_READONLY, E_SQLITE_READONLY },
    { SQLITE_INTERRUPT, E_SQLITE_INTERRUPT},
    { SQLITE_IOERR, E_SQLITE_IOERR },
    { SQLITE_CORRUPT, E_SQLITE_CORRUPT },
    { SQLITE_FULL, E_SQLITE_FULL },
    { SQLITE_CANTOPEN, E_SQLITE_CANTOPEN },
    { SQLITE_SCHEMA, E_SQLITE_SCHEMA },
    { SQLITE_TOOBIG, E_SQLITE_TOOBIG },
    { SQLITE_CONSTRAINT, E_SQLITE_CONSTRAINT },
    { SQLITE_MISMATCH, E_SQLITE_MISMATCH },
    { SQLITE_MISUSE, E_SQLITE_MISUSE },
    { SQLITE_NOTADB, E_SQLITE_CORRUPT },
    { SQLITE_META_RECOVERED, E_SQLITE_META_RECOVERED },
    { SQLITE_ROW, E_OK },
    { SQLITE_DONE, E_NO_MORE_ROWS },
};

static constexpr bool IsIncreasing()
{
    for (size_t i = 1; i < sizeof(SQLiteErrorCodes) / sizeof(SQLiteErrorCode); i++) {
        if (SQLiteErrorCodes[i].sqliteError <= SQLiteErrorCodes[i - 1].sqliteError) {
            return false;
        }
    }
    return true;
}
// JS_ERROR_CODE_MSGS must ensure increment
static_assert(IsIncreasing());

static int GetRdbErrorCode(int32_t errorCode)
{
    auto jsErrorCode = SQLiteErrorCode{ errorCode, -errorCode };
    auto iter = std::lower_bound(SQLiteErrorCodes,
        SQLiteErrorCodes + sizeof(SQLiteErrorCodes) / sizeof(SQLiteErrorCodes[0]), jsErrorCode,
        [](const SQLiteErrorCode &jsErrorCode1, const SQLiteErrorCode &jsErrorCode2) {
            return jsErrorCode1.sqliteError < jsErrorCode2.sqliteError;
        });
    if (iter < SQLiteErrorCodes + sizeof(SQLiteErrorCodes) / sizeof(SQLiteErrorCodes[0]) &&
        iter->sqliteError == errorCode) {
        return iter->rdbError;
    }
    return -errorCode;
}
class SQLiteError {
public:
    static int ErrNo(int sqliteErr)
    {
        return GetRdbErrorCode(sqliteErr);
    }
};
} // namespace NativeRdb
} // namespace OHOS

#endif
