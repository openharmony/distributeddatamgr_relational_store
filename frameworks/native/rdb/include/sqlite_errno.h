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

namespace OHOS {
namespace NativeRdb {
struct ErrMap {
    int32_t sqliteErr;
    int32_t errCode;
};

const static ErrMap ERROR_CODE_TABLE[] = {
    { SQLITE_FULL, E_DATABASE_FULL },
    { SQLITE_BUSY, E_DATABASE_BUSY },
    { SQLITE_LOCKED, E_DATABASE_BUSY },
    { SQLITE_EMPTY, E_OK },
    { SQLITE_MISMATCH, E_INVALID_ARGS },
    { SQLITE_CORRUPT, E_DATABASE_CORRUPT },
    { SQLITE_NOTADB, E_DATABASE_CORRUPT },
};
class SQLiteError {
public:
    static constexpr size_t TABLE_SIZE = sizeof(ERROR_CODE_TABLE) / sizeof(ERROR_CODE_TABLE[0]);
    static int ErrNo(int sqliteErr)
    {
        ErrMap tag = { sqliteErr, E_SQLITE_ERROR };
        auto it = std::lower_bound(ERROR_CODE_TABLE, ERROR_CODE_TABLE + TABLE_SIZE, tag,
            [](const ErrMap &first, const ErrMap &second) { return first.sqliteErr < second.sqliteErr; });
        if (it < ERROR_CODE_TABLE + TABLE_SIZE) {
            return it->errCode;
        }
        return E_SQLITE_ERROR;
    }
};
} // namespace NativeRdb
} // namespace OHOS

#endif
