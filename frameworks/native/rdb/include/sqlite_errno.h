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
const static std::map<int, int> ERROR_CODE_MAPPINT_TABLE = {
    { SQLITE_ERROR, E_SQLITE_ERROR },
    { SQLITE_ABORT, E_SQLITE_ABORT },
    { SQLITE_PERM, E_SQLITE_PERM },
    { SQLITE_BUSY, E_SQLITE_BUSY },
    { SQLITE_LOCKED, E_SQLITE_LOCKED },
    { SQLITE_NOMEM, E_SQLITE_NOMEM },
    { SQLITE_READONLY, E_SQLITE_READONLY },
    { SQLITE_IOERR, E_SQLITE_IOERR },
    { SQLITE_CORRUPT, E_SQLITE_CORRUPT },
    { SQLITE_FULL, E_SQLITE_FULL },
    { SQLITE_CANTOPEN, E_SQLITE_CANTOPEN },
    { SQLITE_TOOBIG, E_SQLITE_TOOBIG },
    { SQLITE_CONSTRAINT, E_SQLITE_CONSTRAINT },
    { SQLITE_MISMATCH, E_SQLITE_MISMATCH },
    { SQLITE_MISUSE, E_SQLITE_MISUSE },
    { SQLITE_NOTADB, E_SQLITE_CORRUPT },
};
class SQLiteError {
public:
    static int ErrNo(int sqliteErr)
    {
        auto iter = ERROR_CODE_MAPPINT_TABLE.find(sqliteErr);
        if (iter != ERROR_CODE_MAPPINT_TABLE.end()) {
            return iter->second;
        }
        return -sqliteErr;
    }
};
} // namespace NativeRdb
} // namespace OHOS

#endif
