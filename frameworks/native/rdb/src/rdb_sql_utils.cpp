/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#ifdef WINDOWS_PLATFORM
#include <dir.h>
#endif

#include "rdb_errno.h"
#include "rdb_sql_utils.h"
#include "sqlite_sql_builder.h"

#ifdef WINDOWS_PLATFORM
#define MKDIR(filePath) (mkdir(filePath))
#else
#define MKDIR(filePath) (mkdir(filePath, 0771))
#endif

namespace OHOS {
namespace NativeRdb {

/**
 * Get and Check default path.
 */
std::string RdbSqlUtils::GetDefaultDatabasePath(const std::string &baseDir, const std::string &name, int &errorCode)
{
    std::string databasePath = baseDir + "/rdb";
    if (access(databasePath.c_str(), F_OK) != 0) {
        if (MKDIR(databasePath.c_str())) {
            errorCode = E_CREATE_FOLDER_FAIL;
        }
    }
    return databasePath.append("/").append(name);
}

std::string RdbSqlUtils::BuildQueryString(const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    return SqliteSqlBuilder::BuildQueryString(predicates, columns);
}
} // namespace NativeRdb
} // namespace OHOS