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
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#ifdef WINDOWS_PLATFORM
#include <dir.h>
#endif
#include <climits>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_sql_utils.h"
#include "sqlite_sql_builder.h"

#ifdef WINDOWS_PLATFORM
#define REALPATH(relPath, absPath, ...) (_fullpath(absPath, relPath, ##__VA_ARGS__))
#define MKDIR(filePath) (mkdir(filePath))
#else
#define REALPATH(absPath, relPath, ...) (realpath(absPath, relPath))
#define MKDIR(filePath) (mkdir(filePath, 0771))
#endif

namespace OHOS {
namespace NativeRdb {
/**
 * Get and Check default path.
 */
std::string RdbSqlUtils::GetDefaultDatabasePath(const std::string &baseDir, const std::string &name, int &errorCode)
{
    if (access(baseDir.c_str(), F_OK) != 0) {
        if (MKDIR(baseDir.c_str())) {
            errorCode = E_CREATE_FOLDER_FAIL;
        }
    }
#if defined(WINDOWS_PLATFORM)
    std::string databasePath = baseDir + "\\rdb";
#else
    std::string databasePath = baseDir + "/rdb";
#endif
    if (access(databasePath.c_str(), F_OK) != 0) {
        if (MKDIR(databasePath.c_str())) {
            errorCode = E_CREATE_FOLDER_FAIL;
        }
    }
    char canonicalPath[PATH_MAX + 1] = { 0 };
    if (REALPATH(databasePath.c_str(), canonicalPath, PATH_MAX) == nullptr) {
        LOG_ERROR("Failed to obtain real path, errno:%{public}d", errno);
        errorCode = E_INVALID_FILE_PATH;
        return "";
    }
    std::string realFilePath(canonicalPath);
#if defined(WINDOWS_PLATFORM)
    realFilePath = realFilePath.append("\\").append(name);
#else
    realFilePath = realFilePath.append("/").append(name);
#endif
    return realFilePath;
}

std::string RdbSqlUtils::BuildQueryString(const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    return SqliteSqlBuilder::BuildQueryString(predicates, columns);
}
} // namespace NativeRdb
} // namespace OHOS