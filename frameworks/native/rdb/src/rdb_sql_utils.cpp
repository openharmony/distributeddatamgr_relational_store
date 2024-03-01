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

#include "rdb_sql_utils.h"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>

#include "acl.h"
#include "rdb_errno.h"
#include "rdb_platform.h"
#include "sqlite_sql_builder.h"
namespace OHOS {
namespace NativeRdb {
using namespace OHOS::DATABASE_UTILS;
constexpr int32_t SERVICE_GID = 3012;
int RdbSqlUtils::CreateDirectory(const std::string &databaseDir)
{
    std::string tempDirectory = databaseDir;
    std::vector<std::string> directories;

    size_t pos = tempDirectory.find('/');
    while (pos != std::string::npos) {
        std::string directory = tempDirectory.substr(0, pos);
        directories.push_back(directory);
        tempDirectory = tempDirectory.substr(pos + 1);
        pos = tempDirectory.find('/');
    }
    directories.push_back(tempDirectory);

    std::string databaseDirectory;
    for (const std::string& directory : directories) {
        databaseDirectory = databaseDirectory + "/" + directory;
        if (access(databaseDirectory.c_str(), F_OK) != 0) {
            if (MkDir(databaseDirectory)) {
                return E_CREATE_FOLDER_FAIL;
            }
            // Set the default ACL attribute to the database root directory to ensure that files created by the server
            // also have permission to operate on the client side.
            Acl acl(databaseDirectory);
            acl.SetDefaultUser(GetUid(), Acl::R_RIGHT | Acl::W_RIGHT);
            acl.SetDefaultGroup(SERVICE_GID, Acl::R_RIGHT | Acl::W_RIGHT);
        }
    }
    return E_OK;
}

/**
 * @brief get custom data base path.
 */
std::pair<std::string, int> RdbSqlUtils::GetDefaultDatabasePath(const std::string &baseDir, const std::string &name,
    const std::string &customDir)
{
    int errorCode = E_OK;
    if (customDir.empty()) {
        return std::make_pair(GetDefaultDatabasePath(baseDir, name, errorCode), errorCode);
    }

    std::string databaseDir;
    databaseDir.append(baseDir).append("/rdb/").append(customDir);

    errorCode = CreateDirectory(databaseDir);
    return std::make_pair(databaseDir.append("/").append(name), errorCode);
}

/**
 * Get and Check default path.
 */
std::string RdbSqlUtils::GetDefaultDatabasePath(const std::string &baseDir, const std::string &name, int &errorCode)
{
    std::string databaseDir = baseDir + "/rdb";
    errorCode = CreateDirectory(databaseDir);
    return databaseDir.append("/").append(name);
}

std::string RdbSqlUtils::BuildQueryString(const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    return SqliteSqlBuilder::BuildQueryString(predicates, columns);
}
} // namespace NativeRdb
} // namespace OHOS