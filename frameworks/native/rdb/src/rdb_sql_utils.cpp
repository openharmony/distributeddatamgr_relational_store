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

#define LOG_TAG "RdbSqlUtils"
#include "rdb_sql_utils.h"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>

#include "acl.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_platform.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"
#include "rdb_fault_hiview_reporter.h"

namespace OHOS {
using namespace Rdb;
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
    struct stat stats[2];
    int32_t cur = 0;
    int32_t prev = cur;
    for (const std::string &directory : directories) {
        if (directory.empty()) {
            continue;
        }
        databaseDirectory = databaseDirectory + "/" + directory;
        prev = cur;
        // (cur + 1) % 2 Switch the two positions of stats
        cur = (cur + 1) % 2;
        if (stat(databaseDirectory.c_str(), &stats[cur]) != 0) {
            if (MkDir(databaseDirectory)) {
                LOG_ERROR("failed to mkdir errno:%{public}d %{public}s prev:[%{public}" PRIu64
                          ",%{public}d,%{public}d,%{public}o]",
                    errno, SqliteUtils::Anonymous(databaseDirectory).c_str(), stats[prev].st_ino, stats[prev].st_uid,
                    stats[prev].st_gid, stats[prev].st_mode);
                RdbFaultHiViewReporter::ReportFault(RdbFaultEvent(FT_EX_FILE, E_CREATE_FOLDER_FAIL, BUNDLE_NAME_COMMON,
                    "failed to mkdir errno[ " + std::to_string(errno) + "]," + databaseDirectory +
                        "ino:" + std::to_string(stats[prev].st_ino) + "uid:" + std::to_string(stats[prev].st_uid) +
                        "gid:" + std::to_string(stats[prev].st_gid) + SqliteUtils::StModeToString(stats[prev].st_mode)));
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

std::pair<std::string, int> RdbSqlUtils::GetCustomDatabasePath(
    const std::string &rootDir, const std::string &name, const std::string &customDir)
{
    std::string databasePath;
    databasePath.append(rootDir).append("/").append(customDir).append("/").append(name);

    struct stat fileStat;
    if (stat(databasePath.c_str(), &fileStat) != 0) {
        LOG_ERROR("File state error. path: %{public}s, errno: %{public}d",
            SqliteUtils::Anonymous(databasePath).c_str(), errno);
        return std::make_pair("", E_INVALID_FILE_PATH);
    }
    return std::make_pair(databasePath, E_OK);
}

/**
 * @brief get custom data base path.
 */
std::pair<std::string, int> RdbSqlUtils::GetDefaultDatabasePath(
    const std::string &baseDir, const std::string &name, const std::string &customDir)
{
    int errorCode = E_OK;
    if (customDir.empty()) {
        return std::make_pair(GetDefaultDatabasePath(baseDir, name, errorCode), errorCode);
    }

    std::string databaseDir;
    databaseDir.append(baseDir).append("/rdb/").append(customDir);

    errorCode = CreateDirectory(databaseDir);
    if (errorCode != E_OK) {
        LOG_ERROR("failed errno[%{public}d] baseDir : %{public}s name : %{public}s customDir : %{public}s", errno,
            SqliteUtils::Anonymous(baseDir).c_str(), SqliteUtils::Anonymous(name).c_str(),
            SqliteUtils::Anonymous(customDir).c_str());
    }
    return std::make_pair(databaseDir.append("/").append(name), errorCode);
}

/**
 * Get and Check default path.
 */
std::string RdbSqlUtils::GetDefaultDatabasePath(const std::string &baseDir, const std::string &name, int &errorCode)
{
    std::string databaseDir = baseDir + "/rdb";
    errorCode = CreateDirectory(databaseDir);
    if (errorCode != E_OK) {
        LOG_ERROR("failed errno[%{public}d] baseDir : %{public}s name : %{public}s", errno,
            SqliteUtils::Anonymous(baseDir).c_str(), SqliteUtils::Anonymous(name).c_str());
    }
    return databaseDir.append("/").append(name);
}

std::string RdbSqlUtils::BuildQueryString(const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    return SqliteSqlBuilder::BuildQueryString(predicates, columns);
}
} // namespace NativeRdb
} // namespace OHOS