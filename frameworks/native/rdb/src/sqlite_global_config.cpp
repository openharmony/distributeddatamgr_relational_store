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
#define LOG_TAG "SqliteGlobalConfig"
#include "sqlite_global_config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <chrono>
#include <cerrno>
#include <cinttypes>
#include "logger.h"
#include "sqlite3sym.h"
#include "sqlite_utils.h"
#include "rdb_errno.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
void SqliteGlobalConfig::InitSqliteGlobalConfig()
{
    static SqliteGlobalConfig globalConfig;
}

SqliteGlobalConfig::SqliteGlobalConfig()
{
    umask(GlobalExpr::APP_DEFAULT_UMASK);

    sqlite3_config(SQLITE_CONFIG_MULTITHREAD);

    sqlite3_config(SQLITE_CONFIG_LOG, &SqliteLogCallback,
        GlobalExpr::CALLBACK_LOG_SWITCH ? reinterpret_cast<void *>(1) : NULL);

    sqlite3_soft_heap_limit(GlobalExpr::SOFT_HEAP_LIMIT);

    sqlite3_initialize();
}

SqliteGlobalConfig::~SqliteGlobalConfig()
{
}

void SqliteGlobalConfig::SqliteLogCallback(const void *data, int err, const char *msg)
{
    bool verboseLog = (data != nullptr);
    auto errType = static_cast<unsigned int>(err);
    errType &= 0xFF;
    if (errType == 0 || errType == SQLITE_CONSTRAINT || errType == SQLITE_SCHEMA || errType == SQLITE_NOTICE
        || err == SQLITE_WARNING_AUTOINDEX) {
        if (verboseLog) {
            LOG_INFO("SQLite Error(%{public}d) %{public}s ", err, msg);
        }
    } else if (errType == SQLITE_WARNING) {
        LOG_WARN("SQLite WARNING(%{public}d) %{public}s ", err, SqliteUtils::Anonymous(msg).c_str());
    } else {
        LOG_ERROR("SQLite Error(%{public}d) errno is:%{public}d %{public}s" PRIu64 ".", err, errno, msg);
    }
}

std::string SqliteGlobalConfig::GetMemoryDbPath()
{
    return GlobalExpr::MEMORY_DB_PATH;
}

int SqliteGlobalConfig::GetPageSize()
{
    return GlobalExpr::DB_PAGE_SIZE;
}

std::string SqliteGlobalConfig::GetSyncMode()
{
    return GlobalExpr::DEFAULE_SYNC_MODE;
}

int SqliteGlobalConfig::GetJournalFileSize()
{
    return GlobalExpr::DB_JOURNAL_SIZE;
}

int SqliteGlobalConfig::GetWalAutoCheckpoint()
{
    return GlobalExpr::WAL_AUTO_CHECKPOINT;
}

std::string SqliteGlobalConfig::GetDefaultJournalMode()
{
    return GlobalExpr::JOURNAL_MODE_WAL;
}

int SqliteGlobalConfig::GetDbPath(const RdbStoreConfig &config, std::string &dbPath)
{
    std::string path;
    if (config.GetRoleType() == VISITOR) {
        path = config.GetVisitorDir();
    } else {
        path = config.GetPath();
    }

    if (config.GetStorageMode() == StorageMode::MODE_MEMORY) {
        if (config.GetRoleType() == VISITOR) {
            LOG_ERROR("not support MODE_MEMORY, storeName:%{public}s, role:%{public}d", config.GetName().c_str(),
                config.GetRoleType());
            return E_NOT_SUPPORT;
        }
        dbPath = SqliteGlobalConfig::GetMemoryDbPath();
    } else if (path.empty() || (path.front() != '/' && path.at(1) != ':')) {
        LOG_ERROR("SqliteConnection GetDbPath input empty database path");
        return E_INVALID_FILE_PATH;
    } else {
        dbPath = path;
    }
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
