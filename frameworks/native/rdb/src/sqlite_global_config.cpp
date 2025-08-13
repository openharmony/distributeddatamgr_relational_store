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
#define LOG_TAG "Config"
#include "sqlite_global_config.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstring>
#include <mutex>
#include <regex>

#include "logger.h"
#include "rdb_errno.h"
#include "sqlite3sym.h"
#include "sqlite_utils.h"
#include "rdb_fault_hiview_reporter.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;

static std::string g_lastCorruptionMsg;
static std::mutex g_corruptionMutex;

void SqliteGlobalConfig::InitSqliteGlobalConfig()
{
    static SqliteGlobalConfig globalConfig;
}

SqliteGlobalConfig::SqliteGlobalConfig()
{
    umask(GlobalExpr::APP_DEFAULT_UMASK);

    sqlite3_config(SQLITE_CONFIG_MULTITHREAD);

    sqlite3_config(SQLITE_CONFIG_LOG, &Log, GlobalExpr::CALLBACK_LOG_SWITCH ? reinterpret_cast<void *>(1) : NULL);

    sqlite3_config(SQLITE_CONFIG_CORRUPTION, &Corruption, nullptr);

    sqlite3_soft_heap_limit(GlobalExpr::SOFT_HEAP_LIMIT);

    sqlite3_initialize();

    sqlite3_register_cksumvfs(0);
}

SqliteGlobalConfig::~SqliteGlobalConfig()
{
    sqlite3_unregister_cksumvfs();
    sqlite3_config(SQLITE_CONFIG_CORRUPTION, nullptr, nullptr);
    sqlite3_config(SQLITE_CONFIG_LOG, nullptr, nullptr);
    LOG_INFO("Destruct.");
}

void SqliteGlobalConfig::Corruption(void *arg, const void *msg)
{
    std::lock_guard<std::mutex> lockGuard(g_corruptionMutex);
    g_lastCorruptionMsg = (const char *)msg;
}

void SqliteGlobalConfig::Log(const void *data, int err, const char *msg)
{
    bool verboseLog = (data != nullptr);
    auto errType = static_cast<unsigned int>(err);
    errType &= 0xFF;
    if (errType == SQLITE_ERROR && strstr(msg, "\"?\": syntax error in \"PRAGMA user_ve") != nullptr) {
        return;
    }
    if (errType == 0 || errType == SQLITE_CONSTRAINT || errType == SQLITE_SCHEMA || errType == SQLITE_NOTICE ||
        err == SQLITE_WARNING_AUTOINDEX) {
        if (verboseLog) {
            LOG_INFO("Error(%{public}d) %{public}s ", err, SqliteUtils::SqlAnonymous(msg).c_str());
        }
    } else if (errType == SQLITE_WARNING) {
        LOG_WARN("WARNING(%{public}d) %{public}s ", err, SqliteUtils::SqlAnonymous(msg).c_str());
    } else {
        LOG_ERROR("Error(%{public}d) errno is:%{public}d %{public}s.", err, errno,
            SqliteUtils::SqlAnonymous(msg).c_str());
        SqliteErrReport(err, msg);
    }
}

void SqliteGlobalConfig::SqliteErrReport(int err, const char *msg)
{
    auto lowErr = static_cast<uint32_t>(err) & 0xFF;
    if (lowErr == SQLITE_NOMEM || lowErr == SQLITE_INTERRUPT || lowErr == SQLITE_FULL || lowErr == SQLITE_SCHEMA ||
        lowErr == SQLITE_NOLFS || lowErr == SQLITE_AUTH || lowErr == SQLITE_BUSY || lowErr == SQLITE_LOCKED ||
        lowErr == SQLITE_IOERR || lowErr == SQLITE_CANTOPEN) {
        std::string log(msg == nullptr ? "" : SqliteUtils::Anonymous(msg).c_str());
        log.append(",errcode=").append(std::to_string(err)).append(",errno=").append(std::to_string(errno));
        RdbFaultHiViewReporter::ReportFault(RdbFaultEvent(FT_SQLITE, E_DFX_SQLITE_LOG, BUNDLE_NAME_COMMON, log));
    }
}

std::string SqliteGlobalConfig::GetMemoryDbPath()
{
    return GlobalExpr::MEMORY_DB_PATH;
}

std::string SqliteGlobalConfig::GetSharedMemoryDbPath(const std::string &name)
{
    static const std::regex pattern(R"(^[\w\-\.]+$)");
    if (!name.empty() && !std::regex_match(name, pattern)) {
        return "";
    }
    return GlobalExpr::SHARED_MEMORY_DB_PATH_PREFIX + name + GlobalExpr::SHARED_MEMORY_DB_PATH_SUFFIX;
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
    if (config.GetStorageMode() == StorageMode::MODE_MEMORY) {
        if (config.GetRoleType() != OWNER) {
            LOG_ERROR("not support MODE_MEMORY, storeName:%{public}s, role:%{public}d",
                SqliteUtils::Anonymous(config.GetName()).c_str(), config.GetRoleType());
            return E_NOT_SUPPORT;
        }
        dbPath = SqliteGlobalConfig::GetSharedMemoryDbPath(config.GetName());
        return dbPath.empty() ? E_INVALID_FILE_PATH : E_OK;
    }
    std::string path;
    if (config.GetRoleType() == OWNER) {
        path = config.GetPath();
    } else if (config.GetRoleType() == VISITOR || config.GetRoleType() == VISITOR_WRITE) {
        path = config.GetVisitorDir();
    } else {
        LOG_ERROR("not support Role, storeName:%{public}s, role:%{public}d",
            SqliteUtils::Anonymous(config.GetName()).c_str(), config.GetRoleType());
        return E_NOT_SUPPORT;
    }
    if (path.empty() || path.front() != '/') {
        LOG_ERROR("invalid path, bundleName:%{public}s, role:%{public}d, %{public}s",
            config.GetBundleName().c_str(), config.GetRoleType(), SqliteUtils::Anonymous(path).c_str());
        return E_INVALID_FILE_PATH;
    }
    dbPath = std::move(path);
    return E_OK;
}

std::string SqliteGlobalConfig::GetLastCorruptionMsg()
{
    std::lock_guard<std::mutex> lockGuard(g_corruptionMutex);
    std::string msg = g_lastCorruptionMsg;
    g_lastCorruptionMsg = "";
    return msg;
}
} // namespace NativeRdb
} // namespace OHOS
