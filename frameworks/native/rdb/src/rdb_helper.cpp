/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define LOG_TAG "RdbHelper"
#include "rdb_helper.h"

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "rdb_security_manager.h"
#include "rdb_store_manager.h"
#include "rdb_trace.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
#include "unistd.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "security_policy.h"
#endif
#include "rdb_fault_hiview_reporter.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Reportor = RdbFaultHiViewReporter;

std::shared_ptr<RdbStore> RdbHelper::GetRdbStore(
    const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    SqliteGlobalConfig::InitSqliteGlobalConfig();
    auto rdb = RdbStoreManager::GetInstance().GetRdbStore(config, errCode, version, openCallback);
    if (errCode != E_OK) {
        Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, errCode, config,
            SqliteUtils::FormatDebugInfoBrief(Connection::Collect(config), SqliteUtils::Anonymous(config.GetName())),
            true));
    }

    return rdb;
}

void RdbHelper::ClearCache()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    RdbStoreManager::GetInstance().Clear();
}

bool RdbHelper::Init()
{
    // dlopen so that cannot be dlclose
    return true;
}

bool RdbHelper::Destroy(int32_t flag)
{
    LOG_INFO("Destroy resource start, flag %{public}d", flag);
    return RdbStoreManager::GetInstance().Destroy();
}

int RdbHelper::DeleteRdbStore(const std::string &dbFileName, bool shouldClose)
{
    RdbStoreConfig config(dbFileName);
    config.SetDBType(DB_SQLITE);
    int errCode = DeleteRdbStore(config, shouldClose);

    config.SetStorageMode(StorageMode::MODE_MEMORY);
    errCode = DeleteRdbStore(config, shouldClose) == E_OK ? errCode : E_REMOVE_FILE;

    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    errCode = DeleteRdbStore(config, shouldClose) == E_OK ? errCode : E_REMOVE_FILE;
    return errCode;
}

int RdbHelper::DeleteRdbStore(const RdbStoreConfig &config, bool shouldClose)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string dbFile;
    auto errCode = SqliteGlobalConfig::GetDbPath(config, dbFile);
    if (errCode != E_OK || dbFile.empty()) {
        return E_INVALID_FILE_PATH;
    }
    if (config.IsMemoryRdb()) {
        RdbStoreManager::GetInstance().Remove(dbFile, shouldClose);
        LOG_INFO("Remove memory store, dbType:%{public}d, path %{public}s", config.GetDBType(),
            SqliteUtils::Anonymous(dbFile).c_str());
        return E_OK;
    }
    if (access(dbFile.c_str(), F_OK) == 0) {
        RdbStoreManager::GetInstance().Delete(config, shouldClose);
    }
    Reportor::ReportRestore(Reportor::Create(config, E_OK, "RestoreType:Delete", false));
    Connection::Delete(config);
    RdbSecurityManager::GetInstance().DelAllKeyFiles(dbFile);
    LOG_INFO("Delete rdb store, dbType:%{public}d, path %{public}s", config.GetDBType(),
        SqliteUtils::Anonymous(dbFile).c_str());
    return E_OK;
}

bool RdbHelper::IsSupportArkDataDb()
{
#ifdef ARKDATA_DB_CORE_IS_EXISTS
    return true;
#else
    return false;
#endif
}

bool RdbHelper::IsSupportedTokenizer(Tokenizer tokenizer)
{
    if (tokenizer >= TOKENIZER_END) {
        return false;
    }
    if (tokenizer == CUSTOM_TOKENIZER) {
#if !defined(CROSS_PLATFORM) && defined(ARKDATA_DATABASE_CORE_ENABLE)
        return true;
#else
        LOG_WARN("CUSTOM_TOKENIZER not support this platform.");
        return false;
#endif
    }
    return true;
}
} // namespace NativeRdb
} // namespace OHOS
