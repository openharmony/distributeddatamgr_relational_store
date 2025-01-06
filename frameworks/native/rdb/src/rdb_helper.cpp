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

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Reportor = RdbFaultHiViewReporter;

std::shared_ptr<RdbStore> RdbHelper::GetRdbStore(
    const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    SqliteGlobalConfig::InitSqliteGlobalConfig();
    return RdbStoreManager::GetInstance().GetRdbStore(config, errCode, version, openCallback);
}

void RdbHelper::ClearCache()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    RdbStoreManager::GetInstance().Clear();
}

static std::vector<std::string> rdPostFixes = {
    "",
    ".redo",
    ".undo",
    ".ctrl",
    ".ctrl.dwr",
    ".safe",
    ".map",
};

int DeleteRdFiles(const std::string &dbFileName)
{
    int errCode = E_OK;
    for (std::string &postFix : rdPostFixes) {
        std::string shmFileName = dbFileName + postFix;
        if (access(shmFileName.c_str(), F_OK) == 0) {
            int result = remove(shmFileName.c_str());
            if (result < 0) {
                LOG_ERROR("RdbHelper DeleteRdbStore failed to delete the shm file err = %{public}d", errno);
                errCode = E_REMOVE_FILE;
            }
        }
    }
    return errCode;
}

int RdbHelper::DeleteRdbStore(const std::string &dbFileName)
{
    RdbStoreConfig config(dbFileName);
    config.SetDBType(DB_SQLITE);
    int errCodeSqlite = DeleteRdbStore(config);

    config.SetDBType(DB_VECTOR);
    int errCodeVector = DeleteRdbStore(config);
    return (errCodeSqlite == E_OK && errCodeVector == E_OK) ? E_OK : E_REMOVE_FILE;
}

int RdbHelper::DeleteRdbStore(const RdbStoreConfig &config)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto dbFile = config.GetPath();
    if (dbFile.empty()) {
        return E_INVALID_FILE_PATH;
    }
    if (access(dbFile.c_str(), F_OK) == 0) {
        RdbStoreManager::GetInstance().Delete(dbFile);
    }
    Connection::Delete(config);

    RdbSecurityManager::GetInstance().DelAllKeyFiles(dbFile);

    Reportor::ReportRestore(Reportor::Create(config, E_OK, "RestoreType:Restore"));
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
} // namespace NativeRdb
} // namespace OHOS
