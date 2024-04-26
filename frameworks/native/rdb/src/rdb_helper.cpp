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
#include "rdb_store_manager.h"
#include "rdb_trace.h"
#include "sqlite_global_config.h"
#include "unistd.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "rdb_security_manager.h"
#include "security_policy.h"
#endif

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

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

static void DeleteRdbKeyFiles(const std::string &dbFileName)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    RdbSecurityManager::GetInstance().DelRdbSecretDataFile(dbFileName);
#endif
}

static std::vector<std::string> rdPostFixes = {
    "",
    ".redo",
    ".undo",
    ".ctrl",
    ".safe",
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
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (dbFileName.empty()) {
        return E_INVALID_FILE_PATH;
    }
    if (access(dbFileName.c_str(), F_OK) != 0) {
        return E_OK; // not not exist
    }
    RdbStoreManager::GetInstance().Delete(dbFileName);
    int result = remove(dbFileName.c_str());
    if (result != 0) {
        LOG_ERROR("RdbHelper DeleteRdbStore failed to delete the db file err = %{public}d", errno);
        return E_REMOVE_FILE;
    }

    int errCode = DeleteRdFiles(dbFileName);
    std::string shmFileName = dbFileName + "-shm";
    if (access(shmFileName.c_str(), F_OK) == 0) {
        result = remove(shmFileName.c_str());
        if (result < 0) {
            LOG_ERROR("RdbHelper DeleteRdbStore failed to delete the shm file err = %{public}d", errno);
            errCode = E_REMOVE_FILE;
        }
    }

    std::string walFileName = dbFileName + "-wal";
    if (access(walFileName.c_str(), F_OK) == 0) {
        result = remove(walFileName.c_str());
        if (result < 0) {
            LOG_ERROR("RdbHelper DeleteRdbStore failed to delete the wal file err = %{public}d", errno);
            errCode = E_REMOVE_FILE;
        }
    }

    std::string journalFileName = dbFileName + "-journal";
    if (access(journalFileName.c_str(), F_OK) == 0) {
        result = remove(journalFileName.c_str());
        if (result < 0) {
            LOG_ERROR("RdbHelper DeleteRdbStore failed to delete the journal file err = %{public}d", errno);
            errCode = E_REMOVE_FILE;
        }
    }
    DeleteRdbKeyFiles(dbFileName);

    return errCode;
}
} // namespace NativeRdb
} // namespace OHOS
