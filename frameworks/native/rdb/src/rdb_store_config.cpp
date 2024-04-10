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
#define LOG_TAG "RdbStoreConfig"
#include "rdb_store_config.h"

#include "logger.h"
#include "rdb_errno.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;

RdbStoreConfig::RdbStoreConfig(const std::string &name, StorageMode storageMode, bool isReadOnly,
    const std::vector<uint8_t> &encryptKey, const std::string &journalMode, const std::string &syncMode,
    const std::string &databaseFileType, SecurityLevel securityLevel, bool isCreateNecessary, bool autoCheck,
    int journalSize, int pageSize, const std::string &encryptAlgo)
    : readOnly(isReadOnly),
      isCreateNecessary_(isCreateNecessary),
      autoCheck_(autoCheck),
      journalSize(journalSize),
      pageSize(pageSize),
      securityLevel(securityLevel),
      storageMode(storageMode),
      name(name),
      path(name),
      journalMode(journalMode),
      syncMode(syncMode),
      databaseFileType(databaseFileType),
      encryptAlgo(encryptAlgo),
      encryptKey_(encryptKey)
{
}

RdbStoreConfig::~RdbStoreConfig()
{
    ClearEncryptKey();
}

/**
 * Obtains the database name.
 */
std::string RdbStoreConfig::GetName() const
{
    return name;
}

/**
 * Obtains the database path.
 */
std::string RdbStoreConfig::GetPath() const
{
    return path;
}

/**
 * Obtains the storage mode.
 */
StorageMode RdbStoreConfig::GetStorageMode() const
{
    return storageMode;
}

/**
 * Obtains the journal mode in this {@code StoreConfig} object.
 */
std::string RdbStoreConfig::GetJournalMode() const
{
    return journalMode;
}

/**
 * Obtains the synchronization mode in this {@code StoreConfig} object.
 */
std::string RdbStoreConfig::GetSyncMode() const
{
    return syncMode;
}

/**
 * Checks whether the database is read-only.
 */
bool RdbStoreConfig::IsReadOnly() const
{
    return readOnly;
}

/**
 * Checks whether the database is memory.
 */
bool RdbStoreConfig::IsMemoryRdb() const
{
    return GetStorageMode() == StorageMode::MODE_MEMORY;
}

/**
 * Obtains the database file type in this {@code StoreConfig} object.
 */
std::string RdbStoreConfig::GetDatabaseFileType() const
{
    return databaseFileType;
}

void RdbStoreConfig::SetName(std::string name)
{
    this->name = std::move(name);
}

/**
 * Sets the journal mode  for the object.
 */
void RdbStoreConfig::SetJournalMode(JournalMode journalMode)
{
    this->journalMode = GetJournalModeValue(journalMode);
}

void RdbStoreConfig::SetDatabaseFileType(DatabaseFileType type)
{
    this->databaseFileType = GetDatabaseFileTypeValue(type);
}

/**
 * Sets the path  for the object.
 */
void RdbStoreConfig::SetPath(std::string path)
{
    this->path = std::move(path);
}

void RdbStoreConfig::SetStorageMode(StorageMode storageMode)
{
    this->storageMode = storageMode;
}

bool RdbStoreConfig::IsAutoCheck() const
{
    return autoCheck_;
}
void RdbStoreConfig::SetAutoCheck(bool autoCheck)
{
    this->autoCheck_ = autoCheck;
}
int RdbStoreConfig::GetJournalSize() const
{
    return journalSize;
}
void RdbStoreConfig::SetJournalSize(int journalSize)
{
    this->journalSize = journalSize;
}
int RdbStoreConfig::GetPageSize() const
{
    return pageSize;
}
void RdbStoreConfig::SetPageSize(int pageSize)
{
    this->pageSize = pageSize;
}
const std::string RdbStoreConfig::GetEncryptAlgo() const
{
    return encryptAlgo;
}
void RdbStoreConfig::SetEncryptAlgo(const std::string &encryptAlgo)
{
    this->encryptAlgo = encryptAlgo;
}

void RdbStoreConfig::SetReadOnly(bool readOnly)
{
    this->readOnly = readOnly;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
int RdbStoreConfig::SetDistributedType(DistributedType type)
{
    if (type != DistributedType::RDB_DEVICE_COLLABORATION) {
        LOG_ERROR("type is invalid");
        return E_ERROR;
    }
    distributedType_ = type;
    return E_OK;
}

DistributedType RdbStoreConfig::GetDistributedType() const
{
    return distributedType_;
}
#endif

int RdbStoreConfig::SetBundleName(const std::string &bundleName)
{
    if (bundleName.empty()) {
        LOG_ERROR("bundleName is empty");
        return E_ERROR;
    }
    bundleName_ = bundleName;
    return E_OK;
}

std::string RdbStoreConfig::GetBundleName() const
{
    return bundleName_;
}

void RdbStoreConfig::SetModuleName(const std::string &moduleName)
{
    moduleName_ = moduleName;
}

std::string RdbStoreConfig::GetModuleName() const
{
    return moduleName_;
}

void RdbStoreConfig::SetServiceName(const std::string &serviceName)
{
    SetBundleName(serviceName);
}

void RdbStoreConfig::SetArea(int32_t area)
{
    area_ = area + 1;
}

int32_t RdbStoreConfig::GetArea() const
{
    return area_;
}

std::string RdbStoreConfig::GetJournalModeValue(JournalMode journalMode)
{
    std::string value = "";

    switch (journalMode) {
        case JournalMode::MODE_DELETE:
            return "DELETE";
        case JournalMode::MODE_TRUNCATE:
            return "TRUNCATE";
        case JournalMode::MODE_PERSIST:
            return  "PERSIST";
        case JournalMode::MODE_MEMORY:
            return "MEMORY";
        case JournalMode::MODE_WAL:
            return "WAL";
        case JournalMode::MODE_OFF:
            return "OFF";
        default:
            break;
    }
    return value;
}

std::string RdbStoreConfig::GetSyncModeValue(SyncMode syncMode)
{
    std::string value = "";
    switch (syncMode) {
        case SyncMode::MODE_OFF:
            return "MODE_OFF";
        case SyncMode::MODE_NORMAL:
            return "MODE_NORMAL";
        case SyncMode::MODE_FULL:
            return "MODE_FULL";
        case SyncMode::MODE_EXTRA:
            return "MODE_EXTRA";
        default:
            break;
    }

    return value;
}

std::string RdbStoreConfig::GetDatabaseFileTypeValue(DatabaseFileType databaseFileType)
{
    std::string value = "";
    switch (databaseFileType) {
        case DatabaseFileType::NORMAL:
            return "db";
        case DatabaseFileType::BACKUP:
            return "backup";
        case DatabaseFileType::CORRUPT:
            return "corrupt";
        default:
            break;
    }

    return value;
}

void RdbStoreConfig::SetSecurityLevel(SecurityLevel sl)
{
    securityLevel = sl;
}

SecurityLevel RdbStoreConfig::GetSecurityLevel() const
{
    return securityLevel;
}

void RdbStoreConfig::SetEncryptStatus(const bool status)
{
    this->isEncrypt_ = status;
}

bool RdbStoreConfig::IsEncrypt() const
{
    return this->isEncrypt_;
}

bool RdbStoreConfig::IsCreateNecessary() const
{
    return isCreateNecessary_;
}

void RdbStoreConfig::SetCreateNecessary(bool isCreateNecessary)
{
    isCreateNecessary_ = isCreateNecessary;
}

int RdbStoreConfig::GetReadConSize() const
{
    return readConSize_;
}

void RdbStoreConfig::SetReadConSize(int readConSize)
{
    readConSize_= readConSize;
}

void RdbStoreConfig::SetEncryptKey(const std::vector<uint8_t> &encryptKey)
{
    encryptKey_ = encryptKey;
}

std::vector<uint8_t> RdbStoreConfig::GetEncryptKey() const
{
    return encryptKey_;
}

void RdbStoreConfig::ClearEncryptKey()
{
    encryptKey_.assign(encryptKey_.size(), 0);
}

void RdbStoreConfig::SetScalarFunction(const std::string &functionName, int argc, ScalarFunction function)
{
    customScalarFunctions.try_emplace(functionName, ScalarFunctionInfo(function, argc));
}

std::map<std::string, ScalarFunctionInfo> RdbStoreConfig::GetScalarFunctions() const
{
    return customScalarFunctions;
}

void RdbStoreConfig::SetDataGroupId(const std::string &DataGroupId)
{
    dataGroupId_ = DataGroupId;
}

std::string RdbStoreConfig::GetDataGroupId() const
{
    return dataGroupId_;
}

void RdbStoreConfig::SetAutoClean(bool isAutoClean)
{
    isAutoClean_ = isAutoClean;
}

bool RdbStoreConfig::GetAutoClean() const
{
    return isAutoClean_;
}

void RdbStoreConfig::SetIsVector(bool isVector)
{
    isVector_ = isVector;
}

bool RdbStoreConfig::IsVector() const
{
    return isVector_;
}

void RdbStoreConfig::SetCustomDir(const std::string &customDir)
{
    customDir_ = customDir;
}

std::string RdbStoreConfig::GetCustomDir() const
{
    return customDir_;
}

void RdbStoreConfig::SetVisitorDir(const std::string &visitorDir)
{
    visitorDir_ = visitorDir;
}

std::string RdbStoreConfig::GetVisitorDir() const
{
    return visitorDir_;
}

bool RdbStoreConfig::IsSearchable() const
{
    return isSearchable_;
}

void RdbStoreConfig::SetSearchable(bool isSearchable)
{
    isSearchable_ = isSearchable;
}

int RdbStoreConfig::GetWriteTime() const
{
    return writeTimeout_;
}

void RdbStoreConfig::SetWriteTime(int timeout)
{
    writeTimeout_ = std::max(MIN_TIMEOUT, std::min(MAX_TIMEOUT, timeout));
}

int RdbStoreConfig::GetReadTime() const
{
    return readTimeout_;
}

void RdbStoreConfig::SetReadTime(int timeout)
{
    readTimeout_ = std::max(MIN_TIMEOUT, std::min(MAX_TIMEOUT, timeout));
}

void RdbStoreConfig::SetRoleType(RoleType role)
{
    role_ = role;
}

uint32_t RdbStoreConfig::GetRoleType() const
{
    return role_;
}

void RdbStoreConfig::SetDBType(int32_t dbType)
{
    dbType_ = dbType;
}

int32_t RdbStoreConfig::GetDBType() const
{
    return dbType_;
}

void RdbStoreConfig::SetAllowRebuild(bool allowRebuild)
{
    this->allowRebuilt_ = allowRebuild;
}

bool RdbStoreConfig::GetAllowRebuild() const
{
    return allowRebuilt_;
}
} // namespace OHOS::NativeRdb
