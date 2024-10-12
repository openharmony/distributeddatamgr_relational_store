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

#include <sstream>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_security_manager.h"
#include "string_utils.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;

RdbStoreConfig::RdbStoreConfig(const std::string &name, StorageMode storageMode, bool isReadOnly,
    const std::vector<uint8_t> &encryptKey, const std::string &journalMode, const std::string &syncMode,
    const std::string &databaseFileType, SecurityLevel securityLevel, bool isCreateNecessary, bool autoCheck,
    int journalSize, int pageSize)
    : readOnly_(isReadOnly), isCreateNecessary_(isCreateNecessary), autoCheck_(autoCheck), journalSize_(journalSize),
      pageSize_(pageSize), securityLevel_(securityLevel), storageMode_(storageMode), path_(name),
      journalMode_(journalMode), syncMode_(syncMode), databaseFileType(databaseFileType)
{
    name_ = StringUtils::ExtractFileName(name);
    cryptoParam_.encryptKey_ = encryptKey;
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
    return name_;
}

/**
 * Obtains the database path.
 */
std::string RdbStoreConfig::GetPath() const
{
    return path_;
}

/**
 * Obtains the storage mode.
 */
StorageMode RdbStoreConfig::GetStorageMode() const
{
    return storageMode_;
}

/**
 * Obtains the journal mode in this {@code StoreConfig} object.
 */
std::string RdbStoreConfig::GetJournalMode() const
{
    return journalMode_;
}

/**
 * Obtains the synchronization mode in this {@code StoreConfig} object.
 */
std::string RdbStoreConfig::GetSyncMode() const
{
    return syncMode_;
}

/**
 * Checks whether the database is read-only.
 */
bool RdbStoreConfig::IsReadOnly() const
{
    return readOnly_;
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
    this->name_ = std::move(name);
}

/**
 * Sets the journal mode  for the object.
 */
void RdbStoreConfig::SetJournalMode(JournalMode journalMode)
{
    this->journalMode_ = GetJournalModeValue(journalMode);
}

void RdbStoreConfig::SetJournalMode(const std::string &journalMode)
{
    this->journalMode_ = journalMode;
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
    this->path_ = std::move(path);
}

void RdbStoreConfig::SetStorageMode(StorageMode storageMode)
{
    this->storageMode_ = storageMode;
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
    return journalSize_;
}
void RdbStoreConfig::SetJournalSize(int journalSize)
{
    this->journalSize_ = journalSize;
}
int RdbStoreConfig::GetPageSize() const
{
    return pageSize_;
}
void RdbStoreConfig::SetPageSize(int pageSize)
{
    this->pageSize_ = pageSize;
}
EncryptAlgo RdbStoreConfig::GetEncryptAlgo() const
{
    return static_cast<EncryptAlgo>(cryptoParam_.encryptAlgo);
}
void RdbStoreConfig::SetEncryptAlgo(EncryptAlgo encryptAlgo)
{
    this->cryptoParam_.encryptAlgo = static_cast<int32_t>(encryptAlgo);
}

void RdbStoreConfig::SetReadOnly(bool readOnly)
{
    this->readOnly_ = readOnly;
}

int RdbStoreConfig::SetDistributedType(DistributedType type)
{
    if (type != DistributedType::RDB_DEVICE_COLLABORATION) {
        LOG_ERROR("type is invalid.");
        return E_ERROR;
    }
    distributedType_ = type;
    return E_OK;
}

DistributedType RdbStoreConfig::GetDistributedType() const
{
    return distributedType_;
}

int RdbStoreConfig::SetBundleName(const std::string &bundleName)
{
    if (bundleName.empty()) {
        LOG_ERROR("bundleName is empty.");
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
    securityLevel_ = sl;
}

SecurityLevel RdbStoreConfig::GetSecurityLevel() const
{
    return securityLevel_;
}

void RdbStoreConfig::SetEncryptStatus(const bool status)
{
    this->isEncrypt_ = status;
}

bool RdbStoreConfig::IsEncrypt() const
{
    return isEncrypt_ || !cryptoParam_.encryptKey_.empty();
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
    cryptoParam_.encryptKey_.assign(cryptoParam_.encryptKey_.size(), 0);
    cryptoParam_.encryptKey_ = encryptKey;
}

void RdbStoreConfig::RestoreEncryptKey(const std::vector<uint8_t> &encryptKey) const
{
    RdbSecurityManager::GetInstance().RestoreKeyFile(GetPath(), encryptKey);
    cryptoParam_.encryptKey_.assign(cryptoParam_.encryptKey_.size(), 0);
    newEncryptKey_.assign(newEncryptKey_.size(), 0);
    cryptoParam_.encryptKey_ = encryptKey;
}

void RdbStoreConfig::SetNewEncryptKey(const std::vector<uint8_t> newEncryptKey)
{
    newEncryptKey_ = newEncryptKey;
}

std::vector<uint8_t> RdbStoreConfig::GetEncryptKey() const
{
    return cryptoParam_.encryptKey_;
}

void RdbStoreConfig::ChangeEncryptKey() const
{
    RdbSecurityManager::GetInstance().ChangeKeyFile(GetPath());
    if (newEncryptKey_.empty()) {
        return;
    }
    cryptoParam_.encryptKey_.assign(cryptoParam_.encryptKey_.size(), 0);
    cryptoParam_.encryptKey_.assign(newEncryptKey_.data(), newEncryptKey_.data() + newEncryptKey_.size());
    newEncryptKey_.assign(newEncryptKey_.size(), 0);
    newEncryptKey_.resize(0);
}

std::vector<uint8_t> RdbStoreConfig::GetNewEncryptKey() const
{
    return newEncryptKey_;
}

int32_t RdbStoreConfig::Initialize() const
{
    return GenerateEncryptedKey();
}

int32_t RdbStoreConfig::GenerateEncryptedKey() const
{
    if (!isEncrypt_ || !cryptoParam_.encryptKey_.empty()) {
        return E_OK;
    }

    auto name = bundleName_;
    if (name.empty()) {
        name = std::string(path_).substr(0, path_.rfind("/") + 1);
    }
    using KeyFileType = RdbSecurityManager::KeyFileType;
    auto errCode = RdbSecurityManager::GetInstance().Init(name);
    if (errCode != E_OK) {
        LOG_ERROR("generate root encrypt key failed, bundleName_:%{public}s", bundleName_.c_str());
        return errCode;
    }
    auto rdbPwd = RdbSecurityManager::GetInstance().GetRdbPassword(path_, KeyFileType::PUB_KEY_FILE);
    if (rdbPwd.IsValid()) {
        cryptoParam_.encryptKey_ = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
    }
    rdbPwd.Clear();
    if ((rdbPwd.isKeyExpired && autoRekey_) ||
        RdbSecurityManager::GetInstance().IsKeyFileExists(path_, KeyFileType::PUB_KEY_FILE_NEW_KEY)) {
        auto rdbNewPwd = RdbSecurityManager::GetInstance().GetRdbPassword(path_, KeyFileType::PUB_KEY_FILE_NEW_KEY);
        if (rdbNewPwd.IsValid()) {
            newEncryptKey_ = std::vector<uint8_t>(rdbNewPwd.GetData(), rdbNewPwd.GetData() + rdbNewPwd.GetSize());
        }
        rdbPwd.Clear();
    }
    if (cryptoParam_.encryptKey_.empty() && newEncryptKey_.empty()) {
        LOG_WARN("key is inValid, bundleName_:%{public}s", bundleName_.c_str());
    }
    return E_OK;
}

void RdbStoreConfig::ClearEncryptKey()
{
    cryptoParam_.encryptKey_.assign(cryptoParam_.encryptKey_.size(), 0);
    newEncryptKey_.assign(newEncryptKey_.size(), 0);
}

void RdbStoreConfig::SetScalarFunction(const std::string &functionName, int argc, ScalarFunction function)
{
    customScalarFunctions.try_emplace(functionName, ScalarFunctionInfo(function, argc));
}

void RdbStoreConfig::SetScalarFunctions(const std::map<std::string, ScalarFunctionInfo> functions)
{
    customScalarFunctions = functions;
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
    isVector ? SetDBType(DB_VECTOR) : SetDBType(DB_SQLITE);
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

void RdbStoreConfig::SetIntegrityCheck(IntegrityCheck checkType)
{
    checkType_ = checkType;
}

IntegrityCheck RdbStoreConfig::GetIntegrityCheck() const
{
    return checkType_;
}

int32_t RdbStoreConfig::GetIter() const
{
    return cryptoParam_.iterNum;
}
 
void RdbStoreConfig::SetIter(int32_t iter) const
{
    cryptoParam_.iterNum = iter;
}

void RdbStoreConfig::SetPluginLibs(const std::vector<std::string> &pluginLibs)
{
    pluginLibs_ = pluginLibs;
}

std::vector<std::string> RdbStoreConfig::GetPluginLibs() const
{
    return pluginLibs_;
}

int32_t RdbStoreConfig::GetHaMode() const
{
    return haMode_;
}

void RdbStoreConfig::SetHaMode(int32_t haMode)
{
    haMode_ = haMode;
}

void RdbStoreConfig::EnableRekey(bool enable)
{
    autoRekey_ = enable;
}

void RdbStoreConfig::SetCryptoParam(RdbStoreConfig::CryptoParam cryptoParam)
{
    cryptoParam_ = cryptoParam;
}

RdbStoreConfig::CryptoParam RdbStoreConfig::GetCryptoParam() const
{
    return cryptoParam_;
}

RdbStoreConfig::CryptoParam::CryptoParam() = default;

RdbStoreConfig::CryptoParam::~CryptoParam()
{
    encryptKey_.assign(encryptKey_.size(), 0);
}

bool RdbStoreConfig::CryptoParam::IsValid() const
{
    int32_t count = iterNum;
    if (count < 0) {
        return false;
    }

    if (encryptAlgo != AES_256_CBC && encryptAlgo != AES_256_GCM) {
        return false;
    }

    if (hmacAlgo < SHA1 || hmacAlgo > SHA512) {
        return false;
    }

    if (kdfAlgo < KDF_SHA1 || kdfAlgo > KDF_SHA512) {
        return false;
    }

    return (cryptoPageSize != 0) && ((cryptoPageSize & DB_INVALID_CRYPTO_PAGE_SIZE_MASK) == 0) &&
           (cryptoPageSize & (cryptoPageSize - 1)) == 0;
}

std::string RdbStoreConfig::Format(const RdbStoreConfig &cacheConfig, const RdbStoreConfig &incomingConfig)
{
    std::stringstream oss;
    oss << " isEncrypt:" << static_cast<int32_t>(cacheConfig.IsEncrypt()) << "->"
        << static_cast<int32_t>(incomingConfig.IsEncrypt()) << ",";
    oss << " securityLevel:" << static_cast<int32_t>(cacheConfig.securityLevel_) << "->"
        << static_cast<int32_t>(incomingConfig.securityLevel_) << ",";
    oss << " area:" << cacheConfig.area_ << "->" << incomingConfig.area_ << ",";
    oss << " storageMode:" << static_cast<int32_t>(cacheConfig.storageMode_) << "->"
        << static_cast<int32_t>(incomingConfig.storageMode_) << ",";
    oss << " journalMode:" << cacheConfig.journalMode_ << "->" << incomingConfig.journalMode_ << ",";
    oss << " syncMode:" << cacheConfig.syncMode_ << "->" << incomingConfig.syncMode_ << ",";
    oss << " databaseFileType:" << cacheConfig.databaseFileType << "->" << incomingConfig.databaseFileType << ",";
    oss << " journalSize:" << cacheConfig.journalSize_ << "->" << incomingConfig.journalSize_ << ",";
    oss << " pageSize:" << cacheConfig.pageSize_ << "->" << incomingConfig.pageSize_ << ",";
    oss << " customDir:" << cacheConfig.customDir_ << "->" << incomingConfig.customDir_ << ",";
    oss << " haMode:" << cacheConfig.haMode_ << "->" << incomingConfig.haMode_ << ",";
    oss << " dbType:" << cacheConfig.dbType_ << "->" << incomingConfig.dbType_ << ",";

    return oss.str();
}
} // namespace OHOS::NativeRdb
