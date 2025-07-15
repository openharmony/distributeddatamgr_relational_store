/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "RdConnection"
#include "rd_connection.h"

#include <securec.h>

#include <string>

#include "grd_api_manager.h"
#include "logger.h"
#include "rd_statement.h"
#include "rdb_errno.h"
#include "rdb_security_manager.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
__attribute__((used))
const int32_t RdConnection::regCreator_ = Connection::RegisterCreator(DB_VECTOR, RdConnection::Create);
__attribute__((used))
const int32_t RdConnection::regRepairer_ = Connection::RegisterRepairer(DB_VECTOR, RdConnection::Repair);
__attribute__((used))
const int32_t RdConnection::regDeleter_ = Connection::RegisterDeleter(DB_VECTOR, RdConnection::Delete);
constexpr int CONFIG_SIZE_EXCEPT_ENCRYPT = 167;  // When modifying config, this item needs to be modified

std::pair<int32_t, std::shared_ptr<Connection>> RdConnection::Create(const RdbStoreConfig &config, bool isWrite)
{
    std::pair<int32_t, std::shared_ptr<Connection>> result = { E_ERROR, nullptr };
    if (!IsUsingArkData() || config.GetStorageMode() == StorageMode::MODE_MEMORY) {
        result.first = E_NOT_SUPPORT;
        return result;
    }
    auto &[errCode, conn] = result;
    for (size_t i = 0; i < ITERS_COUNT; i++) {
        std::shared_ptr<RdConnection> connection = std::make_shared<RdConnection>(config, isWrite);
        if (connection == nullptr) {
            LOG_ERROR("SqliteConnection::Open new failed, connection is nullptr.");
            return result;
        }
        errCode = connection->InnerOpen(config);
        if (errCode == E_OK) {
            conn = connection;
            break;
        }
    }
    return result;
}

int32_t RdConnection::Repair(const RdbStoreConfig &config)
{
    std::string dbPath = "";
    auto errCode = SqliteGlobalConfig::GetDbPath(config, dbPath);
    if (errCode != E_OK) {
        LOG_ERROR("Can not get db path.");
        return errCode;
    }
    std::vector<uint8_t> key = config.GetEncryptKey();
    errCode = RdUtils::RdDbRepair(dbPath.c_str(), GetConfigStr(key, config.IsEncrypt()).c_str());
    key.assign(key.size(), 0);
    if (errCode != E_OK) {
        LOG_ERROR("Fail to repair db.");
    }
    return errCode;
}

static constexpr const char *RD_POST_FIXES[] = {
    "",
    ".redo",
    ".undo",
    ".ctrl",
    ".ctrl.dwr",
    ".safe",
    ".map",
    ".corruptedflg",
};

int32_t RdConnection::Delete(const RdbStoreConfig &config)
{
    auto path = config.GetPath();
    for (auto postFix : RD_POST_FIXES) {
        std::string shmFilePath = path + postFix;
        if (access(shmFilePath.c_str(), F_OK) == 0) {
            remove(shmFilePath.c_str());
        }
    }
    return E_OK;
}

RdConnection::RdConnection(const RdbStoreConfig &config, bool isWriter) : isWriter_(isWriter), config_(config)
{
}

RdConnection::~RdConnection()
{
    if (dbHandle_ != nullptr) {
        int errCode = RdUtils::RdDbClose(dbHandle_, 0);
        if (errCode != E_OK) {
            LOG_ERROR("~RdConnection ~RdConnection: could not close database err = %{public}d", errCode);
        }
        dbHandle_ = nullptr;
    }
}

std::string RdConnection::GetConfigStr(const std::vector<uint8_t> &keys, bool isEncrypt)
{
    std::string config = "{";
    if (isEncrypt) {
        const size_t keyBuffSize = keys.size() * 2 + 1; // 2 hex number can represent a uint8_t, 1 is for '/0'
        config.reserve(CONFIG_SIZE_EXCEPT_ENCRYPT + keyBuffSize);
        char keyBuff[keyBuffSize];
        config += "\"isEncrypted\":1,";
        config += "\"hexPassword\":\"";
        config += RdUtils::GetEncryptKey(keys, keyBuff, keyBuffSize);
        config += "\",";
        std::fill(keyBuff, keyBuff + keyBuffSize, 0);
    }
    config += RdConnection::GRD_OPEN_CONFIG_STR;
    config += "}";
    return config;
}

int RdConnection::InnerOpen(const RdbStoreConfig &config)
{
    std::string dbPath = "";
    auto errCode = SqliteGlobalConfig::GetDbPath(config, dbPath);
    if (errCode != E_OK) {
        LOG_ERROR("Can not get db path.");
        return errCode;
    }
    std::vector<uint8_t> newKey = config.GetNewEncryptKey();
    if (!newKey.empty()) {
        newKey.assign(newKey.size(), 0);
        errCode = ResetKey(config);
        if (errCode != E_OK) {
            LOG_ERROR("Can not reset key %{public}d.", errCode);
            return errCode;
        }
    }

    std::vector<uint8_t> key = config.GetEncryptKey();
    std::string configStr = GetConfigStr(key, config.IsEncrypt());
    errCode = RdUtils::RdDbOpen(dbPath.c_str(), configStr.c_str(),
        GRD_DB_OPEN_CREATE | GRD_DB_OPEN_IGNORE_DATA_CORRPUPTION, &dbHandle_);
    if (errCode == E_CHANGE_UNENCRYPTED_TO_ENCRYPTED) {
        errCode = RdUtils::RdDbRekey(dbPath.c_str(), GetConfigStr({}, false).c_str(), key);
        if (errCode != E_OK) {
            key.assign(key.size(), 0);
            RdUtils::ClearAndZeroString(configStr);
            LOG_ERROR("Can not rekey caylay db %{public}d.", errCode);
            return errCode;
        }
        errCode = RdUtils::RdDbOpen(dbPath.c_str(), configStr.c_str(),
            GRD_DB_OPEN_CREATE | GRD_DB_OPEN_IGNORE_DATA_CORRPUPTION, &dbHandle_);
    }
    key.assign(key.size(), 0);
    RdUtils::ClearAndZeroString(configStr);
    if (errCode != E_OK) {
        LOG_ERROR("Can not open rd db %{public}d.", errCode);
        return errCode;
    }
    errCode = RdUtils::RdSqlRegistryThreadPool(dbHandle_);
    if (errCode != E_OK) {
        LOG_ERROR("Can not registry ThreadPool rd db %{public}d.", errCode);
        return errCode;
    }
    return errCode;
}

int32_t RdConnection::VerifyAndRegisterHook(const RdbStoreConfig &config)
{
    return E_NOT_SUPPORT;
}

std::pair<int32_t, RdConnection::Stmt> RdConnection::CreateStatement(const std::string &sql, Connection::SConn conn)
{
    auto stmt = std::make_shared<RdStatement>();
    stmt->conn_ = conn;
    stmt->config_ = &config_;
    stmt->setPragmas_["user_version"] = ([this](const int &value) -> int32_t {
        return RdUtils::RdDbSetVersion(dbHandle_, GRD_CONFIG_USER_VERSION, value);
    });
    stmt->getPragmas_["user_version"] = ([this](int &version) -> int32_t {
        return RdUtils::RdDbGetVersion(dbHandle_, GRD_CONFIG_USER_VERSION, version);
    });
    int32_t ret = stmt->Prepare(dbHandle_, sql);
    if (ret != E_OK) {
        return { ret, nullptr };
    }
    return { ret, stmt };
}

std::pair<int32_t, RdConnection::Stmt> RdConnection::CreateReplicaStatement([[gnu::unused]] const std::string &sql,
    [[gnu::unused]] Connection::SConn conn)
{
    return { E_NOT_SUPPORT, nullptr };
}

int RdConnection::CheckReplicaForRestore()
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::GetDBType() const
{
    return DB_VECTOR;
}

bool RdConnection::IsWriter() const
{
    return isWriter_;
}

int32_t RdConnection::ResetKey(const RdbStoreConfig &config)
{
    if (!IsWriter()) {
        return E_OK;
    }
    std::string dbPath = "";
    int errCode = SqliteGlobalConfig::GetDbPath(config, dbPath);
    if (errCode != E_OK) {
        LOG_ERROR("Can not get db path.");
        return errCode;
    }
    std::vector<uint8_t> key = config.GetEncryptKey();
    std::vector<uint8_t> newKey = config.GetNewEncryptKey();
    std::string configStr = GetConfigStr(key, config.IsEncrypt());
    errCode = RdUtils::RdDbRekey(dbPath.c_str(), configStr.c_str(), newKey);
    RdUtils::ClearAndZeroString(configStr);
    key.assign(key.size(), 0);
    newKey.assign(newKey.size(), 0);
    if (errCode != E_OK) {
        LOG_ERROR("ReKey failed, err = %{public}d, errno = %{public}d", errCode, errno);
        RdbSecurityManager::GetInstance().DelKeyFile(
            config.GetPath(), RdbSecurityManager::KeyFileType::PUB_KEY_FILE_NEW_KEY);
        return E_OK;
    }
    config.ChangeEncryptKey();
    return E_OK;
}

int32_t RdConnection::TryCheckPoint(bool timeout)
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::LimitWalSize()
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::ConfigLocale(const std::string &localeStr)
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::CleanDirtyData(const std::string &table, uint64_t cursor)
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::Rekey(const RdbStoreConfig::CryptoParam &cryptoParam)
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::SubscribeTableChanges(const Connection::Notifier &notifier)
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::GetMaxVariable() const
{
    return MAX_VARIABLE_NUM;
}

int32_t RdConnection::GetJournalMode()
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::ClearCache()
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::Subscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer)
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::Unsubscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer)
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, bool isAsync,
    std::shared_ptr<SlaveStatus> slaveStatus, bool verifyDb)
{
    if (!destEncryptKey.empty() && !config_.IsEncrypt()) {
        return RdUtils::RdDbBackup(dbHandle_, databasePath.c_str(), destEncryptKey);
    }
    if (config_.IsEncrypt()) {
        std::vector<uint8_t> key = config_.GetEncryptKey();
        int32_t ret = RdUtils::RdDbBackup(dbHandle_, databasePath.c_str(), key);
        key.assign(key.size(), 0);
        return ret;
    }
    return RdUtils::RdDbBackup(dbHandle_, databasePath.c_str(), {});
}

int32_t RdConnection::Restore(
    const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
    std::shared_ptr<SlaveStatus> slaveStatus)
{
    auto ret = RdUtils::RdDbClose(dbHandle_, 0);
    if (ret != E_OK) {
        LOG_ERROR("Close db failed");
        return ret;
    }

    if (destEncryptKey.empty()) {
        std::vector<uint8_t> key = config_.GetEncryptKey();
        ret = RdUtils::RdDbRestore(config_.GetPath().c_str(), databasePath.c_str(), key);
        key.assign(key.size(), 0);
    } else {
        ret = RdUtils::RdDbRestore(config_.GetPath().c_str(), databasePath.c_str(), destEncryptKey);
    }

    if (ret != E_OK) {
        LOG_ERROR("Restore failed, original datapath:%{public}s, restorepath:%{public}s, errcode:%{public}d",
            SqliteUtils::Anonymous(config_.GetPath()).c_str(),
            SqliteUtils::Anonymous(databasePath).c_str(), ret);
        return ret;
    }

    ret = InnerOpen(config_);
    if (ret != E_OK) {
        LOG_ERROR("Reopen db failed:%{public}d", ret);
        return ret;
    }
    return ret;
}

ExchangeStrategy RdConnection::GenerateExchangeStrategy(std::shared_ptr<SlaveStatus> status)
{
    return ExchangeStrategy::NOT_HANDLE;
}

int RdConnection::SetKnowledgeSchema([[gnu::unused]] const DistributedRdb::RdbKnowledgeSchema &schema)
{
    return E_NOT_SUPPORT;
}

int RdConnection::CleanDirtyLog([[gnu::unused]] const std::string &table, [[gnu::unused]] uint64_t cursor)
{
    return E_NOT_SUPPORT;
}

int RdConnection::RegisterAlgo(const std::string &clstAlgoName, ClusterAlgoFunc func)
{
    int errCode =
        RdUtils::RdSqlRegistryClusterAlgo(dbHandle_, clstAlgoName.c_str(), reinterpret_cast<GRD_ClusterAlgoFunc>(func));
    if (errCode != E_OK) {
        LOG_ERROR("Can not registry cluster func in rd db %{public}d.", errCode);
        return errCode;
    }
    return E_OK;
}

} // namespace NativeRdb
} // namespace OHOS