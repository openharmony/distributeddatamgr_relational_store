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

#include "logger.h"
#include "rd_statement.h"
#include "rdb_errno.h"
#include "sqlite_global_config.h"
namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
__attribute__((used))
const int32_t RdConnection::reg_ = Connection::RegisterCreator(DB_VECTOR, RdConnection::Create);
std::pair<int32_t, std::shared_ptr<Connection>> RdConnection::Create(const RdbStoreConfig& config, bool isWrite)
{
    std::pair<int32_t, std::shared_ptr<Connection>> result;
    auto& [errCode, conn] = result;
    for (size_t i = 0; i < ITERS_COUNT; i++) {
        std::shared_ptr<RdConnection> connection = std::make_shared<RdConnection>(isWrite);
        if (connection == nullptr) {
            LOG_ERROR("SqliteConnection::Open new failed, connection is nullptr");
            return result;
        }
        errCode = connection->InnerOpen(config);
        conn = connection;
        break;
    }
    return result;
}

RdConnection::RdConnection(bool isWriter) : isWriter_(isWriter) {}

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

int RdConnection::InnerOpen(const RdbStoreConfig &config)
{
    std::string dbPath = "";
    auto errCode = SqliteGlobalConfig::GetDbPath(config, dbPath);
    if (errCode != E_OK) {
        LOG_ERROR("Can not get db path");
        return errCode;
    }
    errCode = RdUtils::RdDbOpen(dbPath.c_str(), configStr_.c_str(), GRD_DB_OPEN_CREATE, &dbHandle_);
    if (errCode != E_OK) {
        LOG_ERROR("Can not open rd db");
        return errCode;
    }
    return errCode;
}

int32_t RdConnection::OnInitialize()
{
    return E_NOT_SUPPORTED;
}

std::pair<int32_t, RdConnection::Stmt> RdConnection::CreateStatement(const std::string& sql, Connection::SConn conn)
{
    auto stmt = std::make_shared<RdStatement>();
    int32_t ret = stmt->Prepare(dbHandle_, sql);
    if (ret != E_OK) {
        return { ret, nullptr };
    }
    if (!isWriter_) {
        ret = stmt->Step();
        if (ret != E_OK && ret != E_NO_MORE_ROWS) {
            return { ret, nullptr };
        }
        stmt->GetProperties();
        ret = stmt->Reset();
        if (ret != E_OK) {
            return { ret, nullptr };
        }
    }
    return { ret, stmt };
}

int32_t RdConnection::GetDBType() const
{
    return DB_VECTOR;
}

bool RdConnection::IsWriter() const
{
    return isWriter_;
}

int32_t RdConnection::ReSetKey(const RdbStoreConfig& config)
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::TryCheckPoint()
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::LimitWalSize()
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::ConfigLocale(const std::string& localeStr)
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::CleanDirtyData(const std::string& table, uint64_t cursor)
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::SubscribeTableChanges(const Connection::Notifier& notifier)
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::GetMaxVariable() const
{
    return MAX_VARIABLE_NUM;
}

int32_t RdConnection::GetJournalMode()
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::ClearCache()
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::Subscribe(const std::string& event,
    const std::shared_ptr<DistributedRdb::RdbStoreObserver>& observer)
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::Unsubscribe(const std::string& event,
    const std::shared_ptr<DistributedRdb::RdbStoreObserver>& observer)
{
    return E_NOT_SUPPORTED;
}

int32_t RdConnection::Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey)
{
    uint32_t size = 0;
    if ((size = destEncryptKey.size()) != 0) {
        return RdUtils::RdDbBackup(dbHandle_, databasePath.c_str(), const_cast<uint8_t*>(&destEncryptKey[0]), size);
    }
    return RdUtils::RdDbBackup(dbHandle_, databasePath.c_str(), nullptr, 0);
}

int32_t RdConnection::Restore(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey)
{
    uint32_t size = 0;
    if ((size = destEncryptKey.size()) != 0) {
        return RdUtils::RdDbRestore(dbHandle_, databasePath.c_str(), const_cast<uint8_t*>(&destEncryptKey[0]), size);
    }
    return RdUtils::RdDbRestore(dbHandle_, databasePath.c_str(), nullptr, 0);
}
} // namespace NativeRdb
} // namespace OHOS