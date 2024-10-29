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

#include "logger.h"
#include "grd_api_manager.h"
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

std::pair<int32_t, std::shared_ptr<Connection>> RdConnection::Create(const RdbStoreConfig& config, bool isWrite)
{
    (void)config;
    (void)isWrite;
    return {E_NOT_SUPPORT, nullptr};
}

int32_t RdConnection::Repair(const RdbStoreConfig& config)
{
    (void)config;
    return E_NOT_SUPPORT;
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
    (void)config;
    return E_NOT_SUPPORT;
}

RdConnection::RdConnection(const RdbStoreConfig &config, bool isWriter) : isWriter_(isWriter), config_(config)
{
}

RdConnection::~RdConnection()
{
}

std::string RdConnection::GetConfigStr(const std::vector<uint8_t> &keys, bool isEncrypt)
{
    (void)keys;
    (void)isEncrypt;
    return "";
}


int RdConnection::InnerOpen(const RdbStoreConfig &config)
{
    (void)config;
    return E_NOT_SUPPORT;
}

int32_t RdConnection::OnInitialize()
{
    return E_NOT_SUPPORT;
}

std::pair<int32_t, RdConnection::Stmt> RdConnection::CreateStatement(const std::string& sql, Connection::SConn conn)
{
    (void)sql;
    (void)conn;
    RdConnection::Stmt stmt;
    return { E_NOT_SUPPORT, stmt };
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
    (void)config;
    return E_NOT_SUPPORT;
}

int32_t RdConnection::TryCheckPoint(bool timeout)
{
    (void)timeout;
    return E_NOT_SUPPORT;
}

int32_t RdConnection::LimitWalSize()
{
    return E_NOT_SUPPORT;
}

int32_t RdConnection::ConfigLocale(const std::string& localeStr)
{
    (void)localeStr;
    return E_NOT_SUPPORT;
}

int32_t RdConnection::CleanDirtyData(const std::string& table, uint64_t cursor)
{
    (void)table;
    (void)cursor;
    return E_NOT_SUPPORT;
}

int32_t RdConnection::SubscribeTableChanges(const Connection::Notifier& notifier)
{
    (void)notifier;
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

int32_t RdConnection::Subscribe(const std::string& event,
    const std::shared_ptr<DistributedRdb::RdbStoreObserver>& observer)
{
    (void)event;
    (void)observer;
    return E_NOT_SUPPORT;
}

int32_t RdConnection::Unsubscribe(const std::string& event,
    const std::shared_ptr<DistributedRdb::RdbStoreObserver>& observer)
{
    (void)event;
    (void)observer;
    return E_NOT_SUPPORT;
}

int32_t RdConnection::Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
    bool isAsync, SlaveStatus &slaveStatus)
{
    (void)databasePath;
    (void)destEncryptKey;
    (void)isAsync;
    (void)slaveStatus;
    return E_NOT_SUPPORT;
}

int32_t RdConnection::Restore(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
    SlaveStatus &slaveStatus)
{
    (void)databasePath;
    (void)destEncryptKey;
    (void)slaveStatus;
    return E_NOT_SUPPORT;
}

ExchangeStrategy RdConnection::GenerateExchangeStrategy(const SlaveStatus &status)
{
    (void)status;
    return ExchangeStrategy::NOT_HANDLE;
}
} // namespace NativeRdb
} // namespace OHOS