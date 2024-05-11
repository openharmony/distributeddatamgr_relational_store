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
#define LOG_TAG "RdbConnection"
#include "rdb_connection.h"
#include "logger.h"
#include "rd_connection.h"
#include "rdb_errno.h"
#include "sqlite_connection.h"
#include "sqlite_global_config.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

std::shared_ptr<RdbConnection> RdbConnection::Open(const RdbStoreConfig &config, bool isWriteConnection, int &errCode)
{
    if (config.IsVector()) {
        return RdConnection::Open(config, isWriteConnection, errCode);
    }
    return nullptr;
}

RdbConnection::RdbConnection(bool isWriteConnection) : isWriteConnection_(isWriteConnection), isReadOnly_(false),
    openFlags(0)
{
}

bool RdbConnection::IsWriteConnection() const
{
    return isWriteConnection_;
}

int RdbConnection::Prepare(const std::string &sql, bool &outIsReadOnly)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

std::shared_ptr<RdbStatement> RdbConnection::BeginStepQuery(
    int &errCode, const std::string &sql, const std::vector<ValueObject> &args) const
{
    return nullptr;
}

int RdbConnection::DesFinalize()
{
    return E_NOT_SUPPORT;
}

int RdbConnection::EndStepQuery()
{
    return E_NOT_SUPPORT;
}

int RdbConnection::ExecuteForChangedRowCount(
    int &changedRows, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::ExecuteForLastInsertedRowId(int64_t &outRowId, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::ExecuteGetLong(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::ExecuteGetString(std::string &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::ExecuteEncryptSql(const RdbStoreConfig &config, uint32_t iter)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::ReSetKey(const RdbStoreConfig &config)
{
    return E_NOT_SUPPORT;
}

void RdbConnection::SetInTransaction(bool transaction)
{
    return;
}

bool RdbConnection::IsInTransaction()
{
    return E_NOT_SUPPORT;
}

int RdbConnection::TryCheckPoint()
{
    return E_NOT_SUPPORT;
}

int RdbConnection::LimitWalSize()
{
    return E_NOT_SUPPORT;
}

int RdbConnection::ConfigLocale(const std::string &localeStr)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::ExecuteForSharedBlock(int &rowNum, std::string sql, const std::vector<ValueObject> &bindArgs,
    AppDataFwk::SharedBlock *sharedBlock, int startPos, int requiredPos, bool isCountAllRows)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::CleanDirtyData(const std::string &table, uint64_t cursor)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::RegisterCallBackObserver(const DataChangeCallback &clientChangedData)
{
    return E_NOT_SUPPORT;
}

int RdbConnection::GetMaxVariableNumber()
{
    return E_NOT_SUPPORT;
}

uint32_t RdbConnection::GetId() const
{
    return 0;
}

int32_t RdbConnection::SetId(uint32_t id)
{
    (void)id;
    return 0;
}

JournalMode RdbConnection::GetJournalMode()
{
    return JournalMode::MODE_WAL;
}

int RdbConnection::GetDbPath(const RdbStoreConfig &config, std::string &dbPath)
{
    if (config.GetStorageMode() == StorageMode::MODE_MEMORY) {
        dbPath = SqliteGlobalConfig::GetMemoryDbPath();
    } else if (config.GetPath().empty()) {
        LOG_ERROR("RdbConnection GetDbPath input empty database path");
        return E_INVALID_FILE_PATH;
    } else if (config.GetPath().front() != '/' && config.GetPath().at(1) != ':') {
        LOG_ERROR("RdbConnection GetDbPath input relative path");
        return E_RELATIVE_PATH;
    } else {
        dbPath = config.GetPath();
    }
    return E_OK;
}

} // namespace NativeRdb
} // namespace OHOS