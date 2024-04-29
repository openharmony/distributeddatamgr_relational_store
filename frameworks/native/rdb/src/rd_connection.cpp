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
#include "rdb_errno.h"
#include "rd_statement.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

std::shared_ptr<RdConnection> RdConnection::Open(const RdbStoreConfig &config, bool isWriteConnection, int &errCode)
{
    for (size_t i = 0; i < ITERS_COUNT; i++) {
        std::shared_ptr<RdConnection> connection = std::make_shared<RdConnection>(isWriteConnection);
        if (connection == nullptr) {
            LOG_ERROR("SqliteConnection::Open new failed, connection is nullptr");
            return nullptr;
        }
        errCode = connection->InnerOpen(config);
        if (errCode == E_OK) {
            return connection;
        }
    }
    return nullptr;
}

RdConnection::RdConnection(bool isWriteConnection)
    : RdbConnection(isWriteConnection), inTransaction_(false)
{
}

RdConnection::~RdConnection()
{
    if (dbHandle_ != nullptr) {
        if (statement_ != nullptr) {
            statement_ = nullptr;
        }
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
    int errCode = GetDbPath(config, dbPath);
    if (errCode != E_OK) {
        LOG_ERROR("Can not get db path");
        return errCode;
    }
    errCode = RdUtils::RdDbOpen(dbPath.c_str(), configStr_.c_str(), GRD_DB_OPEN_CREATE, &dbHandle_);
    if (errCode != E_OK) {
        LOG_ERROR("Can not open rd db");
        return errCode;
    }
    statement_ = std::make_shared<RdStatement>();
    return errCode;
}

int RdConnection::Prepare(const std::string &sql, bool &outIsReadOnly)
{
    if (statement_ == nullptr) {
        LOG_ERROR("RdConnection Prepare meets empty statement");
        return E_ERROR;
    }
    int ret = std::static_pointer_cast<RdStatement>(statement_)->Prepare(dbHandle_, sql);
    if (ret != E_OK) {
        LOG_ERROR("RdConnection Unable to prepare statement");
        return ret;
    }
    outIsReadOnly = IsWriteConnection();
    return E_OK;
}

int RdConnection::PrepareAndBind(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    if (statement_ == nullptr) {
        LOG_ERROR("RdConnection PrepareAndBind meets empty statement");
        return E_ERROR;
    }
    int errCode = std::static_pointer_cast<RdStatement>(statement_)->Prepare(dbHandle_, sql);
    if (errCode != E_OK) {
        LOG_ERROR("PrepareAndBind unable to prepare stmt : err %{public}d", errCode);
        return errCode;
    }
    return statement_->BindArguments(bindArgs);
}

int RdConnection::ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    int ret = PrepareAndBind(sql, bindArgs);
    if (ret != E_OK) {
        LOG_ERROR("RdConnection unable to prepare and bind stmt : err %{public}d", ret);
        return ret;
    }
    ret = statement_->Step();
    if (ret != E_OK && ret != E_NO_MORE_ROWS) {
        LOG_ERROR("RdConnection Execute : err %{public}d", ret);
        statement_->ResetStatementAndClearBindings();
        return ret;
    }
    return statement_->ResetStatementAndClearBindings();
}

std::shared_ptr<RdbStatement> RdConnection::BeginStepQuery(int &errCode, const std::string &sql,
    const std::vector<ValueObject> &args) const
{
    if (stepStatement_ == nullptr) {
        LOG_ERROR("RdConnection meets unexpected null");
        errCode = E_ROW_OUT_RANGE;
    }
    errCode = std::static_pointer_cast<RdStatement>(stepStatement_)->Prepare(dbHandle_, sql);
    if (errCode != E_OK) {
        return nullptr;
    }
    errCode = stepStatement_->BindArguments(args);
    if (errCode != E_OK) {
        return nullptr;
    }
    return stepStatement_;
}

int RdConnection::DesFinalize()
{
    if (statement_ == nullptr) {
        LOG_ERROR("RdConnection DesFinalize meets empty statement");
        return E_ERROR;
    }
    int ret = 0;
    ret = statement_->Finalize();
    if (ret != E_OK) {
        LOG_ERROR("RdConnection meets unexpected null");
        return ret;
    }
    if (stepStatement_ == nullptr) {
        return E_OK;
    }
    ret = stepStatement_->Finalize();
    if (ret != E_OK) {
        LOG_ERROR("RdConnection unable to finalize statement");
        return ret;
    }
    if (dbHandle_ != nullptr) {
        ret = RdUtils::RdDbClose(dbHandle_, 0);
    }
    if (ret != E_OK) {
        LOG_ERROR("RdConnection unable to close db handle");
    }
    return ret;
}

int RdConnection::EndStepQuery()
{
    if (stepStatement_ == nullptr) {
        LOG_ERROR("RdConnection meets unexpected null");
        return E_ALREADY_CLOSED;
    }
    return stepStatement_->ResetStatementAndClearBindings();
}

void RdConnection::SetInTransaction(bool transaction)
{
    inTransaction_ = transaction;
}

bool RdConnection::IsInTransaction()
{
    return inTransaction_;
}

} // namespace NativeRdb
} // namespace OHOS