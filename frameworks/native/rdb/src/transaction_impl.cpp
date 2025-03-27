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

#define LOG_TAG "TransactionImpl"

#include "transaction_impl.h"

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_store.h"
#include "trans_db.h"

using namespace OHOS::Rdb;
namespace OHOS::NativeRdb {

__attribute__((used))
const int32_t TransactionImpl::regCreator_ = Transaction::RegisterCreator(TransactionImpl::Create);

TransactionImpl::TransactionImpl(std::shared_ptr<Connection> connection, const std::string &name)
    : name_(name), connection_(std::move(connection))
{
}

TransactionImpl::~TransactionImpl()
{
    // If the user does not commit the transaction, the next time using this connection to create the transaction will
    // fail. Here, we attempt to roll back during the transaction object decomposition to prevent this situation
    // from happening.
    if (connection_ == nullptr) {
        return;
    }
    Rollback();
}

std::pair<int32_t, std::shared_ptr<Transaction>> TransactionImpl::Create(
    int32_t type, std::shared_ptr<Connection> connection, const std::string &name)
{
    auto trans = std::make_shared<TransactionImpl>(std::move(connection), name);
    if (trans == nullptr) {
        return { E_ERROR, nullptr };
    }
    auto errorCode = trans->Begin(type);
    if (errorCode != E_OK) {
        LOG_ERROR("Transaction begin failed, errorCode=%{public}d", errorCode);
        return { errorCode, nullptr };
    }
    return { E_OK, trans };
}

std::string TransactionImpl::GetBeginSql(int32_t type)
{
    if (type < TransactionType::DEFERRED || type >= static_cast<int32_t>(TransactionType::TRANS_BUTT)) {
        LOG_ERROR("invalid type=%{public}d", type);
        return {};
    }
    return BEGIN_SQLS[type];
}

int32_t TransactionImpl::Begin(int32_t type)
{
    std::lock_guard lock(mutex_);
    store_ = std::make_shared<TransDB>(connection_, name_);
    if (store_ == nullptr) {
        return E_ERROR;
    }
    auto beginSql = GetBeginSql(type);
    if (beginSql.empty()) {
        CloseInner();
        return E_INVALID_ARGS;
    }
    auto [errorCode, statement] = connection_->CreateStatement(beginSql, connection_);
    if (errorCode != E_OK) {
        LOG_ERROR("create statement failed, errorCode=%{public}d", errorCode);
        CloseInner();
        return errorCode;
    }
    errorCode = statement->Execute();
    if (errorCode != E_OK) {
        LOG_ERROR("statement execute failed, errorCode=%{public}d", errorCode);
        CloseInner();
        return errorCode;
    }
    return E_OK;
}

int32_t TransactionImpl::Commit()
{
    std::lock_guard lock(mutex_);
    if (connection_ == nullptr) {
        LOG_ERROR("connection already closed");
        return E_ALREADY_CLOSED;
    }

    auto [errorCode, statement] = connection_->CreateStatement(COMMIT_SQL, connection_);
    if (errorCode != E_OK) {
        LOG_ERROR("create statement failed, errorCode=%{public}d", errorCode);
        CloseInner(false);
        return errorCode;
    }

    errorCode = statement->Execute();
    if (errorCode != E_OK) {
        CloseInner(false);
        LOG_ERROR("statement execute failed, errorCode=%{public}d", errorCode);
        return errorCode;
    }
    CloseInner();
    return E_OK;
}

int32_t TransactionImpl::Rollback()
{
    std::lock_guard lock(mutex_);
    if (connection_ == nullptr) {
        LOG_ERROR("connection already closed");
        return E_ALREADY_CLOSED;
    }

    auto [errorCode, statement] = connection_->CreateStatement(ROLLBACK_SQL, connection_);
    if (errorCode != E_OK) {
        LOG_ERROR("create statement failed, errorCode=%{public}d", errorCode);
        CloseInner(false);
        return errorCode;
    }

    errorCode = statement->Execute();
    if (errorCode != E_OK) {
        CloseInner(false);
        LOG_ERROR("statement execute failed, errorCode=%{public}d", errorCode);
        return errorCode;
    }
    CloseInner();
    return E_OK;
}

int32_t TransactionImpl::CloseInner(bool connRecycle)
{
    std::lock_guard lock(mutex_);
    store_ = nullptr;
    if (connection_ != nullptr) {
        connection_->SetIsRecyclable(connRecycle);
    }
    connection_ = nullptr;
    for (auto &resultSet : resultSets_) {
        auto sp = resultSet.lock();
        if (sp != nullptr) {
            sp->Close();
        }
    }
    return E_OK;
}

int32_t TransactionImpl::Close()
{
    return CloseInner();
}

std::shared_ptr<RdbStore> TransactionImpl::GetStore()
{
    std::lock_guard lock(mutex_);
    return store_;
}

std::pair<int, int64_t> TransactionImpl::Insert(const std::string &table, const Row &row, Resolution resolution)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_ALREADY_CLOSED, -1 };
    }
    return store->Insert(table, row, resolution);
}

std::pair<int32_t, int64_t> TransactionImpl::BatchInsert(const std::string &table, const Rows &rows)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_ALREADY_CLOSED, -1 };
    }
    int64_t insertRows{};
    auto errorCode = store->BatchInsert(insertRows, table, rows);
    return { errorCode, insertRows };
}

std::pair<int, int64_t> TransactionImpl::BatchInsert(const std::string &table, const RefRows &rows)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_ALREADY_CLOSED, -1 };
    }
    return store->BatchInsert(table, rows);
}

std::pair<int32_t, int64_t> TransactionImpl::BatchInsertWithConflictResolution(
    const std::string &table, const RefRows &rows, Resolution resolution)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_ALREADY_CLOSED, -1 };
    }
    return store->BatchInsertWithConflictResolution(table, rows, resolution);
}

std::pair<int, int> TransactionImpl::Update(
    const std::string &table, const Row &row, const std::string &where, const Values &args, Resolution resolution)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_ALREADY_CLOSED, -1 };
    }
    return store->Update(table, row, where, args, resolution);
}

std::pair<int32_t, int32_t> TransactionImpl::Update(
    const Row &row, const AbsRdbPredicates &predicates, Resolution resolution)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_ALREADY_CLOSED, -1 };
    }
    return store->Update(
        predicates.GetTableName(), row, predicates.GetWhereClause(), predicates.GetBindArgs(), resolution);
}

std::pair<int32_t, int32_t> TransactionImpl::Delete(
    const std::string &table, const std::string &whereClause, const Values &args)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_ALREADY_CLOSED, -1 };
    }
    int deletedRows{};
    auto errorCode = store->Delete(deletedRows, table, whereClause, args);
    return { errorCode, deletedRows };
}

std::pair<int32_t, int32_t> TransactionImpl::Delete(const AbsRdbPredicates &predicates)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_ALREADY_CLOSED, -1 };
    }
    int deletedRows{};
    auto errorCode = store->Delete(deletedRows, predicates);
    return { errorCode, deletedRows };
}

void TransactionImpl::AddResultSet(std::weak_ptr<ResultSet> resultSet)
{
    std::lock_guard lock(mutex_);
    resultSets_.push_back(std::move(resultSet));
}

std::shared_ptr<ResultSet> TransactionImpl::QueryByStep(const std::string &sql, const Values &args, bool preCount)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return nullptr;
    }
    auto resultSet = store->QueryByStep(sql, args);
    if (resultSet != nullptr) {
        AddResultSet(resultSet);
    }
    return resultSet;
}

std::shared_ptr<ResultSet> TransactionImpl::QueryByStep(
    const AbsRdbPredicates &predicates, const Fields &columns, bool preCount)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return nullptr;
    }
    auto resultSet = store->QueryByStep(predicates, columns);
    if (resultSet != nullptr) {
        AddResultSet(resultSet);
    }
    return resultSet;
}

std::pair<int32_t, ValueObject> TransactionImpl::Execute(const std::string &sql, const Values &args)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_ALREADY_CLOSED, ValueObject() };
    }
    return store->Execute(sql, args);
}
} // namespace OHOS::NativeRdb
