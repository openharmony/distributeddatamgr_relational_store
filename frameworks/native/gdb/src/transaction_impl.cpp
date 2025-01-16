/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define LOG_TAG "GdbTrans"
#include "transaction_impl.h"
 
#include <utility>

#include "aip_errors.h"
#include "logger.h"
#include "trans_db.h"
 
namespace OHOS::DistributedDataAip {

constexpr const char *START_GQL = "START TRANSACTION;";
constexpr const char *COMMIT_GQL = "COMMIT;";
constexpr const char *ROLLBACK_GQL = "ROLLBACK;";

__attribute__((used))
const int32_t TransactionImpl::regCreator_ = Transaction::RegisterCreator(TransactionImpl::Create);
 
TransactionImpl::TransactionImpl(std::shared_ptr<Connection> connection)
    : connection_(std::move(connection))
{
}
 
TransactionImpl::~TransactionImpl()
{
    CloseInner();
}
 
std::pair<int32_t, std::shared_ptr<Transaction>> TransactionImpl::Create(std::shared_ptr<Connection> conn)
{
    if (conn == nullptr) {
        LOG_ERROR("conn is nullptr");
        return { E_ERROR, nullptr };
    }
    auto trans = std::make_shared<TransactionImpl>(std::move(conn));
    if (trans == nullptr) {
        LOG_ERROR("trans is nullptr");
        return { E_ERROR, nullptr };
    }
    auto errorCode = trans->Start();
    if (errorCode != E_OK) {
        LOG_ERROR("transaction start failed, errorCode=%{public}d", errorCode);
        return { errorCode, nullptr };
    }
    return { E_OK, trans };
}

int32_t TransactionImpl::Start()
{
    std::lock_guard lock(mutex_);
    store_ = std::make_shared<TransDB>(connection_);
    if (store_ == nullptr) {
        LOG_ERROR("create trans db failed");
        return E_ERROR;
    }

    if (connection_ == nullptr) {
        LOG_ERROR("connection already closed");
        return E_GRD_DB_INSTANCE_ABNORMAL;
    }

    auto [errorCode, statement] = connection_->CreateStatement(START_GQL, connection_);
    if (errorCode != E_OK || statement == nullptr) {
        LOG_ERROR("create statement failed, errorCode=%{public}d", errorCode);
        CloseInner();
        return errorCode;
    }
    errorCode = statement->Step();
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
        return E_GRD_DB_INSTANCE_ABNORMAL;
    }

    auto [errorCode, statement] = connection_->CreateStatement(COMMIT_GQL, connection_);
    if (errorCode != E_OK || statement == nullptr) {
        LOG_ERROR("create statement failed, errorCode=%{public}d", errorCode);
        CloseInner();
        return errorCode;
    }

    errorCode = statement->Step();
    CloseInner();
    if (errorCode != E_OK) {
        LOG_ERROR("statement execute failed, errorCode=%{public}d", errorCode);
        return errorCode;
    }
    return E_OK;
}
 
int32_t TransactionImpl::Rollback()
{
    std::lock_guard lock(mutex_);
    if (connection_ == nullptr) {
        LOG_ERROR("connection already closed");
        return E_GRD_DB_INSTANCE_ABNORMAL;
    }

    auto [errorCode, statement] = connection_->CreateStatement(ROLLBACK_GQL, connection_);
    if (errorCode != E_OK || statement == nullptr) {
        LOG_ERROR("create statement failed, errorCode=%{public}d", errorCode);
        CloseInner();
        return errorCode;
    }

    errorCode = statement->Step();
    CloseInner();
    if (errorCode != E_OK) {
        LOG_ERROR("statement execute failed, errorCode=%{public}d", errorCode);
        return errorCode;
    }
    return E_OK;
}
 
int32_t TransactionImpl::CloseInner()
{
    std::lock_guard lock(mutex_);
    store_ = nullptr;
    connection_ = nullptr;
    return E_OK;
}

int32_t TransactionImpl::Close()
{
    return Rollback();
}

std::shared_ptr<DBStore> TransactionImpl::GetStore()
{
    std::lock_guard lock(mutex_);
    return store_;
}

std::pair<int32_t, std::shared_ptr<Result>> TransactionImpl::Query(const std::string &gql)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_GRD_DB_INSTANCE_ABNORMAL, std::make_shared<FullResult>() };
    }
    return store->QueryGql(gql);
}

std::pair<int32_t, std::shared_ptr<Result>> TransactionImpl::Execute(const std::string &gql)
{
    auto store = GetStore();
    if (store == nullptr) {
        LOG_ERROR("transaction already close");
        return { E_GRD_DB_INSTANCE_ABNORMAL, std::make_shared<FullResult>() };
    }
    return store->ExecuteGql(gql);
}
} // namespace OHOS::DistributedDataAip
