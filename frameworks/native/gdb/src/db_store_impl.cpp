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
#define LOG_TAG "GdbStore"
#include "db_store_impl.h"

#include <utility>

#include "connection.h"
#include "db_trace.h"
#include "gdb_errors.h"
#include "gdb_transaction.h"
#include "gdb_utils.h"
#include "logger.h"
#include "transaction_impl.h"

namespace OHOS::DistributedDataAip {

constexpr int32_t MAX_GQL_LEN = 1024 * 1024;

DBStoreImpl::DBStoreImpl(StoreConfig config) : config_(std::move(config))
{
}

DBStoreImpl::~DBStoreImpl()
{
    LOG_DEBUG("DBStoreImpl enter");
    Close();
}

std::shared_ptr<ConnectionPool> DBStoreImpl::GetConnectionPool()
{
    std::lock_guard lock(mutex_);
    return connectionPool_;
}

void DBStoreImpl::SetConnectionPool(std::shared_ptr<ConnectionPool> connectionPool)
{
    std::lock_guard lock(mutex_);
    connectionPool_ = connectionPool;
}

int32_t DBStoreImpl::InitConn()
{
    if (GetConnectionPool() != nullptr) {
        LOG_INFO("connectionPool_ is not nullptr");
        return E_OK;
    }
    int errCode;
    auto connectionPool = ConnectionPool::Create(config_, errCode);
    if (errCode != E_OK || connectionPool == nullptr) {
        LOG_ERROR("Create conn failed, ret=%{public}d", errCode);
        return errCode;
    }
    SetConnectionPool(connectionPool);
    return E_OK;
}

std::pair<int32_t, std::shared_ptr<Result>> DBStoreImpl::QueryGql(const std::string &gql)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (gql.empty() || gql.length() > MAX_GQL_LEN) {
        LOG_ERROR("Gql is empty or length is too long.");
        return { E_INVALID_ARGS, nullptr };
    }
    if (GdbUtils::IsTransactionGql(gql)) {
        LOG_ERROR("Transaction related statements are not supported.");
        return { E_INVALID_ARGS, nullptr };
    }
    auto connectionPool = GetConnectionPool();
    if (connectionPool == nullptr) {
        LOG_ERROR("The connpool is nullptr.");
        return { E_STORE_HAS_CLOSED, std::make_shared<FullResult>() };
    }
    auto conn = connectionPool->AcquireRef(true);
    if (conn == nullptr) {
        LOG_ERROR("Get conn failed");
        return { E_ACQUIRE_CONN_FAILED, std::make_shared<FullResult>() };
    }
    auto [ret, stmt] = conn->CreateStatement(gql, conn);
    if (ret != E_OK || stmt == nullptr) {
        if (ret == E_GRD_OVER_LIMIT) {
            ret = E_GRD_SEMANTIC_ERROR;
        }
        LOG_ERROR("Create stmt failed, ret=%{public}d", ret);
        return { ret, std::make_shared<FullResult>() };
    }

    auto result = std::make_shared<FullResult>();
    ret = result->InitData(stmt);
    if (ret != E_OK) {
        if (ret == E_GRD_OVER_LIMIT) {
            ret = E_GRD_SEMANTIC_ERROR;
        }
        LOG_ERROR("Get FullResult failed, ret=%{public}d", ret);
        return { ret, std::make_shared<FullResult>() };
    }

    return { E_OK, result };
}

std::pair<int32_t, std::shared_ptr<Result>> DBStoreImpl::ExecuteGql(const std::string &gql)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (gql.empty() || gql.length() > MAX_GQL_LEN) {
        LOG_ERROR("Gql is empty or length is too long.");
        return { E_INVALID_ARGS, std::make_shared<FullResult>() };
    }
    if (GdbUtils::IsTransactionGql(gql)) {
        LOG_ERROR("Transaction related statements are not supported.");
        return { E_INVALID_ARGS, std::make_shared<FullResult>() };
    }
    auto connectionPool = GetConnectionPool();
    if (connectionPool == nullptr) {
        LOG_ERROR("The connpool is nullptr.");
        return { E_STORE_HAS_CLOSED, std::make_shared<FullResult>() };
    }
    auto conn = connectionPool->AcquireRef(false);
    if (conn == nullptr) {
        LOG_ERROR("Get conn failed");
        return { E_ACQUIRE_CONN_FAILED, std::make_shared<FullResult>() };
    }
    auto [ret, stmt] = conn->CreateStatement(gql, conn);
    if (ret != E_OK || stmt == nullptr) {
        LOG_ERROR("Create stmt failed, ret=%{public}d", ret);
        return { ret, std::make_shared<FullResult>() };
    }
    ret = stmt->Step();
    if (ret != E_OK) {
        LOG_ERROR("Step stmt failed, ret=%{public}d", ret);
    }
    return { ret, std::make_shared<FullResult>() };
}

std::pair<int32_t, std::shared_ptr<Transaction>> DBStoreImpl::CreateTransaction()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto connectionPool = GetConnectionPool();
    if (connectionPool == nullptr) {
        LOG_ERROR("The connpool is nullptr.");
        return { E_STORE_HAS_CLOSED, nullptr };
    }
    auto [ret, conn] = connectionPool->CreateTransConn();
    if (ret != E_OK || conn == nullptr) {
        LOG_ERROR("Get conn failed");
        return { ret, nullptr };
    }
    std::shared_ptr<Transaction> trans;
    std::tie(ret, trans) = TransactionImpl::Create(conn);
    if (ret != E_OK || trans == nullptr) {
        LOG_ERROR("Create trans failed, ret=%{public}d", ret);
        return { ret, nullptr };
    }

    std::lock_guard lock(transMutex_);
    for (auto it = transactions_.begin(); it != transactions_.end();) {
        if (it->expired()) {
            it = transactions_.erase(it);
        } else {
            it++;
        }
    }
    transactions_.push_back(trans);
    return { ret, trans };
}

int32_t DBStoreImpl::Close()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    SetConnectionPool(nullptr);

    std::lock_guard lock(transMutex_);
    for (auto &trans : transactions_) {
        auto realTrans = trans.lock();
        if (realTrans) {
            (void)realTrans->Close();
        }
    }
    transactions_ = {};
    return E_OK;
}
} // namespace OHOS::DistributedDataAip