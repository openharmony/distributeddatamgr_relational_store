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

#include "aip_errors.h"
#include "connection.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {
DBStoreImpl::DBStoreImpl(StoreConfig config) : config_(std::move(config))
{
}

DBStoreImpl::~DBStoreImpl()
{
    LOG_DEBUG("DBStoreImpl enter");
    Close();
}

int32_t DBStoreImpl::InitConn()
{
    if (connectionPool_ != nullptr) {
        LOG_ERROR("DBStoreImpl::InitConn connectionPool_ is not nullptr");
        return E_OK;
    }
    int errCode;
    connectionPool_ = ConnectionPool::Create(config_, errCode);
    if (errCode != E_OK || connectionPool_ == nullptr) {
        connectionPool_ = nullptr;
        LOG_ERROR("Create conn failed, ret=%{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

std::pair<int32_t, std::shared_ptr<Result>> DBStoreImpl::QueryGql(const std::string &gql)
{
    if (gql.empty() || gql.length() > MAX_GQL_LEN) {
        LOG_ERROR("Gql is empty or length is too long.");
        return { E_GQL_LENGTH_OVER_LIMIT, nullptr };
    }
    if (connectionPool_ == nullptr) {
        LOG_ERROR("The connpool is nullptr.");
        return { E_STORE_HAS_CLOSED, std::make_shared<FullResult>() };
    }
    auto conn = connectionPool_->AcquireRef(true);
    if (conn == nullptr) {
        LOG_ERROR("Get conn failed");
        return { E_ACQUIRE_CONN_FAILED, std::make_shared<FullResult>() };
    }
    auto [ret2, stmt] = conn->CreateStatement(gql, conn);
    if (ret2 != E_OK || stmt == nullptr) {
        LOG_ERROR("Create stmt failed, ret=%{public}d", ret2);
        return { ret2, std::make_shared<FullResult>() };
    }

    auto result = std::make_shared<FullResult>(stmt);
    auto ret3 = result->InitData();
    if (ret3 != E_OK) {
        LOG_ERROR("Get FullResult failed, ret=%{public}d", ret3);
        return { ret3, std::make_shared<FullResult>() };
    }

    return { E_OK, result };
}

std::pair<int32_t, std::shared_ptr<Result>> DBStoreImpl::ExecuteGql(const std::string &gql)
{
    if (gql.empty() || gql.length() > MAX_GQL_LEN) {
        LOG_ERROR("Gql is empty or length is too long.");
        return { E_GQL_LENGTH_OVER_LIMIT, std::make_shared<FullResult>() };
    }
    if (connectionPool_ == nullptr) {
        LOG_ERROR("The connpool is nullptr.");
        return { E_STORE_HAS_CLOSED, std::make_shared<FullResult>() };
    }
    auto conn = connectionPool_->AcquireRef(false);
    if (conn == nullptr) {
        LOG_ERROR("Get conn failed");
        return { E_ACQUIRE_CONN_FAILED, std::make_shared<FullResult>() };
    }
    auto [ret, stmt] = conn->CreateStatement(gql, conn);
    if (ret != E_OK || stmt == nullptr) {
        LOG_ERROR("Create stmt failed, ret=%{public}d", ret);
        return { ret, std::make_shared<FullResult>() };
    }
    auto ret1 = stmt->Step();
    if (ret1 != E_OK) {
        LOG_ERROR("Step stmt failed, ret=%{public}d", ret1);
    }
    return { ret1, std::make_shared<FullResult>() };
}

int32_t DBStoreImpl::Close()
{
    connectionPool_ = nullptr;
    return E_OK;
}
} // namespace OHOS::DistributedDataAip