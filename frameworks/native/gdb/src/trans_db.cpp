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
#define LOG_TAG "TransDB"
#include "trans_db.h"

#include "aip_errors.h"
#include "db_trace.h"
#include "gdb_utils.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {

constexpr int32_t MAX_GQL_LEN = 1024 * 1024;

TransDB::TransDB(std::shared_ptr<Connection> connection) : conn_(connection)
{
}

std::pair<int32_t, std::shared_ptr<Result>> TransDB::QueryGql(const std::string &gql)
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

    auto [errCode, statement] = GetStatement(gql);
    if (errCode != E_OK || statement == nullptr) {
        return { errCode, std::make_shared<FullResult>() };
    }

    auto result = std::make_shared<FullResult>();
    errCode = result->InitData(statement);
    if (errCode != E_OK) {
        LOG_ERROR("Get FullResult failed, errCode=%{public}d", errCode);
        return { errCode, std::make_shared<FullResult>() };
    }
    
    return { errCode, result };
}

std::pair<int32_t, std::shared_ptr<Result>> TransDB::ExecuteGql(const std::string &gql)
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

    auto [errCode, statement] = GetStatement(gql);
    if (errCode != E_OK || statement == nullptr) {
        return { errCode, std::make_shared<FullResult>() };
    }

    errCode = statement->Step();
    if (errCode != E_OK) {
        LOG_ERROR("Step statement failed, errCode=%{public}d", errCode);
    }
    return { errCode, std::make_shared<FullResult>() };
}

std::pair<int32_t, std::shared_ptr<Statement>> TransDB::GetStatement(const std::string &gql) const
{
    auto connection = conn_.lock();
    if (connection == nullptr) {
        return { E_GRD_DB_INSTANCE_ABNORMAL, nullptr };
    }
    return connection->CreateStatement(gql, connection);
}

std::pair<int32_t, std::shared_ptr<Transaction>> TransDB::CreateTransaction()
{
    return { E_NOT_SUPPORT, nullptr };
}

int32_t TransDB::Close()
{
    return E_NOT_SUPPORT;
}
} // namespace OHOS::DistributedDataAip