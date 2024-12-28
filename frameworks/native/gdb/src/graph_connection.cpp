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
#define LOG_TAG "GdbConn"
#include "graph_connection.h"

#include <unistd.h>

#include <string>
#include <utility>

#include "aip_errors.h"
#include "gdb_utils.h"
#include "graph_statement.h"
#include "logger.h"
#include "securec.h"

namespace OHOS::DistributedDataAip {
__attribute__((used))
const int32_t GraphConnection::regCreator_ = Connection::RegisterCreator(DBType::DB_GRAPH, GraphConnection::Create);

std::pair<int32_t, std::shared_ptr<Connection>> GraphConnection::Create(const StoreConfig &config, bool isWriter)
{
    LOG_DEBUG("GraphConnection::Create start, name=%{public}s, isWriter=%{public}d",
        GdbUtils::Anonymous(config.GetName()).c_str(), isWriter);
    std::pair<int32_t, std::shared_ptr<Connection>> result = { E_INNER_ERROR, nullptr };
    auto &[errCode, conn] = result;
    for (size_t i = 0; i < ITERS_COUNT; i++) {
        std::shared_ptr<GraphConnection> connection = std::make_shared<GraphConnection>(config, isWriter);
        if (connection == nullptr) {
            LOG_ERROR("Open new failed, connection is nullptr. name=%{public}s",
                GdbUtils::Anonymous(config.GetName()).c_str());
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

GraphConnection::GraphConnection(const StoreConfig &config, bool isWriter) : config_(config), isWriter_(isWriter)
{
}

GraphConnection::~GraphConnection()
{
    LOG_DEBUG("enter");
    if (dbHandle_ != nullptr) {
        int errCode = GrdAdapter::Close(dbHandle_, 0);
        if (errCode != E_OK) {
            LOG_ERROR("could not close database, err=%{public}d", errCode);
        }
        dbHandle_ = nullptr;
    }
}

int GraphConnection::InnerOpen(const StoreConfig &config)
{
    std::string dbPath = config.GetFullPath();
    std::string configJson = config.GetJson();
    LOG_DEBUG(
        "GraphConnection::InnerOpen: dbPath=%{public}s, configJson=%{public}s",
        GdbUtils::Anonymous(dbPath).c_str(), configJson.c_str());
    int32_t errCode = GrdAdapter::Open(dbPath.c_str(), configJson.c_str(), GRD_DB_OPEN_CREATE, &dbHandle_);
    if (errCode != E_OK) {
        LOG_ERROR("Can not open rd db, name=%{public}s, errCode=%{public}d.",
            GdbUtils::Anonymous(config.GetName()).c_str(), errCode);
        return errCode;
    }
    return errCode;
}

std::pair<int32_t, GraphConnection::Stmt> GraphConnection::CreateStatement(
    const std::string &gql, std::shared_ptr<Connection> connection)
{
    int32_t ret;
    auto stmt = std::make_shared<GraphStatement>(dbHandle_, gql, connection, ret);
    if (ret != E_OK) {
        return { ret, nullptr };
    }
    return { ret, stmt };
}

DBType GraphConnection::GetDBType() const
{
    return DBType::DB_GRAPH;
}

bool GraphConnection::IsWriter() const
{
    return isWriter_;
}

} // namespace OHOS::DistributedDataAip
