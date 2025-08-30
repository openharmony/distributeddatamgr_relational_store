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
#include "connection.h"

#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
namespace OHOS::NativeRdb {
static Connection::Creator g_creators[DB_BUTT] = { nullptr, nullptr };
static Connection::Repairer g_repairers[DB_BUTT] = { nullptr, nullptr };
static Connection::Deleter g_fileDeleter[DB_BUTT] = { nullptr, nullptr };
static Connection::Collector g_collectors[DB_BUTT] = { nullptr, nullptr };
static Connection::GetDbFileser g_getDbFileser[DB_BUTT] = { nullptr, nullptr };
static Connection::ReplicaChecker g_replicaCheckers[DB_BUTT] = { nullptr, nullptr };
std::pair<int, std::shared_ptr<Connection>> Connection::Create(const RdbStoreConfig &config, bool isWriter)
{
    auto dbType = config.GetDBType();
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return { E_INVALID_ARGS, nullptr };
    }

    auto creator = g_creators[dbType];
    if (creator == nullptr) {
        return { E_NOT_SUPPORT, nullptr };
    }

    return creator(config, isWriter);
}

int32_t Connection::Repair(const RdbStoreConfig &config)
{
    auto dbType = config.GetDBType();
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return E_INVALID_ARGS;
    }

    auto repairer = g_repairers[dbType];
    if (repairer == nullptr) {
        return E_NOT_SUPPORT;
    }

    return repairer(config);
}

int32_t Connection::Delete(const RdbStoreConfig &config)
{
    auto dbType = config.GetDBType();
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return E_INVALID_ARGS;
    }
    auto deleter = g_fileDeleter[dbType];
    if (deleter == nullptr) {
        return E_NOT_SUPPORT;
    }

    return deleter(config);
}

std::map<std::string, Connection::Info> Connection::Collect(const RdbStoreConfig &config)
{
    auto dbType = config.GetDBType();
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return {};
    }

    auto collector = g_collectors[dbType];
    if (collector == nullptr) {
        return {};
    }

    return collector(config);
}

std::vector<std::string> Connection::GetDbFiles(const RdbStoreConfig &config)
{
    auto dbType = config.GetDBType();
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return {};
    }
    auto getDbFileser = g_getDbFileser[dbType];
    if (getDbFileser == nullptr) {
        return {};
    }

    return getDbFileser(config);
}

int32_t Connection::CheckReplicaIntegrity(const RdbStoreConfig &config)
{
    auto dbType = config.GetDBType();
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return E_INVALID_ARGS;
    }
    auto replicaChecker = g_replicaCheckers[dbType];
    if (replicaChecker == nullptr) {
        return E_NOT_SUPPORT;
    }

    return replicaChecker(config);
}

int32_t Connection::RegisterCreator(int32_t dbType, Creator creator)
{
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return E_INVALID_ARGS;
    }

    if (g_creators[dbType] != nullptr) {
        return E_OK;
    }

    g_creators[dbType] = creator;
    return E_OK;
}

int32_t Connection::RegisterRepairer(int32_t dbType, Repairer repairer)
{
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return E_INVALID_ARGS;
    }

    if (g_repairers[dbType] != nullptr) {
        return E_OK;
    }

    g_repairers[dbType] = repairer;
    return E_OK;
}

int32_t Connection::RegisterDeleter(int32_t dbType, Deleter deleter)
{
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return E_INVALID_ARGS;
    }

    if (g_fileDeleter[dbType] != nullptr) {
        return E_OK;
    }

    g_fileDeleter[dbType] = deleter;
    return E_OK;
}

int32_t Connection::RegisterCollector(int32_t dbType, Collector collector)
{
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return E_INVALID_ARGS;
    }

    if (g_collectors[dbType] != nullptr) {
        return E_OK;
    }

    g_collectors[dbType] = collector;
    return E_OK;
}

int32_t Connection::RegisterGetDbFileser(int32_t dbType, GetDbFileser getDbFileser)
{
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return E_INVALID_ARGS;
    }

    if (g_getDbFileser[dbType] != nullptr) {
        return E_OK;
    }

    g_getDbFileser[dbType] = getDbFileser;
    return E_OK;
}

int32_t Connection::RegisterReplicaChecker(int32_t dbType, ReplicaChecker replicaChecker)
{
    if (dbType < static_cast<int32_t>(DB_SQLITE) || dbType >= static_cast<int32_t>(DB_BUTT)) {
        return E_INVALID_ARGS;
    }

    if (g_replicaCheckers[dbType] != nullptr) {
        return E_OK;
    }

    g_replicaCheckers[dbType] = replicaChecker;
    return E_OK;
}

int Connection::SetId(int id)
{
    id_ = id;
    return id_;
}

int Connection::GetId() const
{
    return id_;
}

void Connection::SetIsRecyclable(bool isRecyclable)
{
    isRecyclable_ = isRecyclable;
}

bool Connection::IsRecyclable() const
{
    return isRecyclable_;
}
} // namespace OHOS::NativeRdb
