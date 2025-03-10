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

#include "gdb_errors.h"

namespace OHOS::DistributedDataAip {
static Connection::Creator g_creators[static_cast<int32_t>(DBType::DB_BUTT)] = { nullptr, nullptr };

std::pair<int, std::shared_ptr<Connection>> Connection::Create(const StoreConfig &config, const bool isWriter)
{
    auto dbType = config.GetDbType();
    if (dbType < DBType::DB_GRAPH || dbType >= DBType::DB_BUTT) {
        return { E_NOT_SUPPORT, nullptr };
    }

    auto creator = g_creators[static_cast<int32_t>(dbType)];
    if (creator == nullptr) {
        return { E_NOT_SUPPORT, nullptr };
    }

    return creator(config, isWriter);
}

int32_t Connection::RegisterCreator(DBType dbType, Creator creator)
{
    if (dbType < DBType::DB_GRAPH || dbType >= DBType::DB_BUTT) {
        return E_NOT_SUPPORT;
    }

    if (g_creators[static_cast<int32_t>(dbType)] != nullptr) {
        return E_OK;
    }

    g_creators[static_cast<int32_t>(dbType)] = creator;
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

} // namespace OHOS::DistributedDataAip
