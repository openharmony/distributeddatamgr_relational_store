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

#ifndef OHOS_DISTRIBUTED_DATA_NATIVE_GDB_CONNECTION_H
#define OHOS_DISTRIBUTED_DATA_NATIVE_GDB_CONNECTION_H

#include "gdb_store_config.h"
#include "statement.h"

namespace OHOS::DistributedDataAip {
class StoreConfig;
class Statement;
class Connection {
public:
    using SConn = std::shared_ptr<Connection>;
    using Stmt = std::shared_ptr<Statement>;
    using Creator = std::pair<int32_t, SConn> (*)(const StoreConfig &config, bool isWriter);
    static std::pair<int32_t, SConn> Create(const StoreConfig &config, bool isWriter);
    static int32_t RegisterCreator(DBType dbType, Creator creator);

    int32_t SetId(int32_t id);
    int32_t GetId() const;
    virtual ~Connection() = default;
    virtual std::pair<int32_t, Stmt> CreateStatement(const std::string &gql, std::shared_ptr<Connection> conn) = 0;
    virtual DBType GetDBType() const = 0;
    virtual bool IsWriter() const = 0;

private:
    int32_t id_ = 0;
};
} // namespace OHOS::DistributedDataAip
#endif // OHOS_DISTRIBUTED_DATA_NATIVE_GDB_CONNECTION_H