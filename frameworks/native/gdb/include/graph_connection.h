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

#ifndef OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_CONNECTION_H
#define OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_CONNECTION_H

#include <memory>
#include <mutex>
#include <vector>

#include "connection.h"
#include "gdb_store_config.h"
#include "grd_adapter.h"

namespace OHOS::DistributedDataAip {
class GraphConnection : public Connection {
public:
    static std::pair<int32_t, std::shared_ptr<Connection>> Create(const StoreConfig &config, bool isWriter);
    GraphConnection(const StoreConfig &config, bool isWriter);
    ~GraphConnection() override;
    std::pair<int32_t, Stmt> CreateStatement(const std::string &gql, std::shared_ptr<Connection> conn) override;
    DBType GetDBType() const override;
    bool IsWriter() const override;

private:
    static constexpr uint32_t NO_ITER = 0;
    static constexpr uint32_t ITER_V1 = 5000;
    static constexpr uint32_t ITERS[] = { NO_ITER, ITER_V1 };
    static constexpr uint32_t ITERS_COUNT = sizeof(ITERS) / sizeof(ITERS[0]);

    static const int32_t regCreator_;

    int InnerOpen(const StoreConfig &config);
    int32_t ResetKey(const StoreConfig &config);
    GRD_DB *dbHandle_ = nullptr;
    const StoreConfig config_;
    bool isWriter_ = false;
};

} // namespace OHOS::DistributedDataAip

#endif // OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_CONNECTION_H
