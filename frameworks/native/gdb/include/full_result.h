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
#ifndef OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_FULLRESULT_H
#define OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_FULLRESULT_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "edge.h"
#include "gdb_store_config.h"
#include "path.h"
#include "result.h"
#include "vertex.h"

namespace OHOS::DistributedDataAip {
class Statement;
class FullResult final : public Result {
public:
    FullResult() = default;
    std::vector<std::unordered_map<std::string, GraphValue>> GetAllData() const override;
    int32_t InitData(std::shared_ptr<Statement> stmt);

private:
    std::pair<int32_t, std::unordered_map<std::string, GraphValue>> GetRow(std::shared_ptr<Statement> stmt);
    std::vector<std::unordered_map<std::string, GraphValue>> data_;
};
} // namespace OHOS::DistributedDataAip
#endif //OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_FULLRESULT_H
