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

#ifndef OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_GRAPH_EDGE_H
#define OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_GRAPH_EDGE_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "nlohmann/json.hpp"
#include "rdb_visibility.h"
#include "vertex.h"

namespace OHOS::DistributedDataAip {
class Edge : public Vertex {
public:
    API_EXPORT Edge();
    API_EXPORT Edge(std::string id, std::string label, std::string sourceId, std::string targetId);
    API_EXPORT Edge(const std::shared_ptr<Vertex> &element, std::string sourceId, std::string targetId);
    static std::shared_ptr<Edge> Parse(const nlohmann::json &json, int32_t &errCode);
    API_EXPORT std::string GetSourceId() const;
    API_EXPORT void SetSourceId(std::string sourceId);

    API_EXPORT std::string GetTargetId() const;
    API_EXPORT void SetTargetId(std::string targetId);

    static constexpr const char *SOURCEID = "start";
    static constexpr const char *TARGETID = "end";

private:
    std::string sourceId_;
    std::string targetId_;
    static std::string GetIdFromJson(const std::string &key, const nlohmann::json &json, int32_t &errCode);
};

}
#endif //OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_GRAPH_EDGE_H
