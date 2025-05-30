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

#ifndef OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_GRAPH_PATH_SEGMENT_H
#define OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_GRAPH_PATH_SEGMENT_H
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "edge.h"
#include "rdb_visibility.h"
#include "serializable.h"
#include "vertex.h"

namespace OHOS::DistributedDataAip {
class PathSegment final : public Serializable {
public:
    API_EXPORT PathSegment();
    API_EXPORT PathSegment(std::shared_ptr<Vertex> sourceVertex, std::shared_ptr<Vertex> targetVertex,
        std::shared_ptr<Edge> edge);
    static std::shared_ptr<PathSegment> Parse(const std::string &jsonStr, int32_t &errCode);

    API_EXPORT std::shared_ptr<Vertex> GetSourceVertex() const;
    API_EXPORT void SetSourceVertex(std::shared_ptr<Vertex> vertex);

    API_EXPORT std::shared_ptr<Edge> GetEdge() const;
    API_EXPORT void SetEdge(std::shared_ptr<Edge> edge);

    API_EXPORT std::shared_ptr<Vertex> GetTargetVertex() const;
    API_EXPORT void SetTargetVertex(std::shared_ptr<Vertex> vertex);

    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;

    static constexpr const char *SOURCE_VERTEX = "start";
    static constexpr const char *TARGET_VERTEX = "end";
    static constexpr const char *EDGE = "relationship";

private:
    std::shared_ptr<Vertex> sourceVertex_;
    std::shared_ptr<Edge> edge_;
    std::shared_ptr<Vertex> targetVertex_;
};
} // namespace OHOS::DistributedDataAip
#endif //OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_GRAPH_PATH_SEGMENT_H
