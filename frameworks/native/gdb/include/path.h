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

#ifndef OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_PATH_H
#define OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_PATH_H
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "edge.h"
#include "nlohmann/json.hpp"
#include "path_segment.h"
#include "vertex.h"

namespace OHOS::DistributedDataAip {
class Path {
public:
    Path();
    Path(std::shared_ptr<Vertex> start, std::shared_ptr<Vertex> end);
    Path(std::shared_ptr<Vertex> start, std::shared_ptr<Vertex> end, uint32_t pathLen,
        std::vector<std::shared_ptr<PathSegment>> segments);

    static std::shared_ptr<Path> Parse(const nlohmann::json &json, int32_t &errCode);

    uint32_t GetPathLength() const;
    void SetPathLength(uint32_t pathLen);
    std::shared_ptr<Vertex> GetStart() const;
    void SetStart(std::shared_ptr<Vertex> start);
    std::shared_ptr<Vertex> GetEnd() const;
    void SetEnd(std::shared_ptr<Vertex> end);
    const std::vector<std::shared_ptr<PathSegment>> &GetSegments() const;

    static constexpr const char *PATHLEN = "length";
    static constexpr const char *START = "start";
    static constexpr const char *END = "end";
    static constexpr const char *SEGMENTS = "segments";

private:
    uint32_t pathLen_;
    std::shared_ptr<Vertex> start_;
    std::shared_ptr<Vertex> end_;
    std::vector<std::shared_ptr<PathSegment>> segments_;
};

} // namespace OHOS::DistributedDataAip
#endif //OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_PATH_H
