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
#define LOG_TAG "GdbPath"
#include "path_segment.h"

#include "gdb_errors.h"
#include "grd_error.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {
PathSegment::PathSegment() : sourceVertex_(nullptr), edge_(nullptr), targetVertex_(nullptr)
{
}

PathSegment::PathSegment(
    std::shared_ptr<Vertex> sourceVertex, std::shared_ptr<Vertex> targetVertex, std::shared_ptr<Edge> edge)
    : sourceVertex_(sourceVertex), edge_(edge), targetVertex_(targetVertex)
{
}

std::shared_ptr<Vertex> PathSegment::GetSourceVertex() const
{
    return sourceVertex_;
}

void PathSegment::SetSourceVertex(std::shared_ptr<Vertex> vertex)
{
    sourceVertex_ = vertex;
}

std::shared_ptr<Edge> PathSegment::GetEdge() const
{
    return edge_;
}

void PathSegment::SetEdge(std::shared_ptr<Edge> edge)
{
    this->edge_ = edge;
}

std::shared_ptr<Vertex> PathSegment::GetTargetVertex() const
{
    return targetVertex_;
}

void PathSegment::SetTargetVertex(std::shared_ptr<Vertex> vertex)
{
    targetVertex_ = vertex;
}

std::shared_ptr<PathSegment> PathSegment::Parse(const nlohmann::json &json, int32_t &errCode)
{
    if (!json.contains(PathSegment::SOURCE_VERTEX) || !json.at(PathSegment::SOURCE_VERTEX).is_object() ||
        !json.contains(PathSegment::EDGE) || !json.at(PathSegment::EDGE).is_object() ||
        !json.contains(PathSegment::TARGET_VERTEX) || !json.at(PathSegment::TARGET_VERTEX).is_object()) {
        LOG_ERROR("pathSegment format error. jsonStr=%{public}s", json.dump().c_str());
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }
    errCode = E_OK;
    std::shared_ptr<PathSegment> segment = std::make_shared<PathSegment>();
    auto sourceVertex = Vertex::Parse(json.at(PathSegment::SOURCE_VERTEX), errCode);
    if (errCode != E_OK) {
        return nullptr;
    }
    segment->SetSourceVertex(sourceVertex);

    auto edge = Edge::Parse(json.at(PathSegment::EDGE), errCode);
    if (errCode != E_OK) {
        return nullptr;
    }
    segment->SetEdge(edge);

    auto targetVertex = Vertex::Parse(json.at(PathSegment::TARGET_VERTEX), errCode);
    if (errCode != E_OK) {
        return nullptr;
    }
    segment->SetTargetVertex(targetVertex);

    return segment;
}
} // namespace OHOS::DistributedDataAip
