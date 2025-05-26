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

bool PathSegment::Marshal(json &node) const
{
    return true;
}

bool PathSegment::Unmarshal(const json &node)
{
    bool isUnmarshalSuccess = true;
    if (sourceVertex_ == nullptr) {
        sourceVertex_ = std::make_shared<Vertex>();
    }
    isUnmarshalSuccess = GetValue(node, SOURCE_VERTEX, sourceVertex_) && isUnmarshalSuccess;

    if (targetVertex_ == nullptr) {
        targetVertex_ = std::make_shared<Vertex>();
    }
    isUnmarshalSuccess = GetValue(node, TARGET_VERTEX, targetVertex_) && isUnmarshalSuccess;

    if (edge_ == nullptr) {
        edge_ = std::make_shared<Edge>();
    }
    isUnmarshalSuccess = GetValue(node, EDGE, edge_) && isUnmarshalSuccess;
    return isUnmarshalSuccess;
}

std::shared_ptr<PathSegment> PathSegment::Parse(const std::string &jsonStr, int32_t &errCode)
{
    PathSegment pathSegment;
    if (!Serializable::Unmarshall(jsonStr, pathSegment)) {
        LOG_WARN("Parse pathSegment failed.");
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }
    errCode = E_OK;
    return std::make_shared<PathSegment>(pathSegment);
}
} // namespace OHOS::DistributedDataAip
