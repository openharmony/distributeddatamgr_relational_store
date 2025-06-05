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
#define LOG_TAG "GdbEdge"
#include "edge.h"

#include <utility>

#include "gdb_errors.h"
#include "full_result.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {
Edge::Edge() : id_("0"), properties_(), sourceId_("0"), targetId_("0")
{
}

Edge::Edge(std::string id, std::string label, std::string sourceId, std::string targetId)
    : id_(std::move(id)), label_(std::move(label)), sourceId_(std::move(sourceId)), targetId_(std::move(targetId))
{
}

Edge::Edge(const std::shared_ptr<Vertex> &element, std::string sourceId, std::string targetId)
    : sourceId_(std::move(sourceId)), targetId_(std::move(targetId))
{
    if (element != nullptr) {
        id_ = element->GetId();
        label_ = element->GetLabel();
        properties_ = element->GetProperties();
    }
}

std::string Edge::GetId() const
{
    return id_;
}

void Edge::SetId(std::string id)
{
    id_ = std::move(id);
}

const std::string &Edge::GetLabel() const
{
    return label_;
}

void Edge::SetLabel(const std::string &label)
{
    label_ = label;
}

const std::unordered_map<std::string, PropType> &Edge::GetProperties() const
{
    return properties_;
}

void Edge::SetProperty(const std::string &key, PropType value)
{
    properties_[key] = std::move(value);
}

std::string Edge::GetSourceId() const
{
    return sourceId_;
}

void Edge::SetSourceId(std::string sourceId)
{
    sourceId_ = std::move(sourceId);
}

std::string Edge::GetTargetId() const
{
    return targetId_;
}

void Edge::SetTargetId(std::string targetId)
{
    targetId_ = std::move(targetId);
}

bool Edge::Marshal(json &node) const
{
    return false;
}

bool Edge::Unmarshal(const json &node)
{
    bool isUnmarshalSuccess = true;
    isUnmarshalSuccess = Vertex::GetID(node, ID, id_) && isUnmarshalSuccess;
    isUnmarshalSuccess = GetValue(node, LABEL, label_) && isUnmarshalSuccess;
    isUnmarshalSuccess = Vertex::GetID(node, SOURCEID, sourceId_) && isUnmarshalSuccess;
    isUnmarshalSuccess = Vertex::GetID(node, TARGETID, targetId_) && isUnmarshalSuccess;
    isUnmarshalSuccess = Vertex::GetPropsValue(node, PROPERTIES, properties_) && isUnmarshalSuccess;
    return isUnmarshalSuccess;
}

std::shared_ptr<Edge> Edge::Parse(const std::string &jsonStr, int32_t &errCode)
{
    Edge edge;
    if (!Serializable::Unmarshall(jsonStr, edge)) {
        LOG_WARN("Parse edge failed.");
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }
    errCode = E_OK;
    return std::make_shared<Edge>(edge);
}
} // namespace OHOS::DistributedDataAip
