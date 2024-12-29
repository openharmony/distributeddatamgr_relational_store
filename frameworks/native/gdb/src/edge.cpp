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
#include <utility>

#include "aip_errors.h"
#include "full_result.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {
Edge::Edge() : Vertex(), sourceId_("0"), targetId_("0")
{
}

Edge::Edge(std::string id, std::string label, std::string sourceId, std::string targetId)
    : Vertex(std::move(id), std::move(label)), sourceId_(std::move(sourceId)), targetId_(std::move(targetId))
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

std::string Edge::GetIdFromJson(const std::string &key, const nlohmann::json &json, int32_t &errCode)
{
    if (key.empty() || (!json.at(key).is_string() && !json.at(key).is_number())) {
        LOG_ERROR("edge start or end id is not number or string. jsonStr=%{public}s", json.dump().c_str());
        errCode = E_PARSE_JSON_FAILED;
        return "";
    }
    errCode = E_OK;
    if (json.at(key).is_number()) {
        auto sourceId = json.at(key).get<int32_t>();
        return std::to_string(sourceId);
    }
    if (json.at(key).is_string()) {
        return json.at(key).get<std::string>();
    }
    errCode = E_PARSE_JSON_FAILED;
    return "";
}

std::shared_ptr<Edge> Edge::Parse(const nlohmann::json &json, int32_t &errCode)
{
    if (!json.contains(Edge::SOURCEID) || !json.contains(Edge::TARGETID)) {
        LOG_ERROR("edge format error. jsonStr=%{public}s", json.dump().c_str());
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }
    errCode = E_OK;
    std::shared_ptr<Vertex> element = Vertex::Parse(json, errCode);
    if (errCode != E_OK || element == nullptr) {
        LOG_ERROR("parse edge element failed. jsonStr=%{public}s", json.dump().c_str());
        return nullptr;
    }
    auto sourceId = Edge::GetIdFromJson(Edge::SOURCEID, json, errCode);
    if (errCode != E_OK) {
        return nullptr;
    }
    auto targetId = Edge::GetIdFromJson(Edge::TARGETID, json, errCode);
    if (errCode != E_OK) {
        return nullptr;
    }
    return std::make_shared<Edge>(element, sourceId, targetId);
}
} // namespace OHOS::DistributedDataAip
