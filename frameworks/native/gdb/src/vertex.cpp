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
#define LOG_TAG "GdbVertex"
#include "vertex.h"

#include <utility>

#include "gdb_errors.h"
#include "full_result.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {
Vertex::Vertex() : id_("0"), properties_()
{
}

Vertex::Vertex(std::string id, std::string label) : id_(std::move(id)), label_(std::move(label))
{
}

Vertex::Vertex(std::string id, std::string label,
    const std::unordered_map<std::string, PropType> &properties)
    : id_(std::move(id)), label_(std::move(label)), properties_(properties)
{
}

std::string Vertex::GetId() const
{
    return id_;
}

void Vertex::SetId(std::string id)
{
    id_ = std::move(id);
}

const std::string &Vertex::GetLabel() const
{
    return label_;
}

const std::vector<std::string> &Vertex::GetLabels()
{
    labels_.clear();
    labels_.emplace_back(label_);
    return labels_;
}

void Vertex::SetLabel(const std::string &label)
{
    label_ = label;
}

const std::unordered_map<std::string, PropType> &Vertex::GetProperties() const
{
    return properties_;
}

void Vertex::SetProperty(const std::string &key, PropType value)
{
    properties_[key] = std::move(value);
}

bool Vertex::Marshal(json &node) const
{
    return false;
}

bool Vertex::GetID(const json &node, const std::string &name, std::string &id)
{
    std::string strId;
    const auto ret = GetValue(node, name, strId);
    if (!ret) {
        uint64_t intId;
        if (GetValue(node, name, intId)) {
            strId = std::to_string(intId);
        } else {
            return false;
        }
    }
    id = std::move(strId);
    return true;
}

bool Vertex::GetPropsValue(const json &node, const std::string &name, std::unordered_map<std::string, PropType> &props)
{
    auto &propsNode = GetSubNode(node, name);
    if (propsNode.is_discarded() || propsNode.is_null()) {
        LOG_WARN("propsNode is discarded.");
        return true;
    }
    if (!propsNode.is_object()) {
        LOG_ERROR("propsNode is not object.");
        return false;
    }
    auto keys = propsNode.Keys();
    for (const auto &key : keys) {
        auto &valueObj = GetSubNode(propsNode, key);
        if (valueObj.is_boolean()) {
            bool boolValue;
            valueObj.get_to(boolValue);
            props.emplace(key, boolValue);
        } else if (valueObj.is_string()) {
            std::string stringValue;
            valueObj.get_to(stringValue);
            props.emplace(key, stringValue);
        } else if (valueObj.is_number_unsigned() || valueObj.is_number_integer()) {
            int64_t int64Value;
            valueObj.get_to(int64Value);
            props.emplace(key, int64Value);
        } else if (valueObj.is_number_float()) {
            double doubleValue;
            valueObj.get_to(doubleValue);
            props.emplace(key, doubleValue);
        } else if (valueObj.is_null()) {
            LOG_WARN("element is null. key: %{public}s", key.c_str());
        } else {
            LOG_WARN("element type of properties not support. key: %{public}s", key.c_str());
            return false;
        }
    }
    return true;
}

bool Vertex::Unmarshal(const json &node)
{
    bool isUnmarshalSuccess = true;
    isUnmarshalSuccess = GetID(node, ID, id_) && isUnmarshalSuccess;
    isUnmarshalSuccess = GetValue(node, LABEL, label_) && isUnmarshalSuccess;
    isUnmarshalSuccess = Vertex::GetPropsValue(node, PROPERTIES, properties_) && isUnmarshalSuccess;
    return isUnmarshalSuccess;
}

std::shared_ptr<Vertex> Vertex::Parse(const std::string &jsonStr, int32_t &errCode)
{
    Vertex vertex;
    if (!Serializable::Unmarshall(jsonStr, vertex)) {
        LOG_WARN("Parse vertex failed.");
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }
    errCode = E_OK;
    return std::make_shared<Vertex>(vertex);
}
} // namespace OHOS::DistributedDataAip
