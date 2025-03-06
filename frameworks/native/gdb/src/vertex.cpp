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
#define LOG_TAG "GdbElement"
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
    labels_.emplace_back(label_);
}

Vertex::Vertex(std::string id, std::string label,
    const std::unordered_map<std::string, PropType> &properties)
    : id_(std::move(id)), label_(std::move(label)), properties_(properties)
{
    labels_.emplace_back(label_);
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

const std::vector<std::string> &Vertex::GetLabels() const
{
    return labels_;
}

void Vertex::SetLabel(const std::string &label)
{
    label_ = label;
    labels_.emplace_back(label);
}

const std::unordered_map<std::string, PropType> &Vertex::GetProperties() const
{
    return properties_;
}

void Vertex::SetProperty(const std::string &key, PropType value)
{
    properties_[key] = std::move(value);
}

std::shared_ptr<Vertex> Vertex::Parse(const nlohmann::json &json, int32_t &errCode)
{
    std::shared_ptr<Vertex> element = std::make_shared<Vertex>();
    if (!json.contains(Vertex::LABEL) || !json.contains(Vertex::ID) ||
        !json.contains(Vertex::PROPERTIES) || !json.at(Vertex::PROPERTIES).is_object()) {
        LOG_ERROR("element format error.");
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }

    if (json.at(Vertex::ID).is_number()) {
        auto id = json.at(Vertex::ID).get<int32_t>();
        element->SetId(std::to_string(id));
    } else if (json.at(Vertex::ID).is_string()) {
        auto id = json.at(Vertex::ID).get<std::string>();
        element->SetId(id);
    } else {
        LOG_ERROR("element id is not number or string.");
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }
    if (!json.at(Vertex::LABEL).is_string()) {
        LOG_ERROR("element label is not string.");
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }
    element->SetLabel(json.at(Vertex::LABEL).get<std::string>());
    for (const auto &[key, value] : json.at(Vertex::PROPERTIES).items()) {
        if (value.is_string()) {
            element->SetProperty(key, value.get<std::string>());
        } else if (value.is_number_integer()) {
            element->SetProperty(key, value.get<int64_t>());
        } else if (value.is_number_float()) {
            element->SetProperty(key, value.get<double>());
        } else if (value.is_boolean()) {
            element->SetProperty(key, value.get<bool>());
        } else if (value.is_null()) {
            element->SetProperty(key, nullptr);
        } else {
            LOG_ERROR("element property value type is not supported.");
            errCode = E_PARSE_JSON_FAILED;
            return nullptr;
        }
    }
    errCode = E_OK;
    return element;
}
} // namespace OHOS::DistributedDataAip
