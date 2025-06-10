/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "Serializable"
#include "serializable.h"

#include <cJSON.h>
#include <cmath>
#include "logger.h"
namespace OHOS {
using namespace OHOS::Rdb;
Serializable::json Serializable::Marshall() const
{
    json root;
    Marshal(root);
    return root;
}

bool Serializable::Unmarshall(const std::string &jsonStr)
{
    json jsonObj = json::parse(jsonStr);
    if (jsonObj.is_discarded()) {
        // if the string size is less than 1, means the string is invalid.
        if (jsonStr.empty()) {
            LOG_WARN("jsonStr is empty");
            return false;
        }
        jsonObj = json::parse(jsonStr.substr(1)); // drop first char to adapt A's value;
        if (jsonObj.is_discarded()) {
            LOG_WARN("jsonStr is discarded");
            return false;
        }
    }
    return Unmarshal(jsonObj);
}

Serializable::json Serializable::ToJson(const std::string &jsonStr)
{
    json jsonObj = json::parse(jsonStr);
    if (jsonObj.is_discarded()) {
        // if the string size is less than 1, means the string is invalid.
        if (jsonStr.empty()) {
            return {};
        }
        jsonObj = json::parse(jsonStr.substr(1)); // drop first char to adapt A's value;
        if (jsonObj.is_discarded()) {
            return {};
        }
    }
    return jsonObj;
}

bool Serializable::IsJson(const std::string &jsonStr)
{
    if (!json::accept(jsonStr)) {
        return json::accept(jsonStr.substr(1));
    }
    return true;
}

bool Serializable::GetValue(const json &node, const std::string &name, std::string &value)
{
    auto &subNode = GetSubNode(node, name);
    if (subNode.is_null() || !subNode.is_string()) {
        return false;
    }
    subNode.get_to(value);
    return true;
}

bool Serializable::GetValue(const json &node, const std::string &name, uint32_t &value)
{
    auto &subNode = GetSubNode(node, name);
    if (subNode.is_null() || !subNode.is_number_unsigned()) {
        return false;
    }
    subNode.get_to(value);
    return true;
}

bool Serializable::GetValue(const json &node, const std::string &name, int32_t &value)
{
    auto &subNode = GetSubNode(node, name);
    if (subNode.is_null() || !subNode.is_number_integer()) {
        return false;
    }
    subNode.get_to(value);
    return true;
}

bool Serializable::GetValue(const json &node, const std::string &name, uint64_t &value)
{
    auto &subNode = GetSubNode(node, name);
    if (subNode.is_null() || !subNode.is_number_integer()) {
        return false;
    }
    subNode.get_to(value);
    return true;
}

bool Serializable::GetValue(const json &node, const std::string &name, int64_t &value)
{
    auto &subNode = GetSubNode(node, name);
    if (subNode.is_null() || !subNode.is_number_integer()) {
        return false;
    }
    subNode.get_to(value);
    return true;
}

bool Serializable::GetValue(const json &node, const std::string &name, bool &value)
{
    auto &subNode = GetSubNode(node, name);
    if (subNode.is_null() || !subNode.is_boolean()) {
        return false;
    }
    subNode.get_to(value);
    return true;
}

bool Serializable::GetValue(const json &node, const std::string &name, std::vector<uint8_t> &value)
{
    auto &subNode = GetSubNode(node, name);
    if (subNode.is_null() || !subNode.is_array()) {
        return false;
    }
    subNode.get_to(value);
    return true;
}

bool Serializable::GetValue(const json &node, const std::string &name, Serializable &value)
{
    auto &subNode = GetSubNode(node, name);
    if (subNode.is_null() || !subNode.is_object()) {
        return false;
    }
    return value.Unmarshal(subNode);
}

bool Serializable::GetValue(const json &node, const std::string &name, std::shared_ptr<Serializable> value)
{
    if (value == nullptr) {
        return false;
    }
    auto &subNode = GetSubNode(node, name);
    if (subNode.is_null() || !subNode.is_object()) {
        return false;
    }
    return value->Unmarshal(subNode);
}

bool Serializable::SetValue(json &node, const std::string &value)
{
    node = value;
    return true;
}

bool Serializable::SetValue(json &node, const uint32_t &value)
{
    node = value;
    return true;
}

bool Serializable::SetValue(json &node, const int32_t &value)
{
    node = value;
    return true;
}

bool Serializable::SetValue(json &node, const uint64_t &value)
{
    node = value;
    return true;
}

bool Serializable::SetValue(json &node, const int64_t &value)
{
    node = value;
    return true;
}

bool Serializable::SetValue(json &node, const bool &value)
{
    node = value;
    return true;
}

bool Serializable::SetValue(json &node, const std::vector<uint8_t> &value)
{
    node = value;
    return true;
}

bool Serializable::SetValue(json &node, const Serializable &value)
{
    return value.Marshal(node);
}

const Serializable::json &Serializable::GetSubNode(const json &node, const std::string &name)
{
    static const json jsonNull;
    if (node.is_discarded() || node.is_null()) {
        return jsonNull;
    }

    if (name.empty()) {
        return node;
    }

    auto it = node.find(name);
    if (it == node.end()) {
        return jsonNull;
    }
    return *it;
}

Serializable::JSONWrapper::JSONWrapper() : root_(nullptr)
{
    json_ = cJSON_CreateNull();
    needDel_ = true;
}

Serializable::JSONWrapper::JSONWrapper(cJSON *json, cJSON *root, const std::string &key)
    : json_(json), root_(root), key_(key), needDel_(root == nullptr && json_ != nullptr)
{
}

Serializable::JSONWrapper::JSONWrapper(const std::string &jsonStr) : root_(nullptr), needDel_(true)
{
    json_ = cJSON_Parse(jsonStr.c_str());
}

Serializable::JSONWrapper::JSONWrapper(JSONWrapper &&jsonWrapper)
{
    json_ = jsonWrapper.json_;
    jsonWrapper.json_ = nullptr;
    root_ = jsonWrapper.root_;
    jsonWrapper.root_ = nullptr;
    key_ = std::move(jsonWrapper.key_);
    children_ = std::move(jsonWrapper.children_);
    needDel_ = jsonWrapper.needDel_;
}

Serializable::JSONWrapper::operator std::string() const
{
    return dump();
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(JSONWrapper &&jsonWrapper)
{
    if (this == &jsonWrapper) {
        return *this;
    }
    if (needDel_) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
    json_ = std::move(jsonWrapper.json_);
    jsonWrapper.json_ = nullptr;
    root_ = jsonWrapper.root_;
    jsonWrapper.root_ = nullptr;
    key_ = std::move(jsonWrapper.key_);
    children_ = std::move(jsonWrapper.children_);
    needDel_ = jsonWrapper.needDel_;
    return *this;
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(Serializable::JSONWrapper::Type type)
{
    if (json_ != nullptr) {
        LOG_ERROR("cannot use operator=");
        return *this;
    }
    switch (type) {
        case Type::ARRAY:
            json_ = cJSON_CreateArray();
            break;
        case Type::OBJECT:
            json_ = cJSON_CreateObject();
            break;
        default:
            LOG_ERROR("unknown type, type: %{public}d", static_cast<int32_t>(type));
    }
    if (json_ == nullptr || root_ == nullptr) {
        return *this;
    }
    AddToRoot();
    return *this;
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(bool value)
{
    if (needDel_ && cJSON_IsNull(json_)) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
    if (json_ != nullptr) {
        if (cJSON_IsBool(json_)) {
            cJSON_SetBoolValue(json_, value);
        } else {
            LOG_WARN("type is not bool");
        }
        return *this;
    }
    json_ = cJSON_CreateBool(value);
    if (json_ == nullptr || root_ == nullptr) {
        return *this;
    }
    AddToRoot();
    return *this;
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(int32_t value)
{
    if (root_ == nullptr && cJSON_IsNull(json_)) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
    if (json_ != nullptr) {
        if (cJSON_IsNumber(json_)) {
            cJSON_SetNumberValue(json_, value);
        } else {
            LOG_WARN("type is not number");
        }
        return *this;
    }
    json_ = cJSON_CreateNumber(value);
    if (json_ == nullptr || root_ == nullptr) {
        return *this;
    }
    AddToRoot();
    return *this;
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(uint32_t value)
{
    int32_t number = static_cast<int32_t>(value);
    return operator=(number);
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(int64_t value)
{
    if (root_ == nullptr && cJSON_IsNull(json_)) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
    if (json_ != nullptr) {
        if (cJSON_IsNumber(json_)) {
            cJSON_SetNumberValue(json_, value);
        } else {
            LOG_WARN("type is not number");
        }
        return *this;
    }
    json_ = cJSON_CreateNumber(value);
    if (json_ == nullptr || root_ == nullptr) {
        return *this;
    }
    AddToRoot();
    return *this;
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(uint64_t value)
{
    int64_t number = static_cast<int64_t>(value);
    return operator=(number);
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(double value)
{
    if (root_ == nullptr && cJSON_IsNull(json_)) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
    if (json_ != nullptr) {
        if (cJSON_IsNumber(json_)) {
            cJSON_SetNumberValue(json_, value);
        } else {
            LOG_WARN("type is not number");
        }
        return *this;
    }
    json_ = cJSON_CreateNumber(value);
    if (json_ == nullptr || root_ == nullptr) {
        return *this;
    }
    AddToRoot();
    return *this;
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(const char *value)
{
    if (root_ == nullptr && cJSON_IsNull(json_)) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
    if (json_ != nullptr) {
        return *this;
    }
    json_ = cJSON_CreateString(value);
    if (json_ == nullptr || root_ == nullptr) {
        return *this;
    }
    AddToRoot();
    return *this;
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(const std::string &value)
{
    return operator=(value.c_str());
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator=(const std::vector<uint8_t> &value)
{
    if (root_ == nullptr && cJSON_IsNull(json_)) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
    if (json_ != nullptr) {
        return *this;
    }
    json_ = cJSON_CreateArray();
    children_.clear();
    for (size_t i = 0; json_ && (i < value.size()); i++) {
        auto node = cJSON_CreateNumber(value[i]);
        if (!node || !cJSON_AddItemToArray(json_, node)) {
            cJSON_Delete(json_);
            json_ = nullptr;
            children_.clear();
            return *this;
        }
        children_.push_back(std::make_shared<JSONWrapper>(node, json_));
    }
    if (json_ == nullptr || root_ == nullptr) {
        return *this;
    }
    AddToRoot();
    return *this;
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator[](const std::string &key)
{
    if (root_ == nullptr && cJSON_IsNull(json_)) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
    if (json_ == nullptr) {
        json_ = cJSON_CreateObject();
        if (json_ != nullptr && root_ != nullptr) {
            AddToRoot();
        }
    }
    if (!is_object()) {
        LOG_ERROR("is not object, cannot use operator[].");
    }
    auto it = children_.begin();
    while (it != children_.end()) {
        if ((*it)->key_ == key) {
            return **it;
        }
        ++it;
    }
    auto item = cJSON_GetObjectItem(json_, key.c_str());
    auto res = std::make_shared<JSONWrapper>(item, json_, key);
    children_.push_back(res);
    return *res;
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator[](size_t index)
{
    if (root_ == nullptr && cJSON_IsNull(json_)) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
    if (json_ == nullptr) {
        json_ = cJSON_CreateArray();
        if (json_ != nullptr && root_ != nullptr) {
            AddToRoot();
        }
    }
    if (!is_array()) {
        LOG_ERROR("is not array, cannot use operator[].");
    }

    int rawSize = cJSON_GetArraySize(json_);
    size_t size = (rawSize < 0) ? 0 : static_cast<size_t>(rawSize);
    auto len = children_.size();
    while (len < size) {
        auto item = cJSON_GetArrayItem(json_, len);
        children_.push_back(std::make_shared<JSONWrapper>(item, json_));
        len++;
    }
    if (index > len) {
        LOG_ERROR("cannot use operator[]");
    }
    if (index == len) {
        children_.push_back(std::make_shared<JSONWrapper>(nullptr, json_));
    }
    return *children_[index];
}

Serializable::JSONWrapper &Serializable::JSONWrapper::operator[](size_t index) const
{
    if (!is_array()) {
        LOG_ERROR("invalid args.");
    }
    int rawSize = cJSON_GetArraySize(json_);
    size_t size = (rawSize < 0) ? 0 : static_cast<size_t>(rawSize);
    if (index >= size) {
        LOG_ERROR("invalid args.");
    }
    auto len = children_.size();
    while (len < size) {
        auto item = cJSON_GetArrayItem(json_, len);
        children_.push_back(std::make_shared<JSONWrapper>(item, json_));
        len++;
    }
    return *children_[index];
}

bool Serializable::JSONWrapper::is_null() const
{
    return cJSON_IsNull(json_);
}

bool Serializable::JSONWrapper::is_boolean() const
{
    return cJSON_IsBool(json_);
}

bool Serializable::JSONWrapper::is_number_integer() const
{
    if (!cJSON_IsNumber(json_)) {
        return false;
    }
    auto value = cJSON_GetNumberValue(json_);
    return value == std::floor(value) && value >= std::numeric_limits<int64_t>::min() &&
        value <= std::numeric_limits<int64_t>::max();
}

bool Serializable::JSONWrapper::is_number_unsigned() const
{
    if (!cJSON_IsNumber(json_)) {
        return false;
    }
    auto value = cJSON_GetNumberValue(json_);
    return value == std::floor(value) && value >= 0 && value <= std::numeric_limits<uint64_t>::max();
}

bool Serializable::JSONWrapper::is_number_float() const
{
    if (!cJSON_IsNumber(json_)) {
        return false;
    }
    auto value = cJSON_GetNumberValue(json_);
    if (value == std::floor(value) && value >= std::numeric_limits<int64_t>::min() &&
                value <= std::numeric_limits<int64_t>::max()) {
        return false;
    }
    return true;
}

bool Serializable::JSONWrapper::is_string() const
{
    return cJSON_IsString(json_);
}

bool Serializable::JSONWrapper::is_array() const
{
    return cJSON_IsArray(json_);
}

bool Serializable::JSONWrapper::is_object() const
{
    return cJSON_IsObject(json_);
}

bool Serializable::JSONWrapper::is_discarded() const
{
    return json_ == nullptr;
}

bool Serializable::JSONWrapper::accept(const std::string &str)
{
    cJSON *json = cJSON_Parse(str.c_str());
    if (json == nullptr) {
        return false;
    }

    cJSON_Delete(json);
    return true;
}

bool Serializable::JSONWrapper::get_to(bool &values) const
{
    if (json_ == nullptr || !is_boolean()) {
        return false;
    }

    values = cJSON_IsTrue(json_) ? true : false;
    return true;
}

bool Serializable::JSONWrapper::get_to(int16_t &values) const
{
    if (json_ == nullptr || !is_number_integer()) {
        return false;
    }
    values = json_->valueint;
    return true;
}

bool Serializable::JSONWrapper::get_to(uint16_t &values) const
{
    if (json_ == nullptr || !is_number_unsigned()) {
        return false;
    }
    values = json_->valueint;
    return true;
}

bool Serializable::JSONWrapper::get_to(int32_t &values) const
{
    if (json_ == nullptr || !is_number_integer()) {
        return false;
    }
    values = json_->valueint;
    return true;
}

bool Serializable::JSONWrapper::get_to(uint32_t &values) const
{
    if (json_ == nullptr || !is_number_unsigned()) {
        return false;
    }
    double num = cJSON_GetNumberValue(json_);
    values = static_cast<uint32_t>(num);
    return true;
}

bool Serializable::JSONWrapper::get_to(int64_t &values) const
{
    if (json_ == nullptr || !is_number_integer()) {
        return false;
    }
    double num = cJSON_GetNumberValue(json_);
    values = static_cast<int64_t>(num);
    return true;
}

bool Serializable::JSONWrapper::get_to(uint64_t &values) const
{
    if (json_ == nullptr || !is_number_unsigned()) {
        return false;
    }
    double num = cJSON_GetNumberValue(json_);
    values = static_cast<uint64_t>(num);
    return true;
}

bool Serializable::JSONWrapper::get_to(double &values) const
{
    if (json_ == nullptr || !is_number_integer()) {
        return false;
    }
    values = cJSON_GetNumberValue(json_);
    return true;
}

bool Serializable::JSONWrapper::get_to(std::string &values) const
{
    if (json_ == nullptr || !is_string()) {
        return false;
    }
    values = cJSON_GetStringValue(json_);
    return true;
}

bool Serializable::JSONWrapper::get_to(std::vector<uint8_t> &values) const
{
    if (json_ == nullptr || !is_array()) {
        return false;
    }
    auto size = cJSON_GetArraySize(json_);
    values.clear();
    values.reserve(size);
    for (auto i = 0; i < size; i++) {
        auto item = cJSON_GetArrayItem(json_, i);
        if (item) {
            values.push_back(cJSON_GetNumberValue(item));
        }
    }
    return true;
}

size_t Serializable::JSONWrapper::size() const
{
    if (!cJSON_IsArray(json_) && !cJSON_IsObject(json_)) {
        return 0;
    }
    return cJSON_GetArraySize(json_);
}

std::string Serializable::JSONWrapper::dump() const
{
    if (json_ == nullptr) {
        return "";
    }
    char *str = cJSON_PrintUnformatted(json_);
    std::string res(str);
    cJSON_free(str);
    return res;
}

Serializable::iterator Serializable::JSONWrapper::find(const std::string &key) const
{
    int rawSize = cJSON_GetArraySize(json_);
    size_t size = (rawSize < 0) ? 0 : static_cast<size_t>(rawSize);
    auto len = children_.size();
    if (len != size) {
        children_.clear();
        for (int i = 0; i < size; i++) {
            auto item = cJSON_GetArrayItem(json_, i);
            children_.push_back(std::make_shared<JSONWrapper>(item, json_, item != nullptr ? item->string : ""));
        }
    }
    auto it = children_.begin();
    while (it != children_.end()) {
        if ((*it)->key_ == key) {
            return it;
        }
        ++it;
    }
    return it;
}

Serializable::iterator Serializable::JSONWrapper::begin() const
{
    if (json_ == nullptr || (!is_array() && !is_object())) {
        LOG_ERROR("not support.");
    }
    int rawSize = cJSON_GetArraySize(json_);
    size_t size = (rawSize < 0) ? 0 : static_cast<size_t>(rawSize);
    auto len = children_.size();
    if (len != size) {
        children_.clear();
        for (int i = 0; i < size; i++) {
            auto item = cJSON_GetArrayItem(json_, i);
            children_.push_back(std::make_shared<JSONWrapper>(item, json_, item != nullptr ? item->string : ""));
        }
    }
    return children_.begin();
}

Serializable::iterator Serializable::JSONWrapper::end() const
{
    if (json_ == nullptr || json_->child == nullptr || (!is_array() && !is_object())) {
        LOG_ERROR("not support.");
    }
    int rawSize = cJSON_GetArraySize(json_);
    size_t size = (rawSize < 0) ? 0 : static_cast<size_t>(rawSize);
    auto len = children_.size();
    if (len != size) {
        children_.clear();
        for (int i = 0; i < size; i++) {
            auto item = cJSON_GetArrayItem(json_, i);
            children_.push_back(std::make_shared<JSONWrapper>(item, json_, item != nullptr ? item->string : ""));
        }
    }
    return children_.end();
}

Serializable::JSONWrapper::~JSONWrapper()
{
    if (needDel_ && root_ == nullptr && json_ != nullptr) {
        cJSON_Delete(json_);
    }
}

Serializable::JSONWrapper Serializable::JSONWrapper::parse(const std::string &str)
{
    return Serializable::JSONWrapper(cJSON_Parse(str.c_str()), nullptr);
}

bool Serializable::JSONWrapper::operator==(int32_t value) const
{
    return value == cJSON_GetNumberValue(json_);
}

bool Serializable::JSONWrapper::operator==(const std::string &value) const
{
    return value == cJSON_GetStringValue(json_);
}

void Serializable::JSONWrapper::AddToRoot()
{
    if (!key_.empty()) {
        if (!cJSON_AddItemToObject(root_, key_.c_str(), json_)) {
            cJSON_Delete(json_);
            json_ = nullptr;
        } else {
            needDel_ = false;
        }
    } else {
        if (!cJSON_AddItemToArray(root_, json_)) {
            cJSON_Delete(json_);
            json_ = nullptr;
        } else {
            needDel_ = false;
        }
    }
}

Serializable::iterator::iterator(std::vector<std::shared_ptr<JSONWrapper>>::iterator it) : node_(it)
{
}

Serializable::iterator &Serializable::iterator::operator++()
{
    node_++;
    return *this;
}

bool Serializable::iterator::operator==(const Serializable::iterator &iter) const
{
    return node_ == iter.node_;
}

bool Serializable::iterator::operator!=(const Serializable::iterator &iter) const
{
    return !operator==(iter);
}

const Serializable::JSONWrapper &Serializable::iterator::operator*() const
{
    return **node_;
}

std::string Serializable::iterator::key() const
{
    return (*node_)->key_;
}

const Serializable::JSONWrapper &Serializable::iterator::value() const
{
    return operator*();
}

bool Serializable::JSONWrapper::empty() const
{
    if (json_ == nullptr) {
        return true;
    }
    if (cJSON_IsNull(json_)) {
        return true;
    }
    if (cJSON_IsArray(json_)) {
        return cJSON_GetArraySize(json_) == 0;
    }
    if (cJSON_IsObject(json_)) {
        int size = 0;
        cJSON *child = json_->child;
        while (child) {
            size++;
            child = child->next;
        }
        return size == 0;
    }
    return false;
}

std::string Serializable::JSONWrapper::to_string(const JSONWrapper &jsonWrapper)
{
    return jsonWrapper.dump();
}

std::vector<std::string> Serializable::JSONWrapper::Keys() const
{
    std::vector<std::string> keys;
    cJSON *item;
    cJSON *current = json_;
    cJSON_ArrayForEach(item, current) {
        auto *key = item->string;
        keys.emplace_back(key);
    }
    return keys;
}

bool Serializable::JSONWrapper::contains(const std::string &key) const
{
    if (json_ == nullptr || !is_object()) {
        return false;
    }
    return find(key) != end();
}
} // namespace OHOS
