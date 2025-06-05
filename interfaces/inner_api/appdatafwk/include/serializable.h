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

#ifndef DISTRIBUTED_RDB_SERIALIZABLE_H
#define DISTRIBUTED_RDB_SERIALIZABLE_H
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include "rdb_visibility.h"
#ifndef JSON_NOEXCEPTION
#define JSON_NOEXCEPTION
#endif
struct cJSON;
namespace OHOS {
#ifndef GET_NAME
#define GET_NAME(value) #value
#endif
struct Serializable {
public:
    class iterator;
    class JSONWrapper final {
    public:
        friend iterator;
        enum class Type : uint8_t {
            ARRAY,
            OBJECT,
        };
        API_EXPORT JSONWrapper();
        JSONWrapper(cJSON *json, cJSON *root, const std::string &key = "");
        JSONWrapper(const std::string &jsonStr);
        JSONWrapper(JSONWrapper &&jsonWrapper);

        operator std::string() const;
        bool operator==(int32_t value) const;
        bool operator==(const std::string &value) const;

        JSONWrapper &operator=(JSONWrapper &&jsonWrapper);
        JSONWrapper &operator=(bool value);
        JSONWrapper &operator=(int32_t value);
        JSONWrapper &operator=(uint32_t value);
        JSONWrapper &operator=(int64_t value);
        JSONWrapper &operator=(uint64_t value);
        JSONWrapper &operator=(double value);
        JSONWrapper &operator=(const char *value);
        JSONWrapper &operator=(const std::string &value);
        JSONWrapper &operator=(const std::vector<uint8_t> &value);
        API_EXPORT JSONWrapper &operator=(JSONWrapper::Type type);
        API_EXPORT JSONWrapper &operator[](const std::string &key);
        API_EXPORT JSONWrapper &operator[](size_t index);
        API_EXPORT JSONWrapper &operator[](size_t index) const;

        API_EXPORT bool is_null() const;
        API_EXPORT bool is_boolean() const;
        API_EXPORT bool is_number_integer() const;
        API_EXPORT bool is_number_unsigned() const;
        API_EXPORT bool is_number_float() const;
        API_EXPORT bool is_string() const;
        API_EXPORT bool is_array() const;
        API_EXPORT bool is_object() const;
        API_EXPORT bool is_discarded() const;

        API_EXPORT bool get_to(bool &values) const;
        API_EXPORT bool get_to(int16_t &values) const;
        API_EXPORT bool get_to(uint16_t &values) const;
        API_EXPORT bool get_to(int32_t &values) const;
        API_EXPORT bool get_to(uint32_t &values) const;
        API_EXPORT bool get_to(int64_t &values) const;
        API_EXPORT bool get_to(uint64_t &values) const;
        API_EXPORT bool get_to(double &values) const;
        API_EXPORT bool get_to(std::string &values) const;
        API_EXPORT bool get_to(std::vector<uint8_t> &values) const;
        API_EXPORT size_t size() const;
        API_EXPORT std::string dump() const;
        API_EXPORT bool contains(const std::string &key) const;
        API_EXPORT iterator find(const std::string &key) const;
        API_EXPORT iterator begin() const;
        API_EXPORT iterator end() const;
        API_EXPORT ~JSONWrapper();
        API_EXPORT static JSONWrapper parse(const std::string &str);
        static bool accept(const std::string &str);

        API_EXPORT bool empty() const;
        API_EXPORT static std::string to_string(const JSONWrapper &jsonWrapper);
        API_EXPORT std::vector<std::string> Keys() const;
    private:
        void AddToRoot();
        JSONWrapper(const JSONWrapper &jsonWrapper) = delete;
        JSONWrapper &operator=(const JSONWrapper &jsonWrapper) = delete;
        cJSON *json_ = nullptr;
        cJSON *root_ = nullptr;
        std::string key_;
        bool needDel_ = false;
        mutable std::vector<std::shared_ptr<JSONWrapper>> children_;
    };
    class iterator {
    public:
        iterator(std::vector<std::shared_ptr<JSONWrapper>>::iterator it);
        API_EXPORT iterator &operator++();
        API_EXPORT bool operator==(const iterator &iter) const;
        API_EXPORT bool operator!=(const iterator &iter) const;
        API_EXPORT const JSONWrapper &operator*() const;
        API_EXPORT std::string key() const;
        API_EXPORT const JSONWrapper &value() const;

    private:
        std::vector<std::shared_ptr<JSONWrapper>>::iterator node_;
    };
    using json = JSONWrapper;
    API_EXPORT json Marshall() const;
    template<typename T>
    static std::string Marshall(T &values)
    {
        json root;
        SetValue(root, values);
        return root.dump();
    }

    API_EXPORT bool Unmarshall(const std::string &jsonStr);
    template<typename T>
    static bool Unmarshall(const std::string &body, T &values)
    {
        return GetValue(ToJson(body), "", values);
    }
    API_EXPORT static json ToJson(const std::string &jsonStr);
    API_EXPORT static bool IsJson(const std::string &jsonStr);
    virtual bool Marshal(json &node) const = 0;
    virtual bool Unmarshal(const json &node) = 0;
    API_EXPORT static bool GetValue(const json &node, const std::string &name, std::string &value);
    API_EXPORT static bool GetValue(const json &node, const std::string &name, uint32_t &value);
    API_EXPORT static bool GetValue(const json &node, const std::string &name, int32_t &value);
    API_EXPORT static bool GetValue(const json &node, const std::string &name, int64_t &value);
    API_EXPORT static bool GetValue(const json &node, const std::string &name, uint64_t &value);
    API_EXPORT static bool GetValue(const json &node, const std::string &name, bool &value);
    API_EXPORT static bool GetValue(const json &node, const std::string &name, std::vector<uint8_t> &value);
    API_EXPORT static bool GetValue(const json &node, const std::string &name, Serializable &value);
    API_EXPORT static bool GetValue(const json &node, const std::string &name, std::shared_ptr<Serializable> value);
    API_EXPORT static bool SetValue(json &node, const std::string &value);
    API_EXPORT static bool SetValue(json &node, const uint32_t &value);
    API_EXPORT static bool SetValue(json &node, const int32_t &value);
    API_EXPORT static bool SetValue(json &node, const int64_t &value);
    API_EXPORT static bool SetValue(json &node, const uint64_t &value);
    API_EXPORT static bool SetValue(json &node, const bool &value);
    API_EXPORT static bool SetValue(json &node, const std::vector<uint8_t> &value);
    API_EXPORT static bool SetValue(json &node, const Serializable &value);

protected:
    API_EXPORT ~Serializable() = default;

    template<typename T>
    static bool GetValue(const json &node, const std::string &name, T *&value)
    {
        auto &subNode = GetSubNode(node, name);
        if (subNode.is_null()) {
            return false;
        }
        value = new (std::nothrow) T();
        if (value == nullptr) {
            return false;
        }
        bool result = GetValue(subNode, "", *value);
        if (!result) {
            delete value;
            value = nullptr;
        }
        return result;
    }
    template<typename T>
    static bool GetValue(const json &node, const std::string &name, std::vector<T> &values)
    {
        auto &subNode = GetSubNode(node, name);
        if (subNode.is_null() || !subNode.is_array()) {
            return false;
        }
        bool result = true;
        auto size = subNode.size();
        values.resize(size);
        for (size_t i = 0; i < size; ++i) {
            result = GetValue(subNode[i], "", values[i]) && result;
        }
        return result;
    }

    template<typename T>
    static bool GetValue(const json &node, const std::string &name, std::vector<std::shared_ptr<T>> &values)
    {
        auto &subNode = GetSubNode(node, name);
        if (subNode.is_null() || !subNode.is_array()) {
            return false;
        }
        bool result = true;
        auto size = subNode.size();
        values.resize(size);
        for (size_t i = 0; i < size; ++i) {
            if (values[i] == nullptr) {
                values[i] = std::make_shared<T>();
            }
            result = GetValue(subNode[i], "", values[i]) && result;
        }
        return result;
    }

    template<typename T>
    static bool SetValue(json &node, const std::vector<T> &values)
    {
        bool result = true;
        size_t i = 0;
        node = JSONWrapper::Type::ARRAY;
        for (const auto &value : values) {
            result = SetValue(node[i], value) && result;
            i++;
        }
        return result;
    }

    template<typename T>
    static bool GetValue(const json &node, const std::string &name, std::unordered_map<std::string, T> &values)
    {
        auto &subNode = GetSubNode(node, name);
        if (subNode.is_null() || !subNode.is_object()) {
            return false;
        }
        bool result = true;
        for (auto object = subNode.begin(); object != subNode.end(); ++object) {
            result = GetValue(object.value(), "", values[object.key()]) && result;
        }
        return result;
    }

    template<typename T>
    static bool SetValue(json &node, const std::unordered_map<std::string, T> &values)
    {
        bool result = true;
        node = JSONWrapper::Type::OBJECT;
        for (const auto& kv : values) {
            result = SetValue(node[kv.first], kv.second) && result;
        }
        return result;
    }
    API_EXPORT static const json &GetSubNode(const json &node, const std::string &name);
};
} // namespace OHOS
#endif // DISTRIBUTED_RDB_SERIALIZABLE_H
