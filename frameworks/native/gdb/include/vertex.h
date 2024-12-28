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

#ifndef NATIVE_GDB_GRAPH_VERTEX_H
#define NATIVE_GDB_GRAPH_VERTEX_H
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "nlohmann/json.hpp"

namespace OHOS::DistributedDataAip {
using PropType = std::variant<int64_t, double, std::string, bool, std::nullptr_t>;
class Vertex {
public:
    Vertex();
    Vertex(std::string id, std::string label);
    Vertex(std::string id, std::string label, const std::unordered_map<std::string, PropType> &properties);
    static std::shared_ptr<Vertex> Parse(const nlohmann::json &json, int32_t &errCode);

    std::string GetId() const;
    void SetId(std::string id);

    const std::string &GetLabel() const;
    const std::vector<std::string> &GetLabels() const;
    void SetLabel(const std::string &label);

    const std::unordered_map<std::string, PropType> &GetProperties() const;
    void SetProperty(const std::string &key, PropType value);

    static constexpr const char *ID = "identity";
    static constexpr const char *LABEL = "label";
    static constexpr const char *PROPERTIES = "properties";

protected:
    std::string id_;
    std::string label_;
    std::vector<std::string> labels_;
    std::unordered_map<std::string, PropType> properties_;
};
} // namespace OHOS::DistributedDataAip
#endif //NATIVE_GDB_GRAPH_VERTEX_H
