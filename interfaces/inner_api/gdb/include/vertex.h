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

#ifndef OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_GRAPH_VERTEX_H
#define OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_GRAPH_VERTEX_H
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "rdb_visibility.h"
#include "serializable.h"

namespace OHOS::DistributedDataAip {
using PropType = std::variant<int64_t, double, std::string, bool, std::nullptr_t>;
class Vertex final : public Serializable {
public:
    API_EXPORT Vertex();
    API_EXPORT virtual ~Vertex() = default;
    API_EXPORT Vertex(std::string id, std::string label);
    API_EXPORT Vertex(std::string id, std::string label, const std::unordered_map<std::string, PropType> &properties);
    static std::shared_ptr<Vertex> Parse(const std::string &jsonStr, int32_t &errCode);

    API_EXPORT std::string GetId() const;
    API_EXPORT void SetId(std::string id);

    API_EXPORT const std::string &GetLabel() const;
    API_EXPORT const std::vector<std::string> &GetLabels();
    API_EXPORT void SetLabel(const std::string &label);

    API_EXPORT const std::unordered_map<std::string, PropType> &GetProperties() const;
    API_EXPORT void SetProperty(const std::string &key, PropType value);

    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;
    static bool GetPropsValue(const json &node, const std::string &name, std::unordered_map<std::string, PropType> &props);
    static bool GetID(const json &node, const std::string &name, std::string &id);

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
#endif //OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_GRAPH_VERTEX_H
