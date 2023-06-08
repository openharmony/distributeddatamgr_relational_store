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

#ifndef DATA_PROPERTIES_H
#define DATA_PROPERTIES_H

#include "serializable.h"
namespace OHOS::RdbBMSAdapter {
struct API_EXPORT DataProperties : public Serializable {
    virtual ~DataProperties() = default;
    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;
    static const std::string MODULE_SCOPE;
    static const std::string APPLICATION_SCOPE;
    static const std::string RDB_TYPE;
    static const std::string PUBLISHED_DATA_TYPE;
    std::string storeName;
    std::string tableName;
    std::string scope = MODULE_SCOPE;
    std::string type = RDB_TYPE;
};
} // namespace OHOS::DataShare
#endif //DATA_PROPERTIES_H
