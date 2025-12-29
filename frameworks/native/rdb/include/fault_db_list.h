/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FAULT_DB_LIST_H
#define FAULT_DB_LIST_H
#include <string>
#include <mutex>

#include "serializable.h"
namespace OHOS {
namespace NativeRdb {
 
class FaultDBList {
public:
    static FaultDBList &GetInstance();
    bool Contain(const std::string &storeName);
    std::string GetCallingName();
private:
    struct DBList final : public Serializable {
        std::string callingName;
        std::string storeName;
        bool Marshal(json &node) const override;
        bool Unmarshal(const json &node) override;
    };
 
    FaultDBList() = default;
    ~FaultDBList() = default;
    bool isInitialized_ = false;
    mutable std::mutex initMutex_;
    std::string callingName_;
    std::string storeName_;
};

} // namespace NativeRdb
} // namespace OHOS
#endif // FAULT_DB_LIST_H