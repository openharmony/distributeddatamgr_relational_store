/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_SILENT_PROXY_H
#define NATIVE_RDB_SILENT_PROXY_H

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "lru_bucket.h"
#include "serializable.h"

namespace OHOS {
namespace NativeRdb {
struct SilentProxy final : public Serializable {
    std::string bundleName;
    std::vector<std::string> storeNames;
    bool Marshal(Serializable::json &node) const override;
    bool Unmarshal(const Serializable::json &node) override;
};

struct SilentProxys final : public Serializable {
    std::vector<SilentProxy> silentProxys{};
    bool Marshal(Serializable::json &node) const override;
    bool Unmarshal(const Serializable::json &node) override;
};

class SilentProxyManager {
public:
    explicit SilentProxyManager(const std::string &configPath = "");
    ~SilentProxyManager() = default;

    std::pair<int32_t, bool> IsSupportSilent(const std::string &bundleName, const std::string &storeName);

private:
    std::pair<int32_t, bool> IsSupportSilentFromProxy(const std::string &bundleName, const std::string &storeName);
    std::pair<int32_t, bool> IsSupportSilentFromService(const std::string &bundleName, const std::string &storeName);

    std::string configPath_;
    std::mutex mutex_;
    LRUBucket<std::string, std::map<std::string, bool>> isSilentCache_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif
