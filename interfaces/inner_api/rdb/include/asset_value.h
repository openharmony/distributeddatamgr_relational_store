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

#ifndef OHOS_RELATIONAL_STORE_INNER_API_ASSET_VALUE_H
#define OHOS_RELATIONAL_STORE_INNER_API_ASSET_VALUE_H
#include <string>
namespace OHOS::NativeRdb {
struct AssetValue {
    enum Status : int32_t {
        STATUS_UNKNOWN,
        STATUS_NORMAL,
        STATUS_INSERT,
        STATUS_UPDATE,
        STATUS_DELETE,
        STATUS_ABNORMAL,
        STATUS_DOWNLOADING,
        STATUS_BUTT
    };
    static constexpr uint64_t NO_EXPIRES_TIME = 0;
    uint32_t version = 0;
    mutable uint32_t status = STATUS_UNKNOWN;
    uint64_t expiresTime = NO_EXPIRES_TIME;
    std::string id;
    std::string name;
    std::string uri;
    std::string createTime;
    std::string modifyTime;
    std::string size;
    std::string hash;
    std::string path;

    bool operator<(const AssetValue &ref) const
    {
        if (name != ref.name) {
            return name < ref.name;
        }
        if (status != ref.status) {
            return status < ref.status;
        }
        if (id != ref.id) {
            return id < ref.id;
        }
        if (uri != ref.uri) {
            return uri < ref.uri;
        }
        if (createTime != ref.createTime) {
            return createTime < ref.createTime;
        }
        if (modifyTime != ref.modifyTime) {
            return modifyTime < ref.modifyTime;
        }
        if (size != ref.size) {
            return size < ref.size;
        }
        if (hash != ref.hash) {
            return hash < ref.hash;
        }
        return path < ref.path;
    }
};
} // namespace OHOS::NativeRdb
#endif // OHOS_RELATIONAL_STORE_INNER_API_ASSET_VALUE_H
