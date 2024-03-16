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

#ifndef OHOS_COMMON_TYPES_H
#define OHOS_COMMON_TYPES_H
#include <map>
#include <string>
#include <variant>
#include <vector>
namespace OHOS::CommonType {
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
};
using Bytes = std::vector<uint8_t>;
using Asset = AssetValue;
using Assets = std::vector<AssetValue>;
using Value = std::variant<std::monostate, int64_t, double, std::string, bool, Bytes, Asset, Assets>;
using ValuesBucket = std::map<std::string, Value>;
}
#endif // OHOS_COMMON_TYPES_H
