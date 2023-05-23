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

#include "raw_data_parser.h"
#include "value_object.h"
namespace OHOS::NativeRdb {
size_t RawDataParser::ParserRawData(const uint8_t *data, size_t length, Asset &asset)
{
    size_t used = 0;
    if (used + sizeof(asset.version) > length) {
        return used;
    }
    std::vector<uint8_t> alignData;
    alignData.assign(data, data + sizeof(asset.version));
    asset.version = *(reinterpret_cast<decltype(&asset.version)>(alignData.data()));
    used += sizeof(asset.version);
    return used;
}

size_t RawDataParser::ParserRawData(const uint8_t *data, size_t length, Assets &assets)
{
    size_t used = 0;
    uint16_t num = 0;
    if (used + sizeof(num) > length) {
        return used;
    }
    std::vector<uint8_t> alignData;
    alignData.assign(data, data + sizeof(num));
    num = *(reinterpret_cast<decltype(&num)>(alignData.data()));
    used += sizeof(uint16_t);
    uint16_t count = 0;
    while (used < length && count < num) {
        Asset asset;
        auto dataLen = ParserRawData(&data[used], length - used, asset);
        if (dataLen == 0) {
            break;
        }
        used += dataLen;
        assets.push_back(std::move(asset));
        count++;
    }
    return used;
}

std::vector<uint8_t> RawDataParser::PackageRawData(const Asset &asset)
{
    std::vector<uint8_t> rawData;
    uint32_t version = asset.version;
    rawData.assign(reinterpret_cast<uint8_t *>(&version), reinterpret_cast<uint8_t *>(&version) + sizeof(version));
    return rawData;
}

std::vector<uint8_t> RawDataParser::PackageRawData(const Assets &assets)
{
    std::vector<uint8_t> rawData;
    uint16_t num = uint16_t(assets.size());
    rawData.assign(reinterpret_cast<uint8_t *>(&num), reinterpret_cast<uint8_t *>(&num)+ sizeof(num));
    for (auto &asset : assets) {
        auto data = PackageRawData(asset);
        rawData.insert(rawData.end(), data.begin(), data.end());
    }
    return rawData;
}
} // namespace OHOS::NativeRdb