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
#include "multi_platform_endian.h"
namespace OHOS::NativeRdb {
using Serializable = AppDataFwk::Serializable;
size_t RawDataParser::ParserRawData(const uint8_t *data, size_t length, Asset &asset)
{
    size_t used = 0;
    uint16_t size = 0;
    if (used + sizeof(size) > length) {
        return used;
    }
    std::vector<uint8_t> alignData;
    alignData.assign(data, data + sizeof(size));
    size = AppDataFwk::Endian::Le16toh(*(reinterpret_cast<decltype(&size)>(alignData.data())));
    if (used + size > length) {
        return used;
    }
    used += sizeof(size);

    auto rawData = std::string((char *)(&data[sizeof(uint16_t)]), size);
    InnerAsset innerAsset = InnerAsset(asset);
    innerAsset.Unmarshall(rawData);
    used += size;
    asset = std::move(innerAsset.asset_);
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
    InnerAsset innerAsset = InnerAsset(asset);
    auto data = Serializable::Marshall(innerAsset);
    uint16_t size;
    size = AppDataFwk::Endian::Htole16((uint16_t)data.length());
    rawData.assign(reinterpret_cast<uint8_t *>(&size), reinterpret_cast<uint8_t *>(&size) + sizeof(size));
    rawData.insert(rawData.end(), data.begin(), data.end());
    return rawData;
}

std::vector<uint8_t> RawDataParser::PackageRawData(const Assets &assets)
{
    std::vector<uint8_t> rawData;
    uint16_t num = uint16_t(assets.size());
    rawData.assign(reinterpret_cast<uint8_t *>(&num), reinterpret_cast<uint8_t *>(&num) + sizeof(num));
    for (auto &asset : assets) {
        auto data = PackageRawData(asset);
        rawData.insert(rawData.end(), data.begin(), data.end());
    }
    return rawData;
}

bool RawDataParser::InnerAsset::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(version)], asset_.version);
    SetValue(node[GET_NAME(name)], asset_.name);
    SetValue(node[GET_NAME(uri)], asset_.uri);
    SetValue(node[GET_NAME(createTime)], asset_.createTime);
    SetValue(node[GET_NAME(modifyTime)], asset_.modifyTime);
    SetValue(node[GET_NAME(size)], asset_.size);
    SetValue(node[GET_NAME(hash)], asset_.hash);
    SetValue(node[GET_NAME(path)], asset_.path);
    SetValue(node[GET_NAME(status)], asset_.status);
    return true;
}
bool RawDataParser::InnerAsset::Unmarshal(const Serializable::json &node)
{
    GetValue(node, GET_NAME(version), asset_.version);
    GetValue(node, GET_NAME(name), asset_.name);
    GetValue(node, GET_NAME(uri), asset_.uri);
    GetValue(node, GET_NAME(createTime), asset_.createTime);
    GetValue(node, GET_NAME(modifyTime), asset_.modifyTime);
    GetValue(node, GET_NAME(size), asset_.size);
    GetValue(node, GET_NAME(hash), asset_.hash);
    GetValue(node, GET_NAME(path), asset_.path);
    GetValue(node, GET_NAME(status), asset_.status);
    return true;
}
} // namespace OHOS::NativeRdb