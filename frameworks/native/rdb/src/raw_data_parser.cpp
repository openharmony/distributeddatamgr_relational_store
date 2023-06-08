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

#define UNMARSHAL_RETURN_ERR(theCall) \
    do {                              \
        if (!theCall) {               \
            return false;             \
        }                             \
    } while (0)

namespace OHOS::NativeRdb {
size_t RawDataParser::ParserRawData(const uint8_t *data, size_t length, Asset &asset)
{
    size_t used = 0;
    uint16_t size = 0;

    if (sizeof(ASSET_MAGIC) > length - used) {
        return 0;
    }
    std::vector<uint8_t> alignData;
    alignData.assign(data, data + sizeof(ASSET_MAGIC));
    used += sizeof(ASSET_MAGIC);
    if (*(reinterpret_cast<decltype(&ASSET_MAGIC)>(alignData.data())) != ASSET_MAGIC) {
        return 0;
    }

    if (sizeof(size) > length - used) {
        return 0;
    }
    alignData.assign(data + used, data + used + sizeof(size));
    used += sizeof(size);
    size = Endian::LeToH(*(reinterpret_cast<decltype(&size)>(alignData.data())));

    if (size > length - used) {
        return 0;
    }
    auto rawData = std::string(reinterpret_cast<const char *>(&data[used]), size);
    InnerAsset innerAsset = InnerAsset(asset);
    if (!innerAsset.Unmarshall(rawData)) {
        return 0;
    }
    used += size;
    return used;
}

size_t RawDataParser::ParserRawData(const uint8_t *data, size_t length, Assets &assets)
{
    size_t used = 0;
    uint16_t num = 0;

    if (sizeof(ASSETS_MAGIC) > length - used) {
        return 0;
    }
    std::vector<uint8_t> alignData;
    alignData.assign(data, data + sizeof (ASSETS_MAGIC));
    used += sizeof (ASSETS_MAGIC);
    if (*(reinterpret_cast<decltype(&ASSETS_MAGIC)>(alignData.data())) != ASSETS_MAGIC) {
        return 0;
    }

    if (sizeof(num) > length - used) {
        return 0;
    }
    alignData.assign(data, data + sizeof(num));
    num = *(reinterpret_cast<decltype(&num)>(alignData.data()));
    used += sizeof(num);
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
    InnerAsset innerAsset(const_cast<Asset &>(asset));
    auto data = Serializable::Marshall(innerAsset);
    uint16_t size;
    size = Endian::HToLe((uint16_t)data.length());
    auto magicU8 = reinterpret_cast<uint8_t *>(const_cast<uint32_t *>(&ASSET_MAGIC));
    rawData.insert(rawData.end(), magicU8, magicU8 + sizeof(ASSET_MAGIC));
    rawData.insert(rawData.end(), reinterpret_cast<uint8_t *>(&size), reinterpret_cast<uint8_t *>(&size) + sizeof(size));
    rawData.insert(rawData.end(), data.begin(), data.end());
    return rawData;
}

std::vector<uint8_t> RawDataParser::PackageRawData(const Assets &assets)
{
    std::vector<uint8_t> rawData;
    uint16_t num = uint16_t(assets.size());
    auto magicU8 = reinterpret_cast<uint8_t *>(const_cast<uint32_t *>(&ASSETS_MAGIC));
    rawData.insert(rawData.end(), magicU8, magicU8 + sizeof(ASSETS_MAGIC));
    rawData.insert(rawData.end(), reinterpret_cast<uint8_t *>(&num), reinterpret_cast<uint8_t *>(&num) + sizeof(num));
    for (auto &asset : assets) {
        auto data = PackageRawData(asset);
        rawData.insert(rawData.end(), data.begin(), data.end());
    }
    return rawData;
}

bool RawDataParser::InnerAsset::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(version)], asset_.version);
    SetValue(node[GET_NAME(status)], asset_.status);
    SetValue(node[GET_NAME(timeStamp)], asset_.timeStamp);
    SetValue(node[GET_NAME(name)], asset_.name);
    SetValue(node[GET_NAME(uri)], asset_.uri);
    SetValue(node[GET_NAME(createTime)], asset_.createTime);
    SetValue(node[GET_NAME(modifyTime)], asset_.modifyTime);
    SetValue(node[GET_NAME(size)], asset_.size);
    SetValue(node[GET_NAME(hash)], asset_.hash);
    SetValue(node[GET_NAME(path)], asset_.path);
    return true;
}
bool RawDataParser::InnerAsset::Unmarshal(const Serializable::json &node)
{
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(version), asset_.version));
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(status), asset_.status));
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(timeStamp), asset_.timeStamp));
    if (asset_.status == AssetValue::STATUS_DOWNLOADING &&
        std::chrono::time_point<std::chrono::steady_clock>(std::chrono::milliseconds(asset_.timeStamp)) >
            std::chrono::steady_clock::now()) {
        asset_.status = AssetValue::STATUS_ABNORMAL;
    }
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(name), asset_.name));
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(uri), asset_.uri));
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(createTime), asset_.createTime));
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(modifyTime), asset_.modifyTime));
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(size), asset_.size));
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(hash), asset_.hash));
    UNMARSHAL_RETURN_ERR(GetValue(node, GET_NAME(path), asset_.path));
    return true;
}
} // namespace OHOS::NativeRdb