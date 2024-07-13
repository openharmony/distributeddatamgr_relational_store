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

#include <chrono>

#include "multi_platform_endian.h"

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
    auto hostMagicWord = Endian::LeToH(*(reinterpret_cast<decltype(&ASSET_MAGIC)>(alignData.data())));
    if (hostMagicWord != ASSET_MAGIC) {
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
    auto hostMagicWord = Endian::LeToH(*(reinterpret_cast<decltype(&ASSETS_MAGIC)>(alignData.data())));
    if (hostMagicWord != ASSETS_MAGIC) {
        return 0;
    }

    if (sizeof(num) > length - used) {
        return 0;
    }
    alignData.assign(data, data + sizeof(num));
    num = Endian::LeToH(*(reinterpret_cast<decltype(&num)>(alignData.data())));
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
    uint16_t size = Endian::HToLe((uint16_t)data.length());
    auto leMagic = Endian::HToLe(ASSET_MAGIC);
    auto magicU8 = reinterpret_cast<uint8_t *>(const_cast<uint32_t *>(&leMagic));
    rawData.insert(rawData.end(), magicU8, magicU8 + sizeof(ASSET_MAGIC));
    rawData.insert(rawData.end(), reinterpret_cast<uint8_t *>(&size),
        reinterpret_cast<uint8_t *>(&size) + sizeof(size));
    rawData.insert(rawData.end(), data.begin(), data.end());
    return rawData;
}

std::vector<uint8_t> RawDataParser::PackageRawData(const Assets &assets)
{
    std::vector<uint8_t> rawData;
    uint16_t num = uint16_t(assets.size());
    auto leMagic = Endian::HToLe(ASSETS_MAGIC);
    auto magicU8 = reinterpret_cast<uint8_t *>(const_cast<uint32_t *>(&leMagic));
    rawData.insert(rawData.end(), magicU8, magicU8 + sizeof(ASSETS_MAGIC));
    rawData.insert(rawData.end(), reinterpret_cast<uint8_t *>(&num), reinterpret_cast<uint8_t *>(&num) + sizeof(num));
    for (auto &asset : assets) {
        auto data = PackageRawData(asset);
        rawData.insert(rawData.end(), data.begin(), data.end());
    }
    return rawData;
}

size_t RawDataParser::ParserRawData(const uint8_t *data, size_t length, std::map<std::string, Asset> &assets)
{
    Assets res;
    auto used = ParserRawData(data, length, res);
    auto it = res.begin();
    while (it != res.end()) {
        assets.insert({ it->name, *it });
        it++;
    }
    return used;
}

size_t RawDataParser::ParserRawData(const uint8_t* data, size_t length, BigInteger& bigint)
{
    size_t used = 0;
    if (sizeof(BIG_INT) > length - used) {
        return 0;
    }
    auto magic = Endian::LeToH(*(reinterpret_cast<decltype(&BIG_INT)>(data)));
    used += sizeof(BIG_INT);
    if (magic != BIG_INT) {
        return 0;
    }

    if (sizeof(uint32_t) > length - used) {
        return 0;
    }
    uint32_t sign = Endian::LeToH(*(reinterpret_cast<const uint32_t *>(data + used)));
    used += sizeof(uint32_t);

    if (sizeof(uint64_t) > length - used) {
        return 0;
    }
    uint64_t count = Endian::LeToH(*(reinterpret_cast<const uint64_t *>(data + used)));
    used += sizeof(uint64_t);

    if (sizeof(uint64_t) * count > length - used) {
        return 0;
    }
    const uint64_t *temp = (reinterpret_cast<const uint64_t *>(data + used));
    std::vector<uint64_t> trueFrom(temp, temp + count);
    used += sizeof(uint64_t) * count;
    for (size_t i = 0; i < trueFrom.size(); ++i) {
        trueFrom[i] = Endian::LeToH(trueFrom[i]);
    }
    bigint = BigInteger(static_cast<int32_t>(sign), std::move(trueFrom));
    return used;
}

size_t RawDataParser::ParserRawData(const uint8_t* data, size_t length, RawDataParser::Floats& floats)
{
    size_t used = 0;
    if (sizeof(FLOUT32_ARRAY) > length - used) {
        return 0;
    }
    auto magic = Endian::LeToH(*(reinterpret_cast<decltype(&FLOUT32_ARRAY)>(data)));
    used += sizeof(FLOUT32_ARRAY);
    if (magic != FLOUT32_ARRAY) {
        return 0;
    }

    if (sizeof(uint32_t) > length - used) {
        return 0;
    }

    uint32_t count = Endian::LeToH(*(reinterpret_cast<const uint32_t *>(data + used)));
    used += sizeof(uint32_t);

    if (sizeof(float) * count > length - used) {
        return 0;
    }
    auto values = reinterpret_cast<const float *>(data + used);
    floats.assign(values, values + count);
    used += sizeof(float) * count;
    return used;
}

std::vector<uint8_t> RawDataParser::PackageRawData(const std::map<std::string, Asset> &assets)
{
    Assets res;
    for (auto asset : assets) {
        res.push_back(asset.second);
    }
    return PackageRawData(res);
}

std::vector<uint8_t> RawDataParser::PackageRawData(const BigInteger& bigint)
{
    size_t offset = 0;
    auto size = sizeof(BIG_INT) + sizeof(uint32_t) + sizeof(uint64_t) * (bigint.Size() + 1);
    std::vector<uint8_t> rawData(size, 0);
    uint8_t* data = rawData.data();
    *(reinterpret_cast<uint32_t *>(&data[offset])) = Endian::HToLe(BIG_INT);
    offset += sizeof(BIG_INT);
    *(reinterpret_cast<uint32_t *>(&data[offset])) = Endian::HToLe(uint32_t(bigint.Sign()));
    offset += sizeof(uint32_t);
    *(reinterpret_cast<uint64_t *>(&data[offset])) = Endian::HToLe(uint64_t(bigint.Size()));
    offset += sizeof(uint64_t);
    auto trueForm = bigint.TrueForm();
    if (trueForm == nullptr) {
        return {};
    }
    for (size_t i = 0; i < bigint.Size(); ++i) {
        *(reinterpret_cast<uint64_t *>(&data[offset])) = Endian::HToLe(trueForm[i]);
        offset += sizeof(uint64_t);
    }
    return rawData;
}

std::vector<uint8_t> RawDataParser::PackageRawData(const RawDataParser::Floats& floats)
{
    size_t offset = 0;
    auto size = sizeof(FLOUT32_ARRAY) + sizeof(uint32_t) + sizeof(float) * floats.size();
    std::vector<uint8_t> rawData(size, 0);
    uint8_t* data = rawData.data();
    *(reinterpret_cast<uint32_t *>(&data[offset])) = Endian::HToLe(FLOUT32_ARRAY);
    offset += sizeof(FLOUT32_ARRAY);
    *(reinterpret_cast<uint32_t *>(&data[offset])) = Endian::HToLe(uint32_t(floats.size()));
    offset += sizeof(uint32_t);
    for (size_t i = 0; i < floats.size(); ++i) {
        *(reinterpret_cast<float *>(&data[offset])) = floats[i];
        offset += sizeof(float);
    }
    return rawData;
}

bool RawDataParser::InnerAsset::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(version)], asset_.version);
    SetValue(node[GET_NAME(expiresTime)], asset_.expiresTime);
    SetValue(node[GET_NAME(id)], asset_.id);
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
    bool ret = true;
    ret = GetValue(node, GET_NAME(version), asset_.version) && ret;
    ret = GetValue(node, GET_NAME(expiresTime), asset_.expiresTime) && ret;
    ret = GetValue(node, GET_NAME(id), asset_.id) && ret;
    ret = GetValue(node, GET_NAME(name), asset_.name) && ret;
    ret = GetValue(node, GET_NAME(uri), asset_.uri) && ret;
    ret = GetValue(node, GET_NAME(createTime), asset_.createTime) && ret;
    ret = GetValue(node, GET_NAME(modifyTime), asset_.modifyTime) && ret;
    ret = GetValue(node, GET_NAME(size), asset_.size) && ret;
    ret = GetValue(node, GET_NAME(hash), asset_.hash) && ret;
    ret = GetValue(node, GET_NAME(path), asset_.path) && ret;
    ret = GetValue(node, GET_NAME(status), asset_.status) && ret;
    if (asset_.status == AssetValue::STATUS_DOWNLOADING &&
        asset_.expiresTime < static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch().count())) {
        asset_.status = AssetValue::STATUS_ABNORMAL;
    }
    return ret;
}
} // namespace OHOS::NativeRdb