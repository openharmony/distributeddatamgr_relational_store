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

#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_PARSER_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_PARSER_H

#include "serializable.h"
#include "traits.h"
#include "value_object.h"
namespace OHOS::NativeRdb {
class RawDataParser final {
public:
    using Asset = ValueObject::Asset;
    using Assets = ValueObject::Assets;
    using Floats = ValueObject::FloatVector;
    template<typename T, typename... Rest>
    static bool Convert(T input, std::variant<Rest...> &output);

    static size_t ParserRawData(const uint8_t *data, size_t length, Asset &asset);
    static size_t ParserRawData(const uint8_t *data, size_t length, Assets &assets);
    static size_t ParserRawData(const uint8_t *data, size_t length, std::map<std::string, Asset> &assets);
    static size_t ParserRawData(const uint8_t *data, size_t length, BigInteger &bigint);
    static size_t ParserRawData(const uint8_t *data, size_t length, Floats &floats);

    static std::vector<uint8_t> PackageRawData(const Asset &asset);
    static std::vector<uint8_t> PackageRawData(const Assets &assets);
    static std::vector<uint8_t> PackageRawData(const std::map<std::string, Asset> &assets);
    static std::vector<uint8_t> PackageRawData(const BigInteger &bigint);
    static std::vector<uint8_t> PackageRawData(const Floats &floats);

private:
    struct InnerAsset : public Serializable {
        Asset &asset_;
        explicit InnerAsset(Asset &asset) : asset_(asset) {}

        bool Marshal(json &node) const override;
        bool Unmarshal(const json &node) override;
    };

    template<typename T, typename O>
    static bool Get(T &&input, O &output)
    {
        return false;
    }

    template<typename T, typename O, typename First, typename... Rest>
    static bool Get(T &&input, O &output)
    {
        auto *val = Traits::get_if<First>(&input);
        if (val != nullptr) {
            output = std::move(*val);
            return true;
        }
        return Get<T, O, Rest...>(std::move(input), output);
    }

    static constexpr const uint32_t ASSET_MAGIC = 0x41534554;
    static constexpr const uint32_t ASSETS_MAGIC = 0x41534553;
    static constexpr const uint32_t FLOUT32_ARRAY = 0x46333241;
    static constexpr const uint32_t BIG_INT = 0x42494749;
};

template<typename T, typename... Rest>
bool RawDataParser::Convert(T input, std::variant<Rest...> &output)
{
    return Get<T, decltype(output), Rest...>(std::move(input), output);
}
}

#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_PARSER_H
