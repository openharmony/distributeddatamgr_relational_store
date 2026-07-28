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

#include "rdb_values_bucket_types_util.h"

namespace OHOS::ITypesUtil {
template<>
bool Marshalling(const NativeRdb::AssetValue &input, MessageParcel &data)
{
    return Marshal(data, input.version, input.name, input.size, input.modifyTime, input.uri);
}

template<>
bool Unmarshalling(NativeRdb::AssetValue &output, MessageParcel &data)
{
    return Unmarshal(data, output.version, output.name, output.size, output.modifyTime, output.uri);
}

template<>
bool Marshalling(const NativeRdb::BigInteger &input, MessageParcel &data)
{
    return Marshal(data, input.Sign(), input.Value());
}

template<>
bool Unmarshalling(NativeRdb::BigInteger &output, MessageParcel &data)
{
    int32_t sign = 0;
    std::vector<uint64_t> value;
    if (!Unmarshal(data, sign, value)) {
        return false;
    }
    output = NativeRdb::BigInteger(sign, std::move(value));
    return true;
}

template<>
bool Marshalling(const NativeRdb::ValueObject &input, MessageParcel &data)
{
    return Marshal(data, input.value);
}

template<>
bool Unmarshalling(NativeRdb::ValueObject &output, MessageParcel &data)
{
    return Unmarshal(data, output.value);
}

template<>
bool Marshalling(const NativeRdb::ValuesBucket &input, MessageParcel &data)
{
    return Marshal(data, input.values_);
}

template<>
bool Unmarshalling(NativeRdb::ValuesBucket &output, MessageParcel &data)
{
    return Unmarshal(data, output.values_);
}
} // namespace OHOS::ITypesUtil
