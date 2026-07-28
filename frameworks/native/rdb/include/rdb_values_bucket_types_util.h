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

#ifndef NATIVE_RDB_VALUES_BUCKET_TYPES_UTIL_H
#define NATIVE_RDB_VALUES_BUCKET_TYPES_UTIL_H

#include "itypes_util.h"
#include "rdb_visibility.h"
#include "value_object.h"
#include "values_bucket.h"

namespace OHOS::ITypesUtil {
template<>
API_EXPORT bool Marshalling(const NativeRdb::AssetValue &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(NativeRdb::AssetValue &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const NativeRdb::BigInteger &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(NativeRdb::BigInteger &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const NativeRdb::ValueObject &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(NativeRdb::ValueObject &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const NativeRdb::ValuesBucket &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(NativeRdb::ValuesBucket &output, MessageParcel &data);
} // namespace OHOS::ITypesUtil

#endif // NATIVE_RDB_VALUES_BUCKET_TYPES_UTIL_H
