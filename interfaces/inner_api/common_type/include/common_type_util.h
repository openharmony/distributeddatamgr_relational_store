/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_COMMONTYPE_TYPES_UTIL_H
#define OHOS_COMMONTYPE_TYPES_UTIL_H

#include "itypes_util.h"
#include "visibility.h"
#include "common_value_object.h"
#include "common_values_bucket.h"

namespace OHOS::ITypesUtil {
using ValueObject = CommonType::ValueObject;
using ValuesBucket = CommonType::ValuesBucket;
using Asset = CommonType::AssetValue;
template<>
API_EXPORT bool Marshalling(const ValueObject &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(ValueObject &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const ValuesBucket &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(ValuesBucket &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const Asset &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(Asset &output, MessageParcel &data);
}
#endif // OHOS_COMMONTYPE_TYPES_UTIL_H
