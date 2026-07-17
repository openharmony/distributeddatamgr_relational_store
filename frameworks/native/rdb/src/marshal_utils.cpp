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

#include "marshal_utils.h"

namespace OHOS {
namespace NativeRdb {
__attribute__((weak)) bool MarshalUtils::Marshal(Parcel &data, const std::map<std::string, ValueObject> &input)
{
    return false;
}

__attribute__((weak)) bool MarshalUtils::Unmarshal(Parcel &data, std::map<std::string, ValueObject> &output)
{
    return false;
}

__attribute__((weak)) bool MarshalUtils::Marshal(MessageParcel &data, const std::string &name, sptr<Ashmem> &ashmem)
{
    return false;
}

__attribute__((weak)) bool MarshalUtils::Unmarshal(MessageParcel &data, std::string &name, sptr<Ashmem> &ashmem)
{
    return false;
}
} // namespace NativeRdb
} // namespace OHOS