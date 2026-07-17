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

#include "ashmem.h"
#include "itypes_util.h"
#include "message_parcel.h"

namespace OHOS {
namespace NativeRdb {
bool MarshalUtils::Marshal(Parcel &data, const std::map<std::string, ValueObject> &input)
{
    MessageParcel *msgParcel = static_cast<MessageParcel *>(&data);
    if (msgParcel == nullptr) {
        return false;
    }
    return ITypesUtil::Marshal(*msgParcel, input);
}

bool MarshalUtils::Unmarshal(Parcel &data, std::map<std::string, ValueObject> &output)
{
    MessageParcel *msgParcel = static_cast<MessageParcel *>(&data);
    if (msgParcel == nullptr) {
        return false;
    }
    return ITypesUtil::Unmarshal(*msgParcel, output);
}

bool MarshalUtils::Marshal(MessageParcel &data, const std::string &name, sptr<Ashmem> &ashmem)
{
    if (!data.WriteString(name)) {
        return false;
    }
    if (ashmem == nullptr) {
        return data.WriteBool(false);
    }
    if (!data.WriteBool(true)) {
        return false;
    }
    return data.WriteAshmem(ashmem);
}

bool MarshalUtils::Unmarshal(MessageParcel &data, std::string &name, sptr<Ashmem> &ashmem)
{
    if (!data.ReadString(name)) {
        return false;
    }
    bool hasAshmem = false;
    if (!data.ReadBool(hasAshmem)) {
        return false;
    }
    if (!hasAshmem) {
        ashmem = nullptr;
        return true;
    }
    ashmem = data.ReadAshmem();
    return ashmem != nullptr;
}
} // namespace NativeRdb
} // namespace OHOS