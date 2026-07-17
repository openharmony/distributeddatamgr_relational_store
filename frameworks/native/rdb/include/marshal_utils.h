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

#ifndef NATIVE_RDB_MARSHAL_UTILS_H
#define NATIVE_RDB_MARSHAL_UTILS_H

#include <map>
#include <string>

#include "value_object.h"

namespace OHOS {
template <typename T>
class sptr;
class MessageParcel;
class Parcel;
class Ashmem;
namespace NativeRdb {
class MarshalUtils {
public:
    static bool Marshal(Parcel &data, const std::map<std::string, ValueObject> &input);
    static bool Unmarshal(Parcel &data, std::map<std::string, ValueObject> &output);
    static bool Marshal(MessageParcel &data, const std::string &name, sptr<Ashmem> &ashmem);
    static bool Unmarshal(MessageParcel &data, std::string &name, sptr<Ashmem> &ashmem);
};
} // namespace NativeRdb
} // namespace OHOS
#endif