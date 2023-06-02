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

#ifndef RELATIONAL_VALUE_OBJECT_IMPL_H
#define RELATIONAL_VALUE_OBJECT_IMPL_H

#include "oh_value_object.h"
#include <vector>
#include <string>

namespace OHOS {
namespace RdbNdk {
constexpr int RDB_VOBJECT_CID = 1234565; // The class id used to uniquely identify the OH_Rdb_VObject class.
class ValueObjectImpl : public OH_VObject {
public:
    ValueObjectImpl();
    std::vector<std::string> &getValue();
private:
    std::vector<std::string> value;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_VALUE_OBJECT_IMPL_H