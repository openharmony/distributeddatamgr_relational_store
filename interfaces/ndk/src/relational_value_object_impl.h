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

#include "native_value_object.h"
#include <vector>
#include <string>

int Rdb_ValueObject_PutInt64(OH_VObject *valueObject, int64_t *value, uint32_t count);
int Rdb_ValueObject_PutDouble(OH_VObject *valueObject, double *value, uint32_t count);
int Rdb_ValueObject_PutText(OH_VObject *valueObject, const char *value);
int Rdb_ValueObject_PutTexts(OH_VObject *valueObject, const char **value, uint32_t count);
int Rdb_DestroyValueObject(OH_VObject *valueObject);

namespace OHOS {
namespace RdbNdk {
constexpr int RDB_VOBJECT_CID = 1234565; // The class id used to uniquely identify the OH_Rdb_VObject class.
class ValueObjectImpl : public OH_VObject {
public:
    ValueObjectImpl()
    {
        id = RDB_VOBJECT_CID;
        PutInt64 = Rdb_ValueObject_PutInt64;
        PutDouble = Rdb_ValueObject_PutDouble;
        PutText = Rdb_ValueObject_PutText;
        PutTexts = Rdb_ValueObject_PutTexts;
        DestroyValueObject = Rdb_DestroyValueObject;
    }
    std::vector<std::string> &getValue();
private:
    std::vector<std::string> value;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_VALUE_OBJECT_IMPL_H
