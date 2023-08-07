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

#include <string>
#include <vector>

#include "oh_value_object.h"
#include "value_object.h"

namespace OHOS {
namespace RdbNdk {
using ValueObject = NativeRdb::ValueObject;
class RelationalPredicatesObjects : public OH_VObject {
public:
    RelationalPredicatesObjects();
    static RelationalPredicatesObjects *GetSelf(OH_VObject *objects);
    std::vector<ValueObject> &Get();
private:
    static int PutInt64(OH_VObject *objects, int64_t *value, uint32_t count);
    static int PutDouble(OH_VObject *objects, double *value, uint32_t count);
    static int PutText(OH_VObject *objects, const char *value);
    static int PutTexts(OH_VObject *objects, const char **value, uint32_t count);
    static int Destroy(OH_VObject *objects);
    std::vector<ValueObject> values_;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_VALUE_OBJECT_IMPL_H
