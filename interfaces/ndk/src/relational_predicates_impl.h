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

#ifndef RELATIONAL_PREDICATES_IMPL_H
#define RELATIONAL_PREDICATES_IMPL_H

#include "rdb_predicates.h"
#include "oh_predicates.h"

namespace OHOS {
namespace RdbNdk {
constexpr int RDB_PREDICATES_CID = 1234561; // The class id used to uniquely identify the OH_Predicates class.
class PredicateImpl : public OH_Predicates {
public:
    explicit PredicateImpl(const char *table);
    OHOS::NativeRdb::RdbPredicates &GetPredicates();

private:
    OHOS::NativeRdb::RdbPredicates predicates_;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_PREDICATES_IMPL_H
