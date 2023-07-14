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

#include "logger.h"
#include "oh_predicates_objects.h"
#include "relational_store_error_code.h"
#include "relational_predicates_objects.h"

namespace OHOS {
namespace RdbNdk {
// The class id used to uniquely identify the OH_PredicatesObjects class.
constexpr int RDB_PREDICATES_OBJECTS_CID = 1234565;
int RelationalPredicatesObjects::PutInt64(OH_PredicatesObjects *objects, int64_t *value, uint32_t count)
{
    auto self = GetSelf(objects);
    if (self == nullptr || value == nullptr || count == 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    self->values_.clear();
    self->values_.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        self->values_.push_back(std::to_string(value[i]));
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalPredicatesObjects::PutDouble(OH_PredicatesObjects *objects, double *value, uint32_t count)
{
    auto self = GetSelf(objects);
    if (self == nullptr || value == nullptr || count == 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    self->values_.clear();
    self->values_.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        self->values_.push_back(std::to_string(value[i]));
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalPredicatesObjects::PutText(OH_PredicatesObjects *objects, const char *value)
{
    auto self = GetSelf(objects);
    if (self == nullptr || value == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    self->values_.clear();
    self->values_.push_back(value);
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalPredicatesObjects::PutTexts(OH_PredicatesObjects *objects, const char **value, uint32_t count)
{
    auto self = GetSelf(objects);
    if (self == nullptr || value == nullptr || count == 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    self->values_.clear();
    self->values_.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        self->values_.push_back(value[i]);
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalPredicatesObjects::Destroy(OH_PredicatesObjects *objects)
{
    auto self = GetSelf(objects);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    delete self;
    return OH_Rdb_ErrCode::RDB_OK;
}

RelationalPredicatesObjects::RelationalPredicatesObjects()
{
    id = RDB_PREDICATES_OBJECTS_CID;
    putInt64 = PutInt64;
    putDouble = PutDouble;
    putText = PutText;
    putTexts = PutTexts;
    destroy = Destroy;
}

RelationalPredicatesObjects *RelationalPredicatesObjects::GetSelf(OH_PredicatesObjects *objects)
{
    if (objects == nullptr || objects->id != OHOS::RdbNdk::RDB_PREDICATES_OBJECTS_CID) {
        LOG_ERROR("predicates objects invalid. is null %{public}d", (objects == nullptr));
        return nullptr;
    }
    return static_cast<OHOS::RdbNdk::RelationalPredicatesObjects *>(objects);
}

std::vector<std::string> &RelationalPredicatesObjects::Get()
{
    return values_;
}
} // namespace RdbNdk
} // namespace OHOS