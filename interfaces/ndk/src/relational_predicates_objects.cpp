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
#define LOG_TAG "RelationalPredicatesObjects"
#include "relational_predicates_objects.h"

#include "logger.h"
#include "oh_value_object.h"
#include "rdb_fault_hiview_reporter.h"
#include "relational_store_error_code.h"

using Reporter = OHOS::NativeRdb::RdbFaultHiViewReporter;

namespace OHOS {
namespace RdbNdk {
// The class id used to uniquely identify the OH_VObject class.
constexpr int RDB_PREDICATES_OBJECTS_CID = 1234565;
constexpr uint32_t COUNT_MAX = 4294967294; // length or count up to 4294967294(1024 * 1024 * 1024 * 4 - 2).
constexpr uint32_t COUNT_REPORT = 1073741823; // count to report 1073741823(1024 * 1024 * 1024 - 1).

int RelationalPredicatesObjects::PutInt64(OH_VObject *objects, int64_t *value, uint32_t count)
{
    if (count > COUNT_REPORT) {
        Reporter::ReportFault(OHOS::NativeRdb::RdbFaultEvent(OHOS::NativeRdb::FT_LENGTH_PARAM, RDB_E_INVALID_ARGS,
            OHOS::NativeRdb::BUNDLE_NAME_COMMON, std::string("PutInt64 count is ") + std::to_string(count)));
    }
    auto self = GetSelf(objects);
    if (self == nullptr || value == nullptr || count == 0 || count > COUNT_MAX) {
        LOG_ERROR("self or value is nullptr, count is %{public}u", count);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    self->values_.clear();
    self->values_.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        self->values_.push_back(value[i]);
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalPredicatesObjects::PutDouble(OH_VObject *objects, double *value, uint32_t count)
{
    if (count > COUNT_REPORT) {
        Reporter::ReportFault(OHOS::NativeRdb::RdbFaultEvent(OHOS::NativeRdb::FT_LENGTH_PARAM, RDB_E_INVALID_ARGS,
            OHOS::NativeRdb::BUNDLE_NAME_COMMON, std::string("PutDouble count is ") + std::to_string(count)));
    }
    auto self = GetSelf(objects);
    if (self == nullptr || value == nullptr || count == 0 || count > COUNT_MAX) {
        LOG_ERROR("self or value is nullptr, count is %{public}u", count);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    self->values_.clear();
    self->values_.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        self->values_.push_back(value[i]);
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalPredicatesObjects::PutText(OH_VObject *objects, const char *value)
{
    auto self = GetSelf(objects);
    if (self == nullptr || value == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    self->values_.clear();
    self->values_.push_back(value);
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalPredicatesObjects::PutTexts(OH_VObject *objects, const char **value, uint32_t count)
{
    if (count > COUNT_REPORT) {
        Reporter::ReportFault(OHOS::NativeRdb::RdbFaultEvent(OHOS::NativeRdb::FT_LENGTH_PARAM, RDB_E_INVALID_ARGS,
            OHOS::NativeRdb::BUNDLE_NAME_COMMON, std::string("PutTexts count is ") + std::to_string(count)));
    }
    auto self = GetSelf(objects);
    if (self == nullptr || value == nullptr || count == 0 || count > COUNT_MAX) {
        LOG_ERROR("self or value is nullptr, count is %{public}u", count);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    self->values_.clear();
    self->values_.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        self->values_.push_back(value[i]);
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalPredicatesObjects::Destroy(OH_VObject *objects)
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

RelationalPredicatesObjects *RelationalPredicatesObjects::GetSelf(OH_VObject *valueObject)
{
    if (valueObject == nullptr || valueObject->id != OHOS::RdbNdk::RDB_PREDICATES_OBJECTS_CID) {
        LOG_ERROR("predicates objects invalid. is null %{public}d", (valueObject == nullptr));
        return nullptr;
    }
    return static_cast<OHOS::RdbNdk::RelationalPredicatesObjects *>(valueObject);
}

std::vector<ValueObject> &RelationalPredicatesObjects::Get()
{
    return values_;
}
} // namespace RdbNdk
} // namespace OHOS