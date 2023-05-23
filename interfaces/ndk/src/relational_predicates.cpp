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
#include "relational_predicates.h"

#include "relational_predicates_impl.h"
#include "relational_value_object_impl.h"
#include "relational_error_code.h"
#include "sqlite_global_config.h"
#include "ndk_logger.h"

using OHOS::RdbNdk::RDB_NDK_LABEL;
using namespace OHOS::NativeRdb;

RdbPredicates &OHOS::RdbNdk::PredicateImpl::GetPredicates()
{
    return predicates_;
}

OH_Predicates *OH_Rdb_CreatePredicates(const char *table)
{
    if (table == nullptr) {
        return nullptr;
    }
    return new OHOS::RdbNdk::PredicateImpl(table);
}

int OH_Rdb_DestroyPredicates(OH_Predicates *predicates)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return RDB_ERR_INVALID_ARGS;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    delete tempPredicates;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

OH_Predicates PREDICATES_EqualTo(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr
        || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    tempPredicates->GetPredicates().EqualTo(field, tempValue[0]);
    return *predicates;
}

OH_Predicates PREDICATES_NotEqualTo(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr
        || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    tempPredicates->GetPredicates().NotEqualTo(field, tempValue[0]);
    return *predicates;
}

OH_Predicates PREDICATES_BeginWrap(OH_Predicates *predicates)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().BeginWrap();
    return *predicates;
}

OH_Predicates PREDICATES_EndWrap(OH_Predicates *predicates)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().EndWrap();
    return *predicates;
}

OH_Predicates PREDICATES_Or(OH_Predicates *predicates)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().Or();
    return *predicates;
}

OH_Predicates PREDICATES_And(OH_Predicates *predicates)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().And();
    return *predicates;
}

OH_Predicates PREDICATES_IsNull(OH_Predicates *predicates, const char *field)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().IsNull(field);
    return *predicates;
}

OH_Predicates PREDICATES_IsNotNull(OH_Predicates *predicates, const char *field)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().IsNotNull(field);
    return *predicates;
}

OH_Predicates PREDICATES_Like(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr
        || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    tempPredicates->GetPredicates().Like(field, tempValue[0]);
    return *predicates;
}

OH_Predicates PREDICATES_Between(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr
        || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    if (tempValue.size() != 2) {
        LOG_ERROR("size is %{public}d", tempValue.size());
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);

    tempPredicates->GetPredicates().Between(field, tempValue[0], tempValue[1]);
    return *predicates;
}

OH_Predicates PREDICATES_NotBetween(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr
        || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    if (tempValue.size() != 2) {
        LOG_ERROR("size is %{public}d", tempValue.size());
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().NotBetween(field, tempValue[0], tempValue[1]);
    return *predicates;
}

OH_Predicates PREDICATES_GreaterThan(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr
        || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    tempPredicates->GetPredicates().GreaterThan(field, tempValue[0]);
    return *predicates;
}

OH_Predicates PREDICATES_LessThan(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr
        || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    tempPredicates->GetPredicates().LessThan(field, tempValue[0]);
    return *predicates;
}

OH_Predicates PREDICATES_GreaterThanOrEqualTo(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr
        || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    tempPredicates->GetPredicates().GreaterThanOrEqualTo(field, tempValue[0]);
    return *predicates;
}
OH_Predicates PREDICATES_LessThanOrEqualTo(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr
        || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    tempPredicates->GetPredicates().LessThanOrEqualTo(field, tempValue[0]);
    return *predicates;
}

OH_Predicates PREDICATES_OrderBy(OH_Predicates *predicates, const char *field, OH_Rdb_OrderType type)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || field == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    if (type == OH_Rdb_OrderType::DESC) {
        tempPredicates->GetPredicates().OrderByDesc(field);
        return *predicates;
    }
    tempPredicates->GetPredicates().OrderByAsc(field);
    return *predicates;
}

OH_Predicates PREDICATES_Distinct(OH_Predicates *predicates)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().Distinct();
    return *predicates;
}

OH_Predicates PREDICATES_Limit(OH_Predicates *predicates, unsigned int value)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().Limit(value);
    return *predicates;
}

OH_Predicates PREDICATES_Offset(OH_Predicates *predicates, unsigned int rowOffset)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().Offset(rowOffset);
    return *predicates;
}

OH_Predicates PREDICATES_GroupBy(OH_Predicates *predicates, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, valueObject is NULL ? %{public}d,",
            (predicates == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    if (tempValue.size() > OHOS::NativeRdb::GlobalExpr::SQLITE_MAX_COLUMN) {
        return *predicates;
    }
    tempPredicates->GetPredicates().GroupBy(tempValue);
    return *predicates;
}

OH_Predicates PREDICATES_In(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    if (tempValue.size() > OHOS::NativeRdb::GlobalExpr::SQLITE_MAX_COLUMN) {
        return *predicates;
    }

    tempPredicates->GetPredicates().In(field, tempValue);
    return *predicates;
}

OH_Predicates PREDICATES_NotIn(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID || valueObject == nullptr) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d, field is NULL ? %{public}d,"
                  "valueObject is NULL ? %{public}d",
            (predicates == nullptr), (field == nullptr), (valueObject == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> tempValue = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject)->getValue();
    if (tempValue.size() > OHOS::NativeRdb::GlobalExpr::SQLITE_MAX_COLUMN) {
        return *predicates;
    }

    tempPredicates->GetPredicates().NotIn(field, tempValue);
    return *predicates;
}

OH_Predicates PREDICATES_Clear(OH_Predicates *predicates)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return *predicates;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempPredicates->GetPredicates().Clear();
    return *predicates;
}

int PREDICATES_Close(OH_Predicates *predicates)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("Parameters set error:predicates is NULL ? %{public}d", (predicates == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempPredicates = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    delete tempPredicates;
    tempPredicates = nullptr;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}