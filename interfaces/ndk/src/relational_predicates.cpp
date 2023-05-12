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
#include "relational_error_code.h"

OHOS::NativeRdb::RdbPredicates &OHOS::NativeRdb::PredicateImpl::GetPredicates()
{
    return predicates_;
}

OH_Predicates *OH_Rdb_CreatePredicates(const char *table)
{
    if (table == nullptr) {
        return nullptr;
    }
    return new OHOS::NativeRdb::PredicateImpl(table);
}

int OH_Rdb_DestroyPredicates(OH_Predicates *predicate)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    delete tempPredicates;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_EqualTo(OH_Predicates *predicate, const char *field, const char *value)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().EqualTo(field, value);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_NotEqualTo(OH_Predicates *predicate, const char *field, const char *value)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().NotEqualTo(field, value);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_BeginWrap(OH_Predicates *predicate)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().BeginWrap();
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_EndWrap(OH_Predicates *predicate)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().EndWrap();
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_Or(OH_Predicates *predicate)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().Or();
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_And(OH_Predicates *predicate)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().And();
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_IsNull(OH_Predicates *predicate, const char *field)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().IsNull(field);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_IsNotNull(OH_Predicates *predicate, const char *field)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().IsNotNull(field);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_Like(OH_Predicates *predicate, const char *field, const char *value)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().Like(field, value);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_Between(OH_Predicates *predicate, const char *field, const char *betweenValue, const char *andValue)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().Between(field, betweenValue, andValue);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_NotBetween(OH_Predicates *predicate, const char *field, const char *betweenValue, const char *andValue)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().NotBetween(field, betweenValue, andValue);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_GreaterThan(OH_Predicates *predicate, const char *field, const char *value)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().GreaterThan(field, value);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_LessThan(OH_Predicates *predicate, const char *field, const char *value)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().LessThan(field, value);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_GreaterThanOrEqualTo(OH_Predicates *predicate, const char *field, const char *value)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().GreaterThanOrEqualTo(field, value);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}
int PREDICATES_LessThanOrEqualTo(OH_Predicates *predicate, const char *field, const char *value)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().LessThanOrEqualTo(field, value);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_OrderBy(OH_Predicates *predicate, const char *field, OH_Rdb_OrderByType type)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    if (type == OH_Rdb_OrderByType::RDB_PRE_DESC) {
        tempPredicates->GetPredicates().OrderByDesc(field);
        return OH_Rdb_ErrCode::RDB_ERR_OK;
    }
    tempPredicates->GetPredicates().OrderByAsc(field);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_Distinct(OH_Predicates *predicate)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().Distinct();
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_Limit(OH_Predicates *predicate, unsigned int value)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().Limit(value);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_Offset(OH_Predicates *predicate, unsigned int rowOffset)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().Offset(rowOffset);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_GroupBy(OH_Predicates *predicate, const char *const *field, const int length)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    std::vector<std::string> vec;
    vec.reserve(length);
    if (field != nullptr) {
        for (int i = 0; i < length; i++) {
            vec.push_back(std::string(field[i]));
        }
    }

    tempPredicates->GetPredicates().GroupBy(vec);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_In(OH_Predicates *predicate, const char *filed, const char *const *values, const int length)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    std::vector<std::string> vec;
    vec.reserve(length);
    if (values != nullptr) {
        for (int i = 0; i < length; i++) {
            vec.push_back(std::string(values[i]));
        }
    }

    tempPredicates->GetPredicates().In(filed, vec);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_NotIn(OH_Predicates *predicate, const char *filed, const char *const *values, const int length)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    std::vector<std::string> vec;
    vec.reserve(length);
    if (values != nullptr) {
        for (int i = 0; i < length; i++) {
            vec.push_back(std::string(values[i]));
        }
    }

    tempPredicates->GetPredicates().NotIn(filed, vec);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int PREDICATES_Clear(OH_Predicates *predicate)
{
    if (predicate == nullptr || predicate->id != OHOS::NativeRdb::RDB_PREDICATES_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::PredicateImpl *tempPredicates = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    tempPredicates->GetPredicates().Clear();
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}