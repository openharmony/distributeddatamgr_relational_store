/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "oh_predicates_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "grd_api_manager.h"
#include "oh_data_value.h"
#include "oh_data_values.h"
#include "oh_data_values_buckets.h"
#include "oh_predicates.h"
#include "oh_value_object.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

#define LENGTH_MIN 1
#define LENGTH_MAX 10

#define STRING_LENGTH_MAX 20

namespace OHOS {

std::vector<OH_VObject *> ConsumeRandomLengthValueObjectVector(FuzzedDataProvider &provider)
{
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LENGTH_MIN, LENGTH_MAX);
    std::vector<OH_VObject *> columns;
    for (size_t i = 0; i < loops; ++i) {
        OH_VObject *obj = OH_Rdb_CreateValueObject();
        columns.emplace_back(obj);
    }
    return columns;
}

void TestOH_Predicates_equalTo(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->equalTo(predicates, field.c_str(), obj);
    predicates->destroy(predicates);
}

void TestOH_Predicates_notEqualTo(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->notEqualTo(predicates, field.c_str(), obj);
    predicates->destroy(predicates);
}

void TestOH_Predicates_beginWrap(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    predicates->beginWrap(predicates);
    predicates->destroy(predicates);
}

void TestOH_Predicates_endWrap(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    predicates->endWrap(predicates);
    predicates->destroy(predicates);
}

void TestOH_Predicates_orOperate(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    predicates->orOperate(predicates);
    predicates->destroy(predicates);
}

void TestOH_Predicates_andOperate(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    predicates->andOperate(predicates);
    predicates->destroy(predicates);
}

void TestOH_Predicates_isNull(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->isNull(predicates, field.c_str());
    predicates->destroy(predicates);
}

void TestOH_Predicates_isNotNull(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->isNotNull(predicates, field.c_str());
    predicates->destroy(predicates);
}

void TestOH_Predicates_like(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->like(predicates, field.c_str(), obj);
    predicates->destroy(predicates);
    obj->destroy(obj);
}

void TestOH_Predicates_between(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->between(predicates, field.c_str(), obj);
    predicates->destroy(predicates);
    obj->destroy(obj);
}

void TestOH_Predicates_notBetween(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->notBetween(predicates, field.c_str(), obj);
    predicates->destroy(predicates);
    obj->destroy(obj);
}

void TestOH_Predicates_greaterThan(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->greaterThan(predicates, field.c_str(), obj);
    predicates->destroy(predicates);
    obj->destroy(obj);
}

void TestOH_Predicates_lessThan(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->lessThan(predicates, field.c_str(), obj);
    predicates->destroy(predicates);
    obj->destroy(obj);
}

void TestOH_Predicates_greaterThanOrEqualTo(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->greaterThanOrEqualTo(predicates, field.c_str(), obj);
    predicates->destroy(predicates);
    obj->destroy(obj);
}

void TestOH_Predicates_lessThanOrEqualTo(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    predicates->lessThanOrEqualTo(predicates, field.c_str(), obj);
    predicates->destroy(predicates);
    obj->destroy(obj);
}

void TestOH_Predicates_orderBy(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    OH_VObject *obj = OH_Rdb_CreateValueObject();
    if (obj == nullptr) {
        predicates->destroy(predicates);
        return;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    obj->putText(obj, value.c_str());
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_OrderType type = static_cast<OH_OrderType>(provider.ConsumeIntegral<int>());
    predicates->orderBy(predicates, field.c_str(), type);
    predicates->destroy(predicates);
    obj->destroy(obj);
}

void TestOH_Predicates_distinct(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    predicates->distinct(predicates);
    predicates->destroy(predicates);
}

void TestOH_Predicates_limit(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    unsigned int value = provider.ConsumeIntegral<unsigned int>();
    predicates->limit(predicates, value);
    predicates->destroy(predicates);
}

void TestOH_Predicates_offset(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    unsigned int rowOffset = provider.ConsumeIntegral<unsigned int>();
    predicates->offset(predicates, rowOffset);
    predicates->destroy(predicates);
}

void TestOH_Predicates_groupBy(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LENGTH_MIN, LENGTH_MAX);
    const char *fields[loops];
    for (size_t i = 0; i < loops; ++i) {
        static std::string fieldsString = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX).c_str();
        fields[i] = fieldsString.c_str();
    }
    predicates->groupBy(predicates, fields, loops);
    predicates->destroy(predicates);
}

void TestOH_Predicates_in(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    std::vector<OH_VObject *> values = ConsumeRandomLengthValueObjectVector(provider);
    for (auto value : values) {
        predicates->in(predicates, field.c_str(), value);
        value->destroy(value);
    }
    predicates->destroy(predicates);
}

void TestOH_Predicates_notIn(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    std::vector<OH_VObject *> values = ConsumeRandomLengthValueObjectVector(provider);
    for (auto value : values) {
        predicates->notIn(predicates, field.c_str(), value);
        value->destroy(value);
    }
    predicates->destroy(predicates);
}

void TestOH_Predicates_Having(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    std::string conditions = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Data_Values *values = OH_Values_Create();
    OH_Predicates_Having(predicates, conditions.c_str(), values);
    predicates->destroy(predicates);
}

void TestOH_Predicates_NotLike(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    std::string pattern = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates_NotLike(predicates, field.c_str(), pattern.c_str());
    predicates->destroy(predicates);
}

void TestOH_Predicates_Glob(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    std::string pattern = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates_Glob(predicates, field.c_str(), pattern.c_str());
    predicates->destroy(predicates);
}

void TestOH_Predicates_NotGlob(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    std::string field = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    std::string pattern = provider.ConsumeRandomLengthString(STRING_LENGTH_MAX);
    OH_Predicates_NotGlob(predicates, field.c_str(), pattern.c_str());
    predicates->destroy(predicates);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    OHOS::TestOH_Predicates_equalTo(provider);
    OHOS::TestOH_Predicates_notEqualTo(provider);
    OHOS::TestOH_Predicates_beginWrap(provider);
    OHOS::TestOH_Predicates_endWrap(provider);
    OHOS::TestOH_Predicates_orOperate(provider);
    OHOS::TestOH_Predicates_andOperate(provider);
    OHOS::TestOH_Predicates_isNull(provider);
    OHOS::TestOH_Predicates_isNotNull(provider);
    OHOS::TestOH_Predicates_like(provider);
    OHOS::TestOH_Predicates_between(provider);
    OHOS::TestOH_Predicates_notBetween(provider);
    OHOS::TestOH_Predicates_greaterThan(provider);
    OHOS::TestOH_Predicates_lessThan(provider);
    OHOS::TestOH_Predicates_greaterThanOrEqualTo(provider);
    OHOS::TestOH_Predicates_lessThanOrEqualTo(provider);
    OHOS::TestOH_Predicates_orderBy(provider);
    OHOS::TestOH_Predicates_distinct(provider);
    OHOS::TestOH_Predicates_limit(provider);
    OHOS::TestOH_Predicates_offset(provider);
    OHOS::TestOH_Predicates_groupBy(provider);
    OHOS::TestOH_Predicates_in(provider);
    OHOS::TestOH_Predicates_notIn(provider);
    OHOS::TestOH_Predicates_Having(provider);
    OHOS::TestOH_Predicates_NotLike(provider);
    OHOS::TestOH_Predicates_Glob(provider);
    OHOS::TestOH_Predicates_NotGlob(provider);
    return 0;
}
