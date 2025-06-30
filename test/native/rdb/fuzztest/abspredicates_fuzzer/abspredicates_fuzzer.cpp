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
#include "abspredicates_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <string>
#include <vector>

#include "abs_shared_result_set.h"
#include "ashmem.h"
#include "rd_statement.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
#include "rdb_types.h"
#include "refbase.h"
#include "shared_block.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;

// Define constants
#define MAX_STRING_LENGTH 50
#define MAX_VECTOR_SIZE 10

namespace OHOS {

std::vector<ValueObject> ConsumeRandomLengthValueObjectVector(FuzzedDataProvider &provider)
{
    const int loopsMin = 0;
    const int loopsMax = 100;
    size_t loops = provider.ConsumeIntegralInRange<size_t>(loopsMin, loopsMax);
    std::vector<ValueObject> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t value = provider.ConsumeIntegral<int32_t>();
        ValueObject obj(value);
        columns.emplace_back(obj);
    }
    return columns;
}

std::vector<std::string> ConsumeRandomLengthStringVector(FuzzedDataProvider &provider)
{
    const int loopsMin = 0;
    const int loopsMax = 100;
    size_t loops = provider.ConsumeIntegralInRange<size_t>(loopsMin, loopsMax);
    std::vector<std::string> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t length = provider.ConsumeIntegral<int32_t>();
        auto bytes = provider.ConsumeBytes<char>(length);
        columns.emplace_back(bytes.begin(), bytes.end());
    }
    return columns;
}

void TestSetWhereClause(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string whereClause = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.SetWhereClause(whereClause);
}

void TestSetBindArgs(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::vector<ValueObject> valueObjects = ConsumeRandomLengthValueObjectVector(provider);
    predicates.SetBindArgs(valueObjects);
}

void TestSetOrder(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string order = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.SetOrder(order);
}

void TestLimit(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    int limit = provider.ConsumeIntegral<int>();
    predicates.Limit(limit);
}

void TestLimitWithOffset(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    int offset = provider.ConsumeIntegral<int>();
    int limit = provider.ConsumeIntegral<int>();
    predicates.Limit(offset, limit);
}

void TestOffset(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    int offset = provider.ConsumeIntegral<int>();
    predicates.Offset(offset);
}

void TestGroupBy(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::vector<std::string> fields = ConsumeRandomLengthStringVector(provider);
    predicates.GroupBy(fields);
}

void TestIndexedBy(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string indexName = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.IndexedBy(indexName);
}

void TestHaving(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string conditions = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<ValueObject> valueObjects = ConsumeRandomLengthValueObjectVector(provider);
    predicates.Having(conditions, valueObjects);
}

void TestIn(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<ValueObject> valueObjects = ConsumeRandomLengthValueObjectVector(provider);
    predicates.In(field, valueObjects);
}

void TestNotIn(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::vector<ValueObject> valueObjects = ConsumeRandomLengthValueObjectVector(provider);
    predicates.NotIn(field, valueObjects);
}

void TestBetween(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t value1 = provider.ConsumeIntegral<int32_t>();
    ValueObject obj1(value1);
    int32_t value2 = provider.ConsumeIntegral<int32_t>();
    ValueObject obj2(value2);
    predicates.Between(field, obj1, obj2);
}

void TestNotBetween(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t value1 = provider.ConsumeIntegral<int32_t>();
    ValueObject obj1(value1);
    int32_t value2 = provider.ConsumeIntegral<int32_t>();
    ValueObject obj2(value2);
    predicates.NotBetween(field, obj1, obj2);
}

void TestGreaterThan(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ValueObject valueObject = provider.ConsumeIntegral<int>();
    predicates.GreaterThan(field, valueObject);
}

void TestLessThan(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ValueObject valueObject = provider.ConsumeIntegral<int>();
    predicates.LessThan(field, valueObject);
}

void TestGreaterThanOrEqualTo(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ValueObject valueObject = provider.ConsumeIntegral<int>();
    predicates.GreaterThanOrEqualTo(field, valueObject);
}

void TestLessThanOrEqualTo(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ValueObject valueObject = provider.ConsumeIntegral<int>();
    predicates.LessThanOrEqualTo(field, valueObject);
}

void TestOrderByAsc(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.OrderByAsc(field);
}

void TestOrderByDesc(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.OrderByDesc(field);
}

void TestEqualTo(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ValueObject valueObject = provider.ConsumeIntegral<int>();
    predicates.EqualTo(field, valueObject);
}

void TestNotEqualTo(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ValueObject valueObject = provider.ConsumeIntegral<int>();
    predicates.NotEqualTo(field, valueObject);
}

void TestContains(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.Contains(field, value);
}

void TestNotContains(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.NotContains(field, value);
}

void TestBeginsWith(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.BeginsWith(field, value);
}

void TestEndsWith(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.EndsWith(field, value);
}

void TestIsNull(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.IsNull(field);
}

void TestIsNotNull(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.IsNotNull(field);
}

void TestLike(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.Like(field, value);
}

void TestNotLike(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.NotLike(field, value);
}

void TestGlob(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.Glob(field, value);
}

void TestNotGlob(FuzzedDataProvider &provider, AbsPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    predicates.NotGlob(field, value);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::NativeRdb::AbsPredicates predicates;

    // Call test functions
    OHOS::TestSetWhereClause(provider, predicates);
    OHOS::TestSetBindArgs(provider, predicates);
    OHOS::TestSetOrder(provider, predicates);
    OHOS::TestLimit(provider, predicates);
    OHOS::TestLimitWithOffset(provider, predicates);
    OHOS::TestOffset(provider, predicates);
    OHOS::TestGroupBy(provider, predicates);
    OHOS::TestIndexedBy(provider, predicates);
    OHOS::TestHaving(provider, predicates);
    OHOS::TestIn(provider, predicates);
    OHOS::TestNotIn(provider, predicates);
    OHOS::TestBetween(provider, predicates);
    OHOS::TestNotBetween(provider, predicates);
    OHOS::TestGreaterThan(provider, predicates);
    OHOS::TestLessThan(provider, predicates);
    OHOS::TestGreaterThanOrEqualTo(provider, predicates);
    OHOS::TestLessThanOrEqualTo(provider, predicates);
    OHOS::TestOrderByAsc(provider, predicates);
    OHOS::TestOrderByDesc(provider, predicates);
    OHOS::TestEqualTo(provider, predicates);
    OHOS::TestNotEqualTo(provider, predicates);
    OHOS::TestContains(provider, predicates);
    OHOS::TestNotContains(provider, predicates);
    OHOS::TestBeginsWith(provider, predicates);
    OHOS::TestEndsWith(provider, predicates);
    OHOS::TestIsNull(provider, predicates);
    OHOS::TestIsNotNull(provider, predicates);
    OHOS::TestLike(provider, predicates);
    OHOS::TestNotLike(provider, predicates);
    OHOS::TestGlob(provider, predicates);
    OHOS::TestNotGlob(provider, predicates);

    return 0;
}