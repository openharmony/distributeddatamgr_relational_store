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
#include <fuzzer/FuzzedDataProvider.h>

#include <string>
#include <vector>

#include "abs_rdb_predicates.h"
#include "rdb_types.h"


using namespace OHOS;
using namespace OHOS::NativeRdb;

static const int FOR_LOOP_MIN = 0;
static const int FOR_LOOP_MAX = 10;
static const int RANDOM_STRING_LENGTH = 30;

namespace OHOS {
void FuzzInDevices(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::vector<std::string> devices;
    size_t numDevices = provider.ConsumeIntegralInRange<size_t>(FOR_LOOP_MIN, FOR_LOOP_MAX);
    for (size_t i = 0; i < numDevices; ++i) {
        devices.push_back(provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH));
    }
    predicates.InDevices(devices);
}

void FuzzEqualTo(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    ValueObject value(provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH));
    predicates.EqualTo(field, value);
}

void FuzzNotEqualTo(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    ValueObject value(provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH));
    predicates.NotEqualTo(field, value);
}

void FuzzInStringVector(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::vector<std::string> values;
    size_t numValues = provider.ConsumeIntegralInRange<size_t>(FOR_LOOP_MIN, FOR_LOOP_MAX);
    for (size_t i = 0; i < numValues; ++i) {
        values.push_back(provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH));
    }
    predicates.In(field, values);
}

void FuzzInValueObjectVector(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::vector<ValueObject> values;
    size_t numValues = provider.ConsumeIntegralInRange<size_t>(FOR_LOOP_MIN, FOR_LOOP_MAX);
    for (size_t i = 0; i < numValues; ++i) {
        ValueObject value(provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH));
        values.push_back(value);
    }
    predicates.In(field, values);
}

void FuzzContains(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.Contains(field, value);
}

void FuzzNotContains(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.NotContains(field, value);
}

void FuzzBeginsWith(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.BeginsWith(field, value);
}

void FuzzEndsWith(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.EndsWith(field, value);
}

void FuzzLike(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.Like(field, value);
}

void FuzzNotLike(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.NotLike(field, value);
}

void FuzzGlob(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.Glob(field, value);
}

void FuzzNotGlob(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::string value = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.NotGlob(field, value);
}

void FuzzNotInStringVector(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::vector<std::string> values;
    size_t numValues = provider.ConsumeIntegralInRange<size_t>(FOR_LOOP_MIN, FOR_LOOP_MAX);
    for (size_t i = 0; i < numValues; ++i) {
        values.push_back(provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH));
    }
    predicates.NotIn(field, values);
}

void FuzzNotInValueObjectVector(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    std::vector<ValueObject> values;
    size_t numValues = provider.ConsumeIntegralInRange<size_t>(FOR_LOOP_MIN, FOR_LOOP_MAX);
    for (size_t i = 0; i < numValues; ++i) {
        ValueObject value(provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH));
        values.push_back(value);
    }
    predicates.NotIn(field, values);
}

void FuzzOrderByAsc(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.OrderByAsc(field);
}

void FuzzOrderByDesc(FuzzedDataProvider &provider, AbsRdbPredicates &predicates)
{
    std::string field = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    predicates.OrderByDesc(field);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    // Create an instance of AbsRdbPredicates
    std::string tableName = provider.ConsumeRandomLengthString(RANDOM_STRING_LENGTH);
    AbsRdbPredicates predicates(tableName);

    // Fuzzing for InDevices
    OHOS::FuzzInDevices(provider, predicates);

    // Fuzzing for EqualTo
    OHOS::FuzzEqualTo(provider, predicates);

    // Fuzzing for NotEqualTo
    OHOS::FuzzNotEqualTo(provider, predicates);

    // Fuzzing for In (string vector)
    OHOS::FuzzInStringVector(provider, predicates);

    // Fuzzing for In (ValueObject vector)
    OHOS::FuzzInValueObjectVector(provider, predicates);

    // Fuzzing for Contains
    OHOS::FuzzContains(provider, predicates);

    // Fuzzing for NotContains
    OHOS::FuzzNotContains(provider, predicates);

    // Fuzzing for BeginsWith
    OHOS::FuzzBeginsWith(provider, predicates);

    // Fuzzing for EndsWith
    OHOS::FuzzEndsWith(provider, predicates);

    // Fuzzing for Like
    OHOS::FuzzLike(provider, predicates);

    // Fuzzing for NotLike
    OHOS::FuzzNotLike(provider, predicates);

    // Fuzzing for Glob
    OHOS::FuzzGlob(provider, predicates);

    // Fuzzing for NotGlob
    OHOS::FuzzNotGlob(provider, predicates);

    // Fuzzing for NotIn (string vector)
    OHOS::FuzzNotInStringVector(provider, predicates);

    // Fuzzing for NotIn (ValueObject vector)
    OHOS::FuzzNotInValueObjectVector(provider, predicates);

    // Fuzzing for OrderByAsc
    OHOS::FuzzOrderByAsc(provider, predicates);

    // Fuzzing for OrderByDesc
    OHOS::FuzzOrderByDesc(provider, predicates);

    return 0;
}
