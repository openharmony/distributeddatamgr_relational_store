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

#include "rdb_predicates.h"


#define LOOPS_MIN 0
#define LOOPS_MAX 100

using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace OHOS {
std::vector<std::string> ConsumeRandomLengthStringVector(FuzzedDataProvider &provider)
{
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<std::string> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t length = provider.ConsumeIntegral<int32_t>();
        auto bytes = provider.ConsumeBytes<char>(length);
        columns.emplace_back(bytes.begin(), bytes.end());
    }
    return columns;
}

void RdbPredicatesCrossJoinFuzz(FuzzedDataProvider &provider)
{
    std::string tableName = provider.ConsumeRandomLengthString();
    RdbPredicates predicates(tableName);
    std::string joinTableName = provider.ConsumeRandomLengthString();
    predicates.CrossJoin(joinTableName);
}

void RdbPredicatesInnerJoinFuzz(FuzzedDataProvider &provider)
{
    std::string tableName = provider.ConsumeRandomLengthString();
    RdbPredicates predicates(tableName);
    std::string joinTableName = provider.ConsumeRandomLengthString();
    predicates.InnerJoin(joinTableName);
}

void RdbPredicatesLeftOuterJoinFuzz(FuzzedDataProvider &provider)
{
    std::string tableName = provider.ConsumeRandomLengthString();
    RdbPredicates predicates(tableName);
    std::string joinTableName = provider.ConsumeRandomLengthString();
    predicates.LeftOuterJoin(joinTableName);
}

void RdbPredicatesUsingFuzz(FuzzedDataProvider &provider)
{
    std::string tableName = provider.ConsumeRandomLengthString();
    RdbPredicates predicates(tableName);
    std::vector<std::string> fields = ConsumeRandomLengthStringVector(provider);
    predicates.Using(fields);
}

void RdbPredicatesOnFuzz(FuzzedDataProvider &provider)
{
    std::string tableName = provider.ConsumeRandomLengthString();
    RdbPredicates predicates(tableName);
    std::vector<std::string> clauses = ConsumeRandomLengthStringVector(provider);
    predicates.On(clauses);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RdbPredicatesCrossJoinFuzz(provider);
    OHOS::RdbPredicatesInnerJoinFuzz(provider);
    OHOS::RdbPredicatesLeftOuterJoinFuzz(provider);
    OHOS::RdbPredicatesUsingFuzz(provider);
    OHOS::RdbPredicatesOnFuzz(provider);
    return 0;
}