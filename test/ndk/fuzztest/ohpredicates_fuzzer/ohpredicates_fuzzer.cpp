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
#include "ohpredicates_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "oh_predicates.h"
#include "relational_store.h"
#include <iostream>

void OhPredicatesFuzzTest(FuzzedDataProvider &provider)
{
    static bool runEndFlag = false;
    std::string tableName = provider.ConsumeRandomLengthString();
    std::string field = provider.ConsumeRandomLengthString();
    std::string pattern = provider.ConsumeRandomLengthString();

    OH_Predicates *predicates = OH_Rdb_CreatePredicates(tableName.c_str());
    OH_Predicates_NotLike(predicates, field.c_str(), pattern.c_str());
    OH_Predicates_Glob(predicates, field.c_str(), pattern.c_str());
    OH_Predicates_NotGlob(predicates, field.c_str(), pattern.c_str());

    if (!runEndFlag) {
        runEndFlag = true;
        std::cout << "OhPredicatesFuzzTest end" << std::endl;
    }
    if (predicates != nullptr) {
        predicates->destroy(predicates);
    }
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);

    // Test OH_Predicates_NotLike, OH_Predicates_Glob, OH_Predicates_NotGlob
    OhPredicatesFuzzTest(provider);
    return 0;
}
