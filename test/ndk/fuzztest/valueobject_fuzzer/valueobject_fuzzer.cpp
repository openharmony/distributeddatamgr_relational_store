/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "valueobject_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "grd_api_manager.h"
#include "oh_value_object.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"


using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

void ValueObjectFuzzTest(FuzzedDataProvider &provider)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    if (valueObject == nullptr) {
        return;
    }

    // Test putText
    {
        std::string value = provider.ConsumeRandomLengthString();
        valueObject->putText(valueObject, value.c_str());
    }

    // Test putInt64
    {
        const int minArraySize = 1;
        const int maxArraySize = 50;
        size_t arraySize = provider.ConsumeIntegralInRange<size_t>(minArraySize, maxArraySize);
        std::vector<int64_t> array(arraySize);
        for (size_t i = 0; i < arraySize; i++) {
            array[i] = provider.ConsumeIntegral<int64_t>();
        }
        valueObject->putInt64(valueObject, array.data(), array.size());
    }

    // Test putDouble
    {
        const int minArraySize = 1;
        const int maxArraySize = 50;
        size_t arraySize = provider.ConsumeIntegralInRange<size_t>(minArraySize, maxArraySize);
        std::vector<double> array(arraySize);
        for (size_t i = 0; i < arraySize; i++) {
            array[i] = static_cast<double>(provider.ConsumeFloatingPoint<float>());
        }
        valueObject->putDouble(valueObject, array.data(), array.size());
    }

    // Test putTexts
    {
        const int minArraySize = 1;
        const int maxArraySize = 50;
        size_t arraySize = provider.ConsumeIntegralInRange<size_t>(minArraySize, maxArraySize);

        // Use std::vector to manage memory
        std::vector<std::unique_ptr<char[]>> stringStorage(arraySize);
        const char **array = new const char *[arraySize];

        for (size_t i = 0; i < arraySize; i++) {
            std::string value = provider.ConsumeRandomLengthString();

            // Allocate memory for each string
            stringStorage[i] = std::make_unique<char[]>(value.size() + 1);
            std::copy(value.begin(), value.end(), stringStorage[i].get());
            stringStorage[i][value.size()] = '\0'; // Ensure the string is null-terminated

            // Assign the pointer to array
            array[i] = stringStorage[i].get();
        }

        // Use array
        valueObject->putTexts(valueObject, array, arraySize);

        // Free the array pointer
        delete[] array;
    }

    // Destroy valueObject
    valueObject->destroy(valueObject);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    ValueObjectFuzzTest(provider);
    return 0;
}
