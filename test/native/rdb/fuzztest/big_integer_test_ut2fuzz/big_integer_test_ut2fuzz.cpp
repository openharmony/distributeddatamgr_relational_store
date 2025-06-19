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
#include "big_integer_test_ut2fuzz.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <rdb_helper.h>
#include <rdb_store.h>
#include <rdb_store_config.h>
#include <securec.h>
#include <values_bucket.h>

#include <memory>

#include "big_integer.h"
#include "connection_pool.h"
#include "trans_db.h"


using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

void BigIntegerFuzzTest(FuzzedDataProvider &fdp)
{
    // Test primary constructor with int64_t
    auto bi1 = OHOS::NativeRdb::BigInteger(fdp.ConsumeIntegral<int64_t>());

    // Test (sign, vector) constructor
    std::vector<uint64_t> vec;
    while (fdp.remaining_bytes() >= sizeof(uint64_t)) {
        vec.push_back(fdp.ConsumeIntegral<uint64_t>());
    }
    auto bi2 = OHOS::NativeRdb::BigInteger(
        fdp.ConsumeIntegralInRange<int32_t>(-1, 1),
        std::move(vec)
    );

    // Validate copy semantics
    auto bi3 = OHOS::NativeRdb::BigInteger(bi1);
    bi3 = bi2;  // Test assignment operator

    // Stress test move semantics
    auto bi4 = OHOS::NativeRdb::BigInteger(std::move(bi2));
    bi1 = std::move(bi3);

    // Verify core operations
    (void)(bi1 == bi4);  // Compare equality
    (void)(bi1 < bi4);   // Compare ordering

    // Exercise all public methods
    (void)bi1.Sign();     // Validate sign retrieval
    (void)bi1.Size();     // Check array size
    (void)bi1.TrueForm(); // Access raw data
    (void)bi1.Value();    // Test value copy
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::BigIntegerFuzzTest(fdp);
    return 0;
}
