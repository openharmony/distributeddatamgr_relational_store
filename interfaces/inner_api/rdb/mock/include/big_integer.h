/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_INTERFACES_INNER_API_RDB_INCLUDE_BIG_INTEGER_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_INTERFACES_INNER_API_RDB_INCLUDE_BIG_INTEGER_H
#include <cinttypes>
#include <unistd.h>
#include <vector>

namespace OHOS::NativeRdb {
class BigInteger final {
public:
    BigInteger() = default;
    ~BigInteger() = default;

    BigInteger(int64_t value);
    BigInteger(int32_t sign, std::vector<uint64_t> &&trueForm);
    BigInteger(const BigInteger &other);
    BigInteger(BigInteger &&other);
    BigInteger &operator=(const BigInteger &other);
    BigInteger &operator=(BigInteger &&other);
    bool operator==(const BigInteger &other);

    int32_t Sign() const;
    size_t Size() const;
    const uint64_t *TrueForm() const;

    std::vector<uint64_t> Value() const;
private:
    int32_t sign_ = 0;
    std::vector<uint64_t> value_;
};
}
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_INTERFACES_INNER_API_RDB_INCLUDE_BIG_INTEGER_H
