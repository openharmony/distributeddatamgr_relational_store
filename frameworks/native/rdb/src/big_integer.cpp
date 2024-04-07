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

#include "big_integer.h"

namespace OHOS::NativeRdb {
BigInteger::BigInteger(int64_t value)
{
    if (value < 0) {
        sign_ = 1;
        value *= -1;
    }
    value_.push_back(value);
}

BigInteger::BigInteger(int32_t sign, std::vector<uint64_t>&& trueForm)
    : sign_(sign), value_(std::move(trueForm))
{
}

BigInteger::BigInteger(const BigInteger& other)
{
    operator=(other);
}

BigInteger::BigInteger(BigInteger&& other)
{
    operator=(std::move(other));
}

BigInteger& BigInteger::operator=(const BigInteger& other)
{
    if (this == &other) {
        return *this;
    }
    sign_ = other.sign_;
    value_ = other.value_;
    return *this;
}

BigInteger& BigInteger::operator=(BigInteger&& other)
{
    if (this == &other) {
        return *this;
    }
    sign_ = other.sign_;
    value_ = std::move(other.value_);
    other.sign_ = 0;
    return *this;
}

bool BigInteger::operator==(const BigInteger& other)
{
    if (sign_ != other.sign_) {
        return false;
    }
    return value_ == other.value_;
}

int32_t BigInteger::Sign() const
{
    return sign_;
}

size_t BigInteger::Size() const
{
    return value_.size();
}

const uint64_t* BigInteger::TrueForm() const
{
    return value_.data();
}

std::vector<uint64_t> BigInteger::Value() const
{
    return value_;
}
}