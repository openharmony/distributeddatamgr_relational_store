/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "values_bucket.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "itypes_util.h"
#endif
namespace OHOS {
namespace NativeRdb {
ValuesBucket::ValuesBucket()
{
}

ValuesBucket::ValuesBucket(std::map<std::string, ValueObject> values) : values_(std::move(values))
{
}

ValuesBucket::ValuesBucket(const ValuesBucket &values) : values_(values.values_)
{
}

ValuesBucket &ValuesBucket::operator=(const ValuesBucket &values)
{
    values_ = values.values_;
    return *this;
}

ValuesBucket::ValuesBucket(ValuesBucket &&values) noexcept : values_(std::move(values.values_))
{
}

ValuesBucket &ValuesBucket::operator=(ValuesBucket &&values) noexcept
{
    values_ = std::move(values.values_);
    return *this;
}

ValuesBucket::~ValuesBucket()
{
}

void ValuesBucket::PutString(const std::string &columnName, const std::string &value)
{
    values_.insert(std::make_pair(columnName, ValueObject(value)));
}

void ValuesBucket::PutInt(const std::string &columnName, int value)
{
    values_.insert(std::make_pair(columnName, ValueObject(value)));
}

void ValuesBucket::PutLong(const std::string &columnName, int64_t value)
{
    values_.insert(std::make_pair(columnName, ValueObject(value)));
}

void ValuesBucket::PutDouble(const std::string &columnName, double value)
{
    values_.insert(std::make_pair(columnName, ValueObject(value)));
}

void ValuesBucket::PutBool(const std::string &columnName, bool value)
{
    values_.insert(std::make_pair(columnName, ValueObject(value)));
}

void ValuesBucket::PutBlob(const std::string &columnName, const std::vector<uint8_t> &value)
{
    values_.insert(std::make_pair(columnName, ValueObject(value)));
}

void ValuesBucket::PutNull(const std::string &columnName)
{
    values_.insert(std::make_pair(columnName, ValueObject()));
}

void ValuesBucket::Put(const std::string &columnName,  const ValueObject &value)
{
    values_.insert_or_assign(columnName, value);
}

void ValuesBucket::Delete(const std::string &columnName)
{
    values_.erase(columnName);
}

void ValuesBucket::Clear()
{
    values_.clear();
}

int ValuesBucket::Size() const
{
    return values_.size();
}

bool ValuesBucket::IsEmpty() const
{
    return values_.empty();
}

bool ValuesBucket::HasColumn(const std::string &columnName) const
{
    auto iter = values_.find(columnName);
    if (iter == values_.end()) {
        return false;
    }
    return true;
}

bool ValuesBucket::GetObject(const std::string &columnName, ValueObject &value) const
{
    auto iter = values_.find(columnName);
    if (iter == values_.end()) {
        return false;
    }
    value = iter->second;
    return true;
}

std::map<std::string, ValueObject> ValuesBucket::GetAll() const
{
    return values_;
}

void ValuesBucket::GetAll(std::map<std::string, ValueObject> &output) const
{
    output = values_;
}
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
bool ValuesBucket::Marshalling(Parcel &parcel) const
{
    MessageParcel *data = static_cast<MessageParcel *>(&parcel);
    if (data == nullptr) {
        return false;
    }
    return ITypesUtil::Marshal(*data, values_);
}

ValuesBucket ValuesBucket::Unmarshalling(Parcel &parcel)
{
    MessageParcel *data = static_cast<MessageParcel *>(&parcel);
    if (data == nullptr) {
        return {};
    }
    ValuesBucket bucket;
    ITypesUtil::Unmarshal(*data, bucket.values_);
    return bucket;
}
#endif
} // namespace NativeRdb
} // namespace OHOS
