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
#include "values_buckets.h"

#include "rdb_errno.h"

namespace OHOS {
namespace NativeRdb {
ValuesBuckets::ValuesBuckets()
{
    fields_ = std::make_shared<std::set<std::string>>();
    values_ = std::make_shared<std::set<ValueObject>>();
}

ValuesBuckets::ValuesBuckets(const std::vector<ValuesBucket> &rows) : ValuesBuckets()
{
    buckets_.reserve(rows.size());
    for (const auto &bucket : rows) {
        Put(bucket);
    }
}

ValuesBuckets::ValuesBuckets(std::vector<ValuesBucket> &&rows) : ValuesBuckets()
{
    buckets_.reserve(rows.size());
    for (auto &bucket : rows) {
        Put(std::move(bucket));
    }
}

size_t ValuesBuckets::RowSize() const
{
    return buckets_.size();
}

bool ValuesBuckets::Empty() const
{
    return buckets_.empty();
}

std::pair<ValuesBuckets::FieldsType, ValuesBuckets::ValuesType> ValuesBuckets::GetFieldsAndValues() const
{
    return { fields_, values_ };
}

void ValuesBuckets::Reserve(int32_t size)
{
    buckets_.reserve(size);
}

void ValuesBuckets::Clear()
{
    buckets_.clear();
    fields_->clear();
    values_->clear();
}

void ValuesBuckets::Put(const ValuesBucket &bucket)
{
    BucketType row;
    for (const auto &[field, value] : bucket.values_) {
        auto fieldResult = fields_->insert(field);
        auto valueResult = values_->insert(value);
        row.insert(std::make_pair(std::ref(const_cast<std::string &>(*fieldResult.first)),
            std::ref(const_cast<ValueObject &>(*valueResult.first))));
    }
    buckets_.push_back(std::move(row));
}

void ValuesBuckets::Put(ValuesBucket &&bucket)
{
    BucketType row;
    for (auto &[field, value] : bucket.values_) {
        auto fieldResult = fields_->insert(std::move(field));
        auto valueResult = values_->insert(std::move(value));
        row.insert(std::make_pair(std::ref(const_cast<std::string &>(*fieldResult.first)),
            std::ref(const_cast<ValueObject &>(*valueResult.first))));
    }
    buckets_.push_back(std::move(row));
}

std::pair<int, ValuesBuckets::ValueType> ValuesBuckets::Get(size_t row, const FieldType &field) const
{
    ValueObject empty;
    std::reference_wrapper<ValueObject> emptyRef(empty);
    if (row >= buckets_.size()) {
        return { E_INVALID_ARGS, emptyRef };
    }

    auto &bucket = buckets_[row];
    auto it = bucket.find(field);
    if (it == bucket.end()) {
        return { E_INVALID_ARGS, emptyRef };
    }

    return { E_OK, it->second };
}

std::pair<int, std::vector<ValueObject>> ValuesBuckets::GetColumnValues(const std::string &field) const
{
    std::vector<ValueObject> res;
    res.reserve(buckets_.size());
    for (const auto &bucket : buckets_) {
        auto it = bucket.find(field);
        if (it == bucket.end()) {
            return { E_INVALID_ARGS, {} };
        }
        res.push_back(it->second);
    }
    return { E_OK, res };
}
} // namespace NativeRdb
} // namespace OHOS
