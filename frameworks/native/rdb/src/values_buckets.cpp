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

size_t ValuesBuckets::RowSize() const
{
    return buckets_.size();
}

std::pair<ValuesBuckets::FieldsType, ValuesBuckets::ValuesType> ValuesBuckets::GetFieldsAndValues() const
{
    return { fields_, values_ };
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
} // namespace NativeRdb
} // namespace OHOS
