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

#ifndef NATIVE_RDB_VALUES_BUCKETS_H
#define NATIVE_RDB_VALUES_BUCKETS_H

#include <map>
#include <memory>
#include <set>

#include "value_object.h"
#include "values_bucket.h"

namespace OHOS {
namespace NativeRdb {
class API_EXPORT ValuesBuckets {
public:
    using FieldsType = std::shared_ptr<std::set<std::string>>;
    using ValuesType = std::shared_ptr<std::set<ValueObject>>;
    using FieldType = std::reference_wrapper<const std::string>;
    using ValueType = std::reference_wrapper<ValueObject>;
    using BucketType = std::map<FieldType, ValueType, std::less<std::string>>;

    API_EXPORT ValuesBuckets();
    API_EXPORT ValuesBuckets(const std::vector<ValuesBucket> &rows);
    API_EXPORT ValuesBuckets(std::vector<ValuesBucket> &&rows) noexcept;

    API_EXPORT size_t RowSize() const;
    API_EXPORT std::pair<FieldsType, ValuesType> GetFieldsAndValues() const;

    API_EXPORT void Reserve(int32_t size);
    API_EXPORT void Put(const ValuesBucket &bucket);
    API_EXPORT void Put(ValuesBucket &&bucket);
    API_EXPORT std::pair<int, ValueType> Get(size_t row, const FieldType &field) const;

    API_EXPORT void Clear();

private:
    FieldsType fields_;
    ValuesType values_;
    std::vector<BucketType> buckets_;
};

} // namespace NativeRdb
} // namespace OHOS
#endif
