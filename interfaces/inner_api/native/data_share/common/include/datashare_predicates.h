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

#ifndef DATASHARE_PREDICATES_H
#define DATASHARE_PREDICATES_H

#include "datashare_abs_predicates.h"

#include <parcel.h>
#include <list>
#include <string>

#include "datashare_predicates_def.h"
#include "datashare_predicates_object.h"

namespace OHOS {
namespace DataShare {
class DataSharePredicates : public virtual DataShareAbsPredicates, public virtual OHOS::Parcelable {
public:
    DataSharePredicates();
    explicit DataSharePredicates(Predicates &predicates);
    explicit DataSharePredicates(std::string &tablename);
    ~DataSharePredicates();
    DataSharePredicates *EqualTo(const std::string &field, const int value)override;
    DataSharePredicates *EqualTo(const std::string &field, const int64_t value)override;
    DataSharePredicates *EqualTo(const std::string &field, const double value)override;
    DataSharePredicates *EqualTo(const std::string &field, const std::string &value)override;
    DataSharePredicates *EqualTo(const std::string &field, const bool value)override;
    DataSharePredicates *NotEqualTo(const std::string &field, const int value)override;
    DataSharePredicates *NotEqualTo(const std::string &field, const int64_t value)override;
    DataSharePredicates *NotEqualTo(const std::string &field, const double value)override;
    DataSharePredicates *NotEqualTo(const std::string &field, const std::string &value)override;
    DataSharePredicates *NotEqualTo(const std::string &field, const bool value)override;
    DataSharePredicates *GreaterThan(const std::string &field, const int value)override;
    DataSharePredicates *GreaterThan(const std::string &field, const int64_t value)override;
    DataSharePredicates *GreaterThan(const std::string &field, const double value)override;
    DataSharePredicates *GreaterThan(const std::string &field, const std::string &value)override;
    DataSharePredicates *LessThan(const std::string &field, const int value)override;
    DataSharePredicates *LessThan(const std::string &field, const int64_t value)override;
    DataSharePredicates *LessThan(const std::string &field, const double value)override;
    DataSharePredicates *LessThan(const std::string &field, const std::string &value)override;
    DataSharePredicates *GreaterThanOrEqualTo(const std::string &field, const int value)override;
    DataSharePredicates *GreaterThanOrEqualTo(const std::string &field, const int64_t value)override;
    DataSharePredicates *GreaterThanOrEqualTo(const std::string &field, const double value)override;
    DataSharePredicates *GreaterThanOrEqualTo(const std::string &field, const std::string &value)override;
    DataSharePredicates *LessThanOrEqualTo(const std::string &field, const int value)override;
    DataSharePredicates *LessThanOrEqualTo(const std::string &field, const int64_t value)override;
    DataSharePredicates *LessThanOrEqualTo(const std::string &field, const double value)override;
    DataSharePredicates *LessThanOrEqualTo(const std::string &field, const std::string &value)override;
    DataSharePredicates *In(const std::string &field, const std::vector<int> &values)override;
    DataSharePredicates *In(const std::string &field, const std::vector<int64_t> &values)override;
    DataSharePredicates *In(const std::string &field, const std::vector<double> &values)override;
    DataSharePredicates *In(const std::string &field, const std::vector<std::string> &values)override;
    DataSharePredicates *NotIn(const std::string &field, const std::vector<int> &values)override;
    DataSharePredicates *NotIn(const std::string &field, const std::vector<int64_t> &values)override;
    DataSharePredicates *NotIn(const std::string &field, const std::vector<double> &values)override;
    DataSharePredicates *NotIn(const std::string &field, const std::vector<std::string> &values)override;
    DataSharePredicates *BeginWrap()override;
    DataSharePredicates *EndWrap()override;
    DataSharePredicates *Or()override;
    DataSharePredicates *And()override;
    DataSharePredicates *Contains(const std::string &field, const std::string &value)override;
    DataSharePredicates *BeginsWith(const std::string &field, const std::string &value)override;
    DataSharePredicates *EndsWith(const std::string &field, const std::string &value)override;
    DataSharePredicates *IsNull(const std::string &field)override;
    DataSharePredicates *IsNotNull(const std::string &field)override;
    DataSharePredicates *Like(const std::string &field, const std::string &value)override;
    DataSharePredicates *Unlike(const std::string &field, const std::string &value);
    DataSharePredicates *Glob(const std::string &field, const std::string &value)override;
    DataSharePredicates *Between(const std::string &field, const std::string &low, const std::string &high)override;
    DataSharePredicates *NotBetween(const std::string &field, const std::string &low, const std::string &high)override;
    DataSharePredicates *OrderByAsc(const std::string &field)override;
    DataSharePredicates *OrderByDesc(const std::string &field)override;
    DataSharePredicates *Distinct()override;
    DataSharePredicates *Limit(const int number, const int offset)override;
    DataSharePredicates *Offset(int rowOffset)override;
    DataSharePredicates *GroupBy(const std::vector<std::string> &fields)override;
    DataSharePredicates *IndexedBy(const std::string &indexName)override;
    DataSharePredicates *Reset()override;
    DataSharePredicates *KeyPrefix(const std::string &prefix);
    DataSharePredicates *InDevices(const std::vector<std::string> &devices);
    DataSharePredicates *InAllDevices();
    DataSharePredicates *SetSuggestIndex(const std::string &index);
    DataSharePredicates *InKeys(const std::vector<std::string> &keys);
    bool Marshalling(OHOS::Parcel &parcel) const override;
    static DataSharePredicates *Unmarshalling(OHOS::Parcel &parcel);
    const std::list<OperationItem>& GetOperationList() const;
    std::string GetTableName() const;

private:
    void SetOperationList(OperationType operationType, DataSharePredicatesObject &para1,
        DataSharePredicatesObject &para2, DataSharePredicatesObject &para3, ParameterCount parameterCount);
    Predicates predicates_;
};
} // namespace DataShare
} // namespace OHOS

#endif