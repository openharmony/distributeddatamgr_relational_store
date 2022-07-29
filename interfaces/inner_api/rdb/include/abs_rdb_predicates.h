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


#ifndef NATIVE_RDB_ABSRDBPREDICATES_H
#define NATIVE_RDB_ABSRDBPREDICATES_H

#include "abs_predicates.h"
#include "rdb_types.h"

namespace OHOS::NativeRdb {
class AbsRdbPredicates : public AbsPredicates {
public:
    explicit AbsRdbPredicates(std::string tableName);

    ~AbsRdbPredicates() override {}

    void Clear() override;
    
    std::string ToString() const;

    std::string GetTableName() const;

    AbsRdbPredicates *InDevices(std::vector<std::string>& devices);
    
    AbsRdbPredicates *InAllDevices();

    AbsRdbPredicates* EqualTo(std::string field, std::string value) override;
    AbsRdbPredicates* NotEqualTo(std::string field, std::string value) override;
    AbsRdbPredicates* And() override;
    AbsRdbPredicates* Or() override;
    AbsRdbPredicates* OrderByAsc(std::string field) override;
    AbsRdbPredicates* OrderByDesc(std::string field) override;

    const DistributedRdb::RdbPredicates& GetDistributedPredicates() const;

    virtual void InitialParam();
    virtual std::vector<std::string> GetJoinTypes();
    virtual void SetJoinTypes(const std::vector<std::string> joinTypes);
    virtual std::vector<std::string> GetJoinTableNames();
    virtual void SetJoinTableNames(const std::vector<std::string> joinTableNames);
    virtual std::vector<std::string> GetJoinConditions();
    virtual void SetJoinConditions(const std::vector<std::string> joinConditions);
    virtual std::string GetJoinClause() const;
    virtual int GetJoinCount() const;
    virtual void SetJoinCount(int joinCount);

protected:
    std::vector<std::string> joinTypes;
    std::vector<std::string> joinTableNames;
    std::vector<std::string> joinConditions;
    int joinCount = 0;

private:
    std::string tableName;
    mutable DistributedRdb::RdbPredicates predicates_;
};
} // namespace OHOS::NativeRdb

#endif