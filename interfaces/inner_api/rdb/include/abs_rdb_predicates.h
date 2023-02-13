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

/**
 * The AbsRdbPredicates class of RDB.
 */
namespace OHOS::NativeRdb {
class AbsRdbPredicates : public AbsPredicates {
public:
    /**
     * @brief Constructor.
     *
     * A parameterized constructor used to create an AbsRdbPredicates instance.
     *
     * @param tableName Indicates the table name of the database.
     */
    explicit AbsRdbPredicates(std::string tableName);
    /**
     * @brief Destructor.
     */
    ~AbsRdbPredicates() override {}
    /**
     * @brief Initalzie AbsRdbPredicates object.
     */
    void Clear() override;
    /**
     * @brief Obtains the parameters of the current AbsRdbPredicates object.
     */
    std::string ToString() const;
    /**
     * @brief Obtains the table name.
     */
    std::string GetTableName() const;
    /**
     * @brief Sync data between devices.
     *
     * When query database, this function should not be called.
     *
     * @param devices Indicates specified remote devices.
     *
     * @return Returns the self.
     */
    AbsRdbPredicates *InDevices(std::vector<std::string>& devices);
    /**
     * @brief Specify all remote devices which connect to local device when syncing distributed database.
     *
     * When query database, this function should not be called.
     *
     * @return Returns the self.
     */
    AbsRdbPredicates *InAllDevices();
    /**
     * @brief Restricts the value of the field to be equal to the specified value to the remote AbsRdbPredicates.
     *
     * This method is similar to = of the SQL statement.
     *
     * @param field Indicates the column name in the database table.
     * @param value Indicates the value to match with the {@link RdbPredicates}.
     *
     * @return Returns the self.
     */
    AbsRdbPredicates* EqualTo(std::string field, std::string value) override;
    /**
     * @brief Restricts the value of the field to be not equal to the specified value to the remote AbsRdbPredicates.
     *
     * This method is similar to != of the SQL statement.
     *
     * @param field Indicates the column name in the database table.
     * @param value Indicates the value to match with the {@link RdbPredicates}.
     *
     * @return Returns the self.
     */
    AbsRdbPredicates* NotEqualTo(std::string field, std::string value) override;
    /**
     * @brief Adds an and condition to the remote AbsRdbPredicates.
     *
     * This method is similar to or of the SQL statement.
     */
    AbsRdbPredicates* And() override;
    /**
     * @brief Adds an or condition to the remote AbsRdbPredicates.
     *
     * This method is similar to or of the SQL statement.
     */
    AbsRdbPredicates* Or() override;
    /**
     * @brief Restricts the ascending order of the return list. When there are several orders,
     * the one close to the head has the highest priority.
     *
     * @param field Indicates the column name for sorting the return list.
     */
    AbsRdbPredicates* OrderByAsc(std::string field) override;
    /**
     * @brief Restricts the descending order of the return list. When there are several orders,
     * the one close to the head has the highest priority.
     *
     * @param field Indicates the column name for sorting the return list.
     */
    AbsRdbPredicates* OrderByDesc(std::string field) override;
    /**
     * @brief Get predicates of remote device.
     */
    const DistributedRdb::RdbPredicates& GetDistributedPredicates() const;

    /**
     * @brief Initialize relevant parameters of the union table.
     */
    virtual void InitialParam();
    /**
     * @brief Obtains the join types in the predicates.
     */
    virtual std::vector<std::string> GetJoinTypes();
    /**
     * @brief Sets the join types in the predicates. The value can be {@code INNER JOIN}, {@code LEFT OUTER JOIN},
     * and {@code CROSS JOIN}.
     */
    virtual void SetJoinTypes(const std::vector<std::string> joinTypes);
    /**
     * @brief Obtains the database table names of the joins in the predicates.
     */
    virtual std::vector<std::string> GetJoinTableNames();
    /**
     * @brief Sets the database table names of the joins in the predicates.
     */
    virtual void SetJoinTableNames(const std::vector<std::string> joinTableNames);
    /**
     * @brief Obtains the join conditions in the predicates.
     */
    virtual std::vector<std::string> GetJoinConditions();
    /**
     * @brief Sets the join conditions required in the predicates.
     */
    virtual void SetJoinConditions(const std::vector<std::string> joinConditions);
    /**
     * @brief Obtains the join clause in the predicates.
     */
    virtual std::string GetJoinClause() const;
    /**
     * @brief Sets the number of joins in the predicates.
     */
    virtual int GetJoinCount() const;
    /**
     * @brief Sets the number of joins in the predicates.
     */
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