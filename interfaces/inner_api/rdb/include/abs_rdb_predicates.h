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
class API_EXPORT AbsRdbPredicates : public AbsPredicates {
public:
    /**
     * @brief Constructor.
     *
     * A parameterized constructor used to create an AbsRdbPredicates instance.
     *
     * @param tableName Indicates the table name of the database.
     */
    API_EXPORT explicit AbsRdbPredicates(const std::string &tableName);

    /**
     * @brief Constructor.
     *
     * A parameterized constructor used to create an AbsRdbPredicates instance.
     *
     * @param tableName Indicates the table name of the database.
     */
    API_EXPORT explicit AbsRdbPredicates(const std::vector<std::string> &tables);

    /**
     * @brief Destructor.
     */
    API_EXPORT ~AbsRdbPredicates() override {}

    /**
     * @brief Initalzie AbsRdbPredicates object.
     */
    API_EXPORT void Clear() override;

    /**
     * @brief Obtains the parameters of the current AbsRdbPredicates object.
     */
    [[deprecated("Use GetStatement() instead.")]]
    API_EXPORT std::string ToString() const;

    /**
     * @brief Obtains the table name.
     */
    API_EXPORT std::string GetTableName() const;

    /**
     * @brief Sync data between devices.
     *
     * When query database, this function should not be called.
     *
     * @param devices Indicates specified remote devices.
     *
     * @return Returns the self.
     */
    API_EXPORT AbsRdbPredicates *InDevices(std::vector<std::string>& devices);

    /**
     * @brief Specify all remote devices which connect to local device when syncing distributed database.
     *
     * When query database, this function should not be called.
     *
     * @return Returns the self.
     */
    API_EXPORT AbsRdbPredicates *InAllDevices();

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
    API_EXPORT AbsRdbPredicates* EqualTo(const std::string &field, const ValueObject &value) override;

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
    API_EXPORT AbsRdbPredicates* NotEqualTo(const std::string &field, const ValueObject &value) override;

    /**
     * @brief Adds an and condition to the remote AbsRdbPredicates.
     *
     * This method is similar to or of the SQL statement.
     */
    API_EXPORT AbsRdbPredicates* And() override;

    /**
     * @brief Adds an or condition to the remote AbsRdbPredicates.
     *
     * This method is similar to or of the SQL statement.
     */
    API_EXPORT AbsRdbPredicates* Or() override;

    /**
     * @brief Adds an left bracket condition to the remote AbsRdbPredicates.
     *
     * This method is similar to left bracket of the SQL statement.
     */
    API_EXPORT AbsPredicates *BeginWrap() override;

    /**
     * @brief Adds an right bracket condition to the remote AbsRdbPredicates.
     *
     * This method is similar to right bracket of the SQL statement.
     */
    API_EXPORT virtual AbsPredicates *EndWrap() override;

    /**
     * @brief Adds an In condition to the remote AbsRdbPredicates.
     *
     * This method is similar to In of the SQL statement.
     */
    API_EXPORT virtual AbsPredicates *In(const std::string &field, const std::vector<ValueObject> &values) override;

    /**
     * @brief Adds an In condition to the remote AbsRdbPredicates.
     *
     * This method is similar to In of the SQL statement.
     */
    API_EXPORT virtual AbsPredicates *In(const std::string &field, const std::vector<std::string> &values) override;

    /**
     * @brief Adds an Contains condition to the remote AbsRdbPredicates.
     *
     * This method indicates that the expected field contains value.
     */
    API_EXPORT AbsRdbPredicates *Contains(const std::string &field, const std::string &value) override;

    /**
     * @brief Adds an Not Contains condition to the remote AbsRdbPredicates.
     *
     * This method indicates that the expected field not contains value.
     */
    API_EXPORT AbsRdbPredicates *NotContains(const std::string &field, const std::string &value) override;

    /**
     * @brief Adds an BeginsWith condition to the remote AbsRdbPredicates.
     *
     * This method indicates that the expected field begin with value.
     */
    API_EXPORT AbsRdbPredicates *BeginsWith(const std::string &field, const std::string &value) override;

    /**
     * @brief Adds an EndsWith condition to the remote AbsRdbPredicates.
     *
     * This method indicates that the expected field end with value.
     */
    API_EXPORT AbsRdbPredicates *EndsWith(const std::string &field, const std::string &value) override;

    /**
     * @brief Adds an IsNull condition to the remote AbsRdbPredicates.
     *
     * This method indicates that the expected field is null.
     */
    API_EXPORT AbsRdbPredicates *IsNull(const std::string &field) override;

    /**
     * @brief Adds an IsNotNull condition to the remote AbsRdbPredicates.
     *
     * This method indicates that the expected field is not null.
     */
    API_EXPORT AbsRdbPredicates *IsNotNull(const std::string &field) override;

    /**
     * @brief Adds an Like condition to the remote AbsRdbPredicates.
     *
     * This method is similar to Like of the SQL statement.
     */
    API_EXPORT AbsRdbPredicates *Like(const std::string &field, const std::string &value) override;

    /**
     * @brief Adds an Like condition to the remote AbsRdbPredicates.
     *
     * This method is similar to Like of the SQL statement.
     */
    API_EXPORT AbsRdbPredicates *NotLike(const std::string &field, const std::string &value) override;

    /**
     * @brief Adds an Glob condition to the remote AbsRdbPredicates.
     *
     * This method is similar to glob of the SQL statement.
     */
    API_EXPORT AbsRdbPredicates *Glob(const std::string &field, const std::string &value) override;

    /**
     * @brief Adds an Distinct condition to the remote AbsRdbPredicates.
     *
     * This method is similar to distinct of the SQL statement.
     */
    API_EXPORT AbsRdbPredicates *Distinct() override;

    /**
     * @brief Adds an IndexedBy condition to the remote AbsRdbPredicates.
     *
     * This method is similar to indexed by of the SQL statement.
     */
    API_EXPORT AbsRdbPredicates *IndexedBy(const std::string &indexName) override;

    /**
     * @brief Adds an NotIn condition to the remote AbsRdbPredicates.
     *
     * This method is similar to not in of the SQL statement.
     */
    API_EXPORT AbsRdbPredicates *NotIn(const std::string &field, const std::vector<std::string> &values) override;

    /**
     * @brief Adds an NotIn condition to the remote AbsRdbPredicates.
     *
     * This method is similar to not in of the SQL statement.
     */
    API_EXPORT AbsRdbPredicates *NotIn(const std::string &field, const std::vector<ValueObject> &values) override;

    /**
     * @brief Restricts the ascending order of the return list. When there are several orders,
     * the one close to the head has the highest priority.
     *
     * @param field Indicates the column name for sorting the return list.
     */
    API_EXPORT AbsRdbPredicates* OrderByAsc(const std::string &field) override;

    /**
     * @brief Restricts the descending order of the return list. When there are several orders,
     * the one close to the head has the highest priority.
     *
     * @param field Indicates the column name for sorting the return list.
     */
    API_EXPORT AbsRdbPredicates* OrderByDesc(const std::string &field) override;

    /**
     * @brief Get predicates of remote device.
     */
    API_EXPORT const DistributedRdb::PredicatesMemo & GetDistributedPredicates() const;

    /**
     * @brief Initialize relevant parameters of the union table.
     */
    API_EXPORT virtual void InitialParam();

    /**
     * @brief Obtains the join types in the predicates.
     */
    API_EXPORT virtual std::vector<std::string> GetJoinTypes();

    /**
     * @brief Sets the join types in the predicates. The value can be {@code INNER JOIN}, {@code LEFT OUTER JOIN},
     * and {@code CROSS JOIN}.
     */
    API_EXPORT virtual void SetJoinTypes(const std::vector<std::string> &joinTypes);

    /**
     * @brief Obtains the database table names of the joins in the predicates.
     */
    API_EXPORT virtual std::vector<std::string> GetJoinTableNames();

    /**
     * @brief Sets the database table names of the joins in the predicates.
     */
    API_EXPORT virtual void SetJoinTableNames(const std::vector<std::string> &joinTableNames);

    /**
     * @brief Obtains the join conditions in the predicates.
     */
    API_EXPORT virtual std::vector<std::string> GetJoinConditions();

    /**
     * @brief Sets the join conditions required in the predicates.
     */
    API_EXPORT virtual void SetJoinConditions(const std::vector<std::string> &joinConditions);

    /**
     * @brief Obtains the join clause in the predicates.
     */
    API_EXPORT virtual std::string GetJoinClause() const;

    /**
     * @brief Obtains the number of joins in the predicates.
     */
    API_EXPORT virtual int GetJoinCount() const;

    /**
     * @brief Sets the number of joins in the predicates.
     */
    API_EXPORT virtual void SetJoinCount(int joinCount);

    static constexpr const char *LOCK_STATUS = "#_status";
    static constexpr int LOCKED = 2;
    static constexpr int LOCK_CHANGED = 3;

protected:
    std::vector<std::string> joinTypes;
    std::vector<std::string> joinTableNames;
    std::vector<std::string> joinConditions;
    int joinCount = 0;

private:
    std::string tableName_;
    mutable DistributedRdb::PredicatesMemo predicates_;
};
} // namespace OHOS::NativeRdb

#endif