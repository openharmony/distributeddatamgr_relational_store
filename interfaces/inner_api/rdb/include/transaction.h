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

#ifndef NATIVE_RDB_TRANSACTION_H
#define NATIVE_RDB_TRANSACTION_H

#include <functional>
#include <tuple>
#include <utility>
#include <vector>

#include "abs_rdb_predicates.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_types.h"
#include "rdb_visibility.h"
#include "result_set.h"
#include "values_bucket.h"
#include "values_buckets.h"

namespace OHOS::NativeRdb {
class Connection;
class API_EXPORT Transaction {
public:
    /**
     * @brief Use Fields replace std::vector<std::string> columns.
     */
    using Fields = std::vector<std::string>;

    /**
     * @brief Use Values replace std::vector<ValueObject> args.
     */
    using Values = std::vector<ValueObject>;

    /**
     * @brief Use Row replace ValuesBucket.
     */
    using Row = ValuesBucket;

    /**
     * @brief Use Rows replace std::vector<Row>.
     */
    using Rows = std::vector<Row>;

    /**
     * @brief Use Rows replace std::vector<Row>.
     */
    using RefRows = ValuesBuckets;

    /**
     * @brief Use Resolution replace ConflictResolution.
     */
    using Resolution = ConflictResolution;

    static constexpr Resolution NO_ACTION = ConflictResolution::ON_CONFLICT_NONE;

    enum TransactionType : int32_t {
        DEFERRED,
        IMMEDIATE,
        EXCLUSIVE,
        TRANS_BUTT,
    };

    using Creator = std::function<std::pair<int32_t, std::shared_ptr<Transaction>>(
        int32_t type, std::shared_ptr<Connection> connection, const std::string &)>;

    static std::pair<int32_t, std::shared_ptr<Transaction>> Create(
        int32_t type, std::shared_ptr<Connection> connection, const std::string &name);
    static int32_t RegisterCreator(Creator creator);

    virtual ~Transaction() = default;

    virtual int32_t Commit() = 0;
    virtual int32_t Rollback() = 0;
    virtual int32_t Close() = 0;

    /**
     * @brief Inserts a row of data into the target table.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data {@link ValuesBucket} to be inserted into the table.
     * @param resolution Indicates the {@link ConflictResolution} to insert data into the table.
     */
    virtual std::pair<int32_t, int64_t> Insert(
        const std::string &table, const Row &row, Resolution resolution = NO_ACTION) = 0;

    /**
     * @brief Inserts a batch of data into the target table.
     *
     * @param table Indicates the target table.
     * @param rows Indicates the rows of data {@link ValuesBucket} to be inserted into the table.
     */
    virtual std::pair<int32_t, int64_t> BatchInsert(const std::string &table, const Rows &rows) = 0;

    /**
     * @brief Inserts a batch of data into the target table.
     *
     * @param table Indicates the target table.
     * @param values Indicates the rows of data {@link ValuesBuckets} to be inserted into the table.
     */
    virtual std::pair<int32_t, int64_t> BatchInsert(const std::string &table, const RefRows &rows) = 0;

    /**
     * @brief Updates data in the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param args Indicates the where arguments.
     */
    virtual std::pair<int, int> Update(const std::string &table, const Row &row, const std::string &where = "",
        const Values &args = {}, Resolution resolution = NO_ACTION) = 0;

    /**
     * @brief Updates data in the database based on a a specified instance object of AbsRdbPredicates.
     *
     * @param values Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     */
    virtual std::pair<int32_t, int32_t> Update(
        const Row &row, const AbsRdbPredicates &predicates, Resolution resolution = NO_ACTION) = 0;

    /**
     * @brief Deletes data from the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param whereClause Indicates the where clause.
     * @param args Indicates the where arguments.
     */
    virtual std::pair<int32_t, int32_t> Delete(
        const std::string &table, const std::string &whereClause = "", const Values &args = {}) = 0;

    /**
     * @brief Deletes data from the database based on a specified instance object of AbsRdbPredicates.
     *
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     */
    virtual std::pair<int32_t, int32_t> Delete(const AbsRdbPredicates &predicates) = 0;

    /**
     * @brief Queries data in the database based on SQL statement.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the selection arguments.
     * @param preCount IIndicates whether to calculate the count during query.
     */
    virtual std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const Values &args = {},
        bool preCount = true) = 0;

    /**
     * @brief Queries data in the database based on specified conditions.
     *
     * @param predicates Indicates the specified query condition by the instance object of {@link AbsRdbPredicates}.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     * @param preCount IIndicates whether to calculate the count during query.
     */
    virtual std::shared_ptr<ResultSet> QueryByStep(const AbsRdbPredicates &predicates, const Fields &columns = {},
        bool preCount = true) = 0;

    /**
     * @brief Executes an SQL statement that contains specified parameters and
     *        get two values of type int and ValueObject.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual std::pair<int32_t, ValueObject> Execute(const std::string &sql, const Values &args = {}) = 0;

private:
    static inline Creator creator_;
};
} // namespace OHOS::NativeRdb
#endif
