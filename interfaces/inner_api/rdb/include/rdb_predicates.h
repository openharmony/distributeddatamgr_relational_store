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

#ifndef NATIVE_RDB_RDBPREDICATES_H
#define NATIVE_RDB_RDBPREDICATES_H
#include "abs_rdb_predicates.h"
#include "rdb_visibility.h"

namespace OHOS {
namespace NativeRdb {
/**
 * The RdbPredicates class of RDB.
 */
class API_EXPORT RdbPredicates : public AbsRdbPredicates {
public:
    /**
     * @brief Constructor.
     *
     * A parameterized constructor used to create an AbsRdbPredicates instance.
     *
     * @param tableName Indicates the table name of the database.
     */
    API_EXPORT explicit RdbPredicates(const std::string &tableName);

    /**
     * @brief Destructor.
     */
    API_EXPORT ~RdbPredicates() override {}

    /**
     * @brief Obtains the join clause in the predicates.
     */
    API_EXPORT std::string GetJoinClause() const override;

    /**
     * @brief Adds a {@code cross join} condition to a SQL statement.
     */
    API_EXPORT RdbPredicates *CrossJoin(const std::string &tableName);

    /**
     * @brief Adds an {@code inner join} condition to a SQL statement.
     */
    API_EXPORT RdbPredicates *InnerJoin(const std::string &tableName);

    /**
      * @brief Adds a {@code left outer join} condition to a SQL statement.
      */
    API_EXPORT RdbPredicates *LeftOuterJoin(const std::string &tableName);

    /**
     * @brief Adds a {@code using} condition to the predicate.
     * This method is similar to {@code using} of the SQL statement.
     */
    API_EXPORT RdbPredicates *Using(const std::vector<std::string> &fields);

    /**
     * @brief Adds an {@code on} condition to the predicate.
     */
    API_EXPORT RdbPredicates *On(const std::vector<std::string> &clauses);

private:
    std::string ProcessJoins() const;
    std::string GetGrammar(int type) const;
    RdbPredicates *Join(int join, const std::string &tableName);
};
} // namespace NativeRdb
} // namespace OHOS

#endif