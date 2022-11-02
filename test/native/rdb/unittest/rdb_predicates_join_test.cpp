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

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <ctime>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "abs_predicates.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbStorePredicateJoinTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void GenerateAllTables();
    void InsertUserDates();
    void InsertBookDates();
    int ResultSize(std::unique_ptr<ResultSet> &resultSet);

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

const std::string RdbStorePredicateJoinTest::DATABASE_NAME = RDB_TEST_PATH + "predicates_join_test.db";
std::shared_ptr<RdbStore> RdbStorePredicateJoinTest::store = nullptr;
const std::string CREATE_TABLE_USER_SQL = std::string("CREATE TABLE IF NOT EXISTS user ") +
      std::string("(userId INTEGER PRIMARY KEY AUTOINCREMENT, firstName TEXT, lastName TEXT,") +
      std::string("age INTEGER , balance REAL  NOT NULL)");
const std::string CREATE_TABLE_BOOK_SQL = std::string("CREATE TABLE IF NOT EXISTS book ") +
      std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT, userId INTEGER,") +
      std::string("FOREIGN KEY (userId) REFERENCES user (userId) ON UPDATE NO ACTION ON DELETE CASCADE)");

class PredicateJoinTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
};


int PredicateJoinTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int PredicateJoinTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStorePredicateJoinTest::SetUpTestCase(void) {}

void RdbStorePredicateJoinTest::TearDownTestCase(void) {}

void RdbStorePredicateJoinTest::SetUp(void)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStorePredicateJoinTest::DATABASE_NAME);
    PredicateJoinTestOpenCallback helper;
    RdbStorePredicateJoinTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbStorePredicateJoinTest::store, nullptr);
    RdbStorePredicateJoinTest::GenerateAllTables();
}

void RdbStorePredicateJoinTest::TearDown(void)
{
    RdbHelper::DeleteRdbStore(RdbStorePredicateJoinTest::DATABASE_NAME);
}

void RdbStorePredicateJoinTest::GenerateAllTables()
{
    RdbStorePredicateJoinTest::store->ExecuteSql(CREATE_TABLE_USER_SQL);
    RdbStorePredicateJoinTest::InsertUserDates();

    RdbStorePredicateJoinTest::store->ExecuteSql(CREATE_TABLE_BOOK_SQL);
    RdbStorePredicateJoinTest::InsertBookDates();
}

void RdbStorePredicateJoinTest::InsertUserDates()
{
    int64_t  id;
    ValuesBucket values;

    values.PutInt("userId", 1);
    values.PutString("firstName", std::string("Zhang"));
    values.PutString("lastName", std::string("San"));
    values.PutInt("age", 29);
    values.PutDouble("balance", 100.51);
    store->Insert(id, "user", values);

    values.Clear();
    values.PutInt("userId", 2);
    values.PutString("firstName", std::string("Li"));
    values.PutString("lastName", std::string("Si"));
    values.PutInt("age", 30);
    values.PutDouble("balance", 200.51);
    store->Insert(id, "user", values);

    values.Clear();
    values.PutInt("userId", 3);
    values.PutString("firstName", std::string("Wang"));
    values.PutString("lastName", std::string("Wu"));
    values.PutInt("age", 30);
    values.PutDouble("balance", 300.51);
    store->Insert(id, "user", values);

    values.Clear();
    values.PutInt("userId", 4);
    values.PutString("firstName", std::string("Sun"));
    values.PutString("lastName", std::string("Liu"));
    values.PutInt("age", 31);
    values.PutDouble("balance", 400.51);
    store->Insert(id, "user", values);

    values.Clear();
    values.PutInt("userId", 5);
    values.PutString("firstName", std::string("Ma"));
    values.PutString("lastName", std::string("Qi"));
    values.PutInt("age", 32);
    values.PutDouble("balance", 500.51);
    store->Insert(id, "user", values);
}

void RdbStorePredicateJoinTest::InsertBookDates()
{
    int64_t  id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("SanGuo"));
    values.PutInt("userId", 1);
    store->Insert(id, "book", values);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("XiYouJi"));
    values.PutInt("userId", 2);
    store->Insert(id, "book", values);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("ShuiHuZhuan"));
    values.PutInt("userId", 3);
    store->Insert(id, "book", values);
}

int RdbStorePredicateJoinTest::ResultSize(std::unique_ptr<ResultSet> &resultSet)
{
    if (resultSet->GoToFirstRow() != E_OK) {
        return 0;
    }
    int count = 1;
    while (resultSet->GoToNextRow() == E_OK) {
        count++;
    }
    return count;
}

/* *
 * @tc.name: RdbStore_CrossJoin_001
 * @tc.desc: Normal testCase of RdbPredicates for CrossJoin
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateJoinTest, RdbStore_CrossJoin_001, TestSize.Level1)
{
    RdbPredicates predicates("user");

    std::vector<std::string> clauses;
    clauses.push_back("user.userId = book.userId");
    predicates.CrossJoin("book")->On(clauses);

    std::vector<std::string> joinTypes;
    joinTypes.push_back("CROSS JOIN");
    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());
    EXPECT_EQ("book", predicates.GetJoinTableNames()[0]);
    EXPECT_EQ("ON(user.userId = book.userId)", predicates.GetJoinConditions()[0]);
    EXPECT_EQ("user CROSS JOIN book ON(user.userId = book.userId)", predicates.GetJoinClause());

    std::vector<std::string> columns;
    std::unique_ptr<ResultSet> allDataTypes = RdbStorePredicateJoinTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));

    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());
    int userId;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(0, userId));
    EXPECT_EQ(1, userId);

    std::string firstName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(1, firstName));
    EXPECT_EQ("Zhang", firstName);

    std::string lastName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(2, lastName));
    EXPECT_EQ("San", lastName);

    int age;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(3, age));
    EXPECT_EQ(29, age);

    double balance;
    EXPECT_EQ(E_OK, allDataTypes->GetDouble(4, balance));
    EXPECT_EQ(100.51, balance);

    int id;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(5, id));
    EXPECT_EQ(1, id);

    std::string name;
    EXPECT_EQ(E_OK, allDataTypes->GetString(6, name));
    EXPECT_EQ("SanGuo", name);

    int userId_1;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(7, userId_1));
    EXPECT_EQ(1, userId_1);
}

/* *
 * @tc.name: RdbStore_InnerJoin_002
 * @tc.desc: Normal testCase of RdbPredicates for InnerJoin
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateJoinTest, RdbStore_InnerJoin_002, TestSize.Level1)
{
    RdbPredicates predicates("user");

    std::vector<std::string> clauses;
    clauses.push_back("user.userId = book.userId");
    predicates.InnerJoin("book")->On(clauses)->EqualTo("book.name", "SanGuo");

    std::vector<std::string> joinTypes;
    joinTypes.push_back("INNER JOIN");
    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());
    EXPECT_EQ("ON(user.userId = book.userId)", predicates.GetJoinConditions()[0]);

    std::vector<std::string> columns;
    std::unique_ptr<ResultSet> allDataTypes = RdbStorePredicateJoinTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());

    int userId;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(0, userId));
    EXPECT_EQ(1, userId);

    std::string firstName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(1, firstName));
    EXPECT_EQ("Zhang", firstName);

    std::string lastName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(2, lastName));
    EXPECT_EQ("San", lastName);

    int age;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(3, age));
    EXPECT_EQ(29, age);

    double balance;
    EXPECT_EQ(E_OK, allDataTypes->GetDouble(4, balance));
    EXPECT_EQ(100.51, balance);

    int id;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(5, id));
    EXPECT_EQ(1, id);

    std::string name;
    EXPECT_EQ(E_OK, allDataTypes->GetString(6, name));
    EXPECT_EQ("SanGuo", name);

    int userId_1;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(7, userId_1));
    EXPECT_EQ(1, userId_1);
}

/* *
 * @tc.name: RdbStore_LeftOuterJoin_003
 * @tc.desc: Normal testCase of RdbPredicates for LeftOuterJoin
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateJoinTest, RdbStore_LeftOuterJoin_003, TestSize.Level1)
{
    RdbPredicates predicates("user");

    std::vector<std::string> fields;
    fields.push_back("userId");
    predicates.LeftOuterJoin("book")->Using(fields)->EqualTo("name", "SanGuo");

    std::vector<std::string> joinTypes;
    joinTypes.push_back("LEFT OUTER JOIN");
    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());
    EXPECT_EQ("USING(userId)", predicates.GetJoinConditions()[0]);

    std::vector<std::string> columns;
    std::unique_ptr<ResultSet> allDataTypes = RdbStorePredicateJoinTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());

    int userId;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(0, userId));
    EXPECT_EQ(1, userId);

    std::string firstName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(1, firstName));
    EXPECT_EQ("Zhang", firstName);

    std::string lastName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(2, lastName));
    EXPECT_EQ("San", lastName);

    int age;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(3, age));
    EXPECT_EQ(29, age);

    double balance;
    EXPECT_EQ(E_OK, allDataTypes->GetDouble(4, balance));
    EXPECT_EQ(100.51, balance);

    int id;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(5, id));
    EXPECT_EQ(1, id);

    std::string name;
    EXPECT_EQ(E_OK, allDataTypes->GetString(6, name));
    EXPECT_EQ("SanGuo", name);
}

/* *
 * @tc.name: RdbStore_LeftOuterJoin_004
 * @tc.desc: Normal testCase of RdbPredicates for LeftOuterJoin
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateJoinTest, RdbStore_LeftOuterJoin_004, TestSize.Level1)
{
    RdbPredicates predicates("user");

    std::vector<std::string> clauses;
    clauses.push_back("user.userId = book.userId");
    std::vector<std::string> joinTypes;
    joinTypes.push_back("LEFT OUTER JOIN");

    predicates.LeftOuterJoin("book")->On(clauses);
    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());
    EXPECT_EQ("ON(user.userId = book.userId)", predicates.GetJoinConditions()[0]);

    std::vector<std::string> columns;
    std::unique_ptr<ResultSet> allDataTypes = RdbStorePredicateJoinTest::store->Query(predicates, columns);
    EXPECT_EQ(5, ResultSize(allDataTypes));
}
