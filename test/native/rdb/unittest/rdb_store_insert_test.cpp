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

#include <gtest/gtest.h>

#include <string>

#include "common.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbInsertTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void CheckResultSet(std::shared_ptr<RdbStore> &store);
    void CheckAge(std::shared_ptr<ResultSet> &resultSet);
    void CheckSalary(std::shared_ptr<ResultSet> &resultSet);
    void CheckBlob(std::shared_ptr<ResultSet> &resultSet);

    static std::shared_ptr<RdbStore> store;
};

std::shared_ptr<RdbStore> RdbInsertTest::store = nullptr;

class InsertTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

const std::string CREATE_TABLE_TEST =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB, name1 TEXT, name2 TEXT "
                                                                  "name13 TEXT, name14 TEXT, name15 TEXT "
                                                                  "name23 TEXT, name24 TEXT, name25 TEXT "
                                                                  "name33 TEXT, name34 TEXT, name35 TEXT "
                                                                  "name43 TEXT, name44 TEXT, name45 TEXT "
                                                                  "name53 TEXT, name54 TEXT, name55 TEXT "
                                                                  "name63 TEXT, name64 TEXT, name65 TEXT "
                                                                  "name73 TEXT, name74 TEXT, name75 TEXT "
                                                                  "name83 TEXT, name84 TEXT, name85 TEXT "
                                                                  "name93 TEXT, name94 TEXT, name95 TEXT "
                                                                  "name103 TEXT, name104 TEXT, name105 TEXT "
                                                                  "name113 TEXT, name114 TEXT, name115 TEXT "
                                                                  "name123 TEXT, name124 TEXT, name125 TEXT "
                                                                  "name133 TEXT, name134 TEXT, name135 TEXT "
                                                                  "name143 TEXT, name144 TEXT, name145 TEXT "
                                                                  "name153 TEXT, name154 TEXT, name155 TEXT "
                                                                  "name163 TEXT, name164 TEXT, name165 TEXT "
                                                                  "name173 TEXT, name174 TEXT, name175 TEXT "
                                                                  "name183 TEXT, name184 TEXT, name185 TEXT "
                                                                  "name193 TEXT, name194 TEXT, name195 TEXT "
                                                                  "name203 TEXT, name204 TEXT, name205 TEXT "
                                                                  "name16 TEXT, name17 TEXT, name18 TEXT)");

const std::string NAME =
    "Michael, David, Andrew, James, Benjamin, William, Joseph, Christopher, Matthew, Joshua, "
    "Ethan, Daniel, Anthony, Mark, Richard, Charles, Thomas, Kevin, Steven, Patrick, "
    "Lucas, Ryan, Adam, Justin, Nicholas, Brandon, Timothy, Jason, Jesus, Caleb, "
    "Logan, Noah, Samuel, Jonathan, Dylan, Gabriel, Nathan, Christian, Aaron, Tyler, "
    "Jacob, Hunter, Austin, Joshuaua, Alexander, Sean, Evan, Isaac, Liam, Andrew, "
    "Jack, Lucas, Mason, Jayden, Benjamin, Ethan, Henry, Oliver, William, James, "
    "Adam, Christopher, David, Matthew, Michael, Andrew, Joshua, Daniel, Anthony, Mark, "
    "Kevin, Steven, Ryan, Nicholas, Brandon, Timothy, Jason, Caleb, Logan, Ethan, "
    "Noah, Samuel, Dylan, Gabriel, Nathan, Christian, Aaron, Tyler, Jacob, Hunter, "
    "Austin, Alexander, Sean, Evan, Isaac, Liam, Jack, Mason, Jayden, Benjamin, "
    "Henry, Oliver, Lucas, James, Christopher, David, Matthew, Michael, Andrew, Joshua, "
    "Daniel, Anthony, Mark, Kevin, Steven, Ryan, Nicholas, Brandon, Timothy, Jason, "
    "Caleb, Logan, Ethan, Noah, Samuel, Dylan, Gabriel, Nathan, Christian, Aaron, "
    "Tyler, Jacob, Hunter, Austin, Alexander, Sean, Evan, Isaac, Liam, Jack, "
    "Mason, Jayden, Benjamin, Henry, Oliver, Lucas, James, Christopher, David, Matthew, "
    "Michael, Joshua, Andrew, Daniel, Anthony, Mark, Kevin, Steven, Ryan, Nicholas, "
    "Brandon, Timothy, Jason, Caleb, Logan, Ethan, Noah, Samuel, Dylan, Gabriel, "
    "Nathan, Christian, Aaron, Tyler, Jacob, Hunter, Austin, Alexander, Sean, Evan, "
    "Isaac, Liam, Jack, Mason, Jayden, Benjamin, Henry, Oliver, Lucas, James, "
    "Christopher, David, Matthew, Michael, Joshua, Andrew, Daniel, Anthony, Mark, Kevin, "
    "Steven, Ryan, Nicholas, Brandon, Timothy, Jason, Caleb, Logan, Ethan, Noah, "
    "Samuel, Dylan, Gabriel, Nathan, Christian, Aaron, Tyler, Jacob, Hunter, Austin, "
    "Alexander, Sean, Evan, Isaac, Liam, Jack, Mason, Jayden, Benjamin, Henry, "
    "Oliver, Lucas, James, Christopher, David, Matthew, Michael, Joshua, Andrew, Daniel, "
    "Anthony, Mark, Kevin, Steven, Ryan, Nicholas, Brandon, Timothy, Jason, Caleb, "
    "Logan, Ethan, Noah, Samuel, Dylan, Gabriel, Nathan, Christian, Aaron, Tyler, "
    "Jacob, Hunter, Austin, Alexander, Sean, Evan, Isaac, Liam, Jack, Mason, "
    "Jayden, Benjamin, Henry, Oliver, Lucas, James, Christopher, David, Matthew, Michael, "
    "Joshua, Andrew, Daniel, Anthony, Mark, Kevin, Steven, Ryan, Nicholas, Brandon, "
    "Timothy, Jason, Caleb, Logan, Ethan, Noah, Samuel, Dylan, Gabriel, Nathan, "
    "Christian, Aaron, Tyler, Jacob, Hunter, Austin, Alexander, Sean, Evan, Isaac, "
    "Liam, Jack, Mason, Jayden, Benjamin, Henry, Oliver, Lucas, James, Christopher, "
    "David, Matthew, Michael, Joshua, Andrew, Daniel, Anthony, Mark, Kevin, Steven, "
    "Ryan, Nicholas, Brandon, Timothy, Jason, Caleb, Logan, Ethan, Noah, Samuel, "
    "Dylan, Gabriel, Nathan, Christian, Aaron, Tyler, Jacob, Hunter, Austin, Alexander, "
    "Sean, Evan, Isaac, Liam, Jack, Mason, Jayden, Benjamin, Henry, Oliver"
int InsertTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int InsertTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbInsertTest::SetUpTestCase(void)
{
}

void RdbInsertTest::TearDownTestCase(void)
{
}

void RdbInsertTest::SetUp(void)
{
}

void RdbInsertTest::TearDown(void)
{
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", std::string("zhangsan"));
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", std::string("zhangsan"));
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", std::string("zhangsan"));
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", std::string("zhangsan"));
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", std::string("zhangsan"));
    values.PutString("name104", NAME);
    values.PutString("name105", NAME);
    values.PutString("name113", NAME);
    values.PutString("name114", std::string("zhangsan"));
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

void RdbInsertTest::CheckResultSet(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> result =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    EXPECT_NE(result, nullptr);

    int columnIndex;
    int intVal;
    std::string strVal;
    ColumnType columnType;
    int position;
    int ret = result->GetRowIndex(position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, -1);

    ret = result->GetColumnType(0, columnType);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = result->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);

    ret = result->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnIndex, 0);
    ret = result->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = result->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = result->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_STRING);
    ret = result->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    RdbStoreInsertTest::CheckAge(result);
    RdbStoreInsertTest::CheckSalary(result);
    RdbStoreInsertTest::CheckBlob(result);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = result->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = result->Close();
    EXPECT_EQ(ret, E_OK);
}

void RdbInsertTest::CheckAge(std::shared_ptr<ResultSet> &result)
{
    int columnIndex;
    int intVal;
    ColumnType columnType;
    int ret = result->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = result->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    // 18 is 18
    EXPECT_EQ(18, intVal);
}

void RdbInsertTest::CheckSalary(std::shared_ptr<ResultSet> &result)
{
    int columnIndex;
    double dVal;
    ColumnType columnType;
    int ret = result->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_FLOAT);
    ret = result->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    // 100.5 is 100.5
    EXPECT_EQ(100.5, dVal);
}

void RdbInsertTest::CheckBlob(std::shared_ptr<ResultSet> &result)
{
    int columnIndex;
    std::vector<uint8_t> blob;
    ColumnType columnType;
    int ret = result->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_BLOB);
    ret = result->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    // 3 is 3
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    // 1 is 1
    EXPECT_EQ(1, blob[0]);
    // 2 is 2
    EXPECT_EQ(2, blob[1]);
    EXPECT_EQ(1, blob[1]);
}

/**
 * @tc.name: Rdb_Insert_002
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdb_Inert_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("id", 1);
    valuesBucket.PutString("name", std::string("zhangsan"));
    valuesBucket.PutInt("age", 18);
    valuesBucket.PutDouble("salary", 100.5);
    valuesBucket.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    valuesBucket.PutString("name1", std::string("zhangsan"));
    valuesBucket.PutString("name2", NAME);
    valuesBucket.PutString("name13", NAME);
    valuesBucket.PutString("name14", NAME);
    valuesBucket.PutString("name15", NAME);
    valuesBucket.PutString("name23", NAME);
    valuesBucket.PutString("name24", NAME);
    valuesBucket.PutString("name25", NAME);
    valuesBucket.PutString("name33", NAME);
    valuesBucket.PutString("name34", NAME);
    valuesBucket.PutString("name35", NAME);
    valuesBucket.PutString("name43", std::string("zhangsan"));
    valuesBucket.PutString("name44", NAME);
    valuesBucket.PutString("name45", NAME);
    valuesBucket.PutString("name53", NAME);
    valuesBucket.PutString("name54", NAME);
    valuesBucket.PutString("name55", std::string("zhangsan"));
    valuesBucket.PutString("name63", NAME);
    int ret = store->Insert(id, "", valuesBucket); // empty table name
    EXPECT_EQ(ret, E_EMPTY_TABLE_NAME);

    ret = store->Insert(id, "wrongTable", valuesBucket); // no such table
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Insert_003
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStre_Insert_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket emptyBucket;
    int ret = store->Insert(id, "test", emptyBucket);
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);

    ValuesBucket valuesBucket;
    ValuesBucket values;
    valuesBucket.PutInt("id", 1);
    valuesBucket.PutString("name", std::string("zhangsan"));
    valuesBucket.PutInt("age", 18);
    valuesBucket.PutDouble("wrongColumn", 100.5); // no such column
    valuesBucket.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    valuesBucket.PutString("name1", NAME);
    valuesBucket.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", std::string("zhangsan"));
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", std::string("zhangsan"));
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", std::string("zhangsan"));
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Replace_001
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStore_Rplace_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    int ret = store->Replace(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> result = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(result, nullptr);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    int intVal;
    std::string strVal;

    ret = result->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = result->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    ret = result->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(18, intVal);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = result->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Replace_002
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStore_Rplace_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket valuesbucket;
    ValuesBucket values;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    valuesbucket.Clear();
    valuesbucket.PutInt("id", 1);
    valuesbucket.PutString("name", std::string("zhangsan"));
    valuesbucket.PutInt("age", 18);
    valuesbucket.PutDouble("salary", 200.5);
    valuesbucket.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    ret = store->Replace(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> result = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    int intVal;
    std::string strVal;

    ret = result->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = result->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    ret = result->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(18, intVal);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = result->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Replace_003
 * @tc.desc: test RdbStore Replace
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbSore_Replace_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;
    ValuesBucket value;
    value.PutInt("id", 1);
    value.PutString("name", std::string("zhangsan"));
    value.PutInt("age", 18);
    value.PutDouble("salary", 100.5);
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", std::string("zhangsan"));
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", std::string("zhangsan"));
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    int ret = store->Replace(id, "", value); // empty table name
    EXPECT_EQ(ret, E_EMPTY_TABLE_NAME);

    ret = store->Replace(id, "wrongTable", value); // no such table
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Replace_004
 * @tc.desc: test RdbStore Replace
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdStore_Replace_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket emptyBucket;
    int ret = store->Replace(id, "test", emptyBucket);
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);

    ValuesBucket value;
    ValuesBucket values;
    value.PutInt("id", 1);
    value.PutString("name", std::string("zhangsan"));
    value.PutInt("age", 18);
    value.PutDouble("wrongColumn", 100.5); // no such column
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", std::string("zhangsan"));
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", std::string("zhangsan"));
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", std::string("zhangsan"));
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    ret = store->Replace(id, "test", values);
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Replace_005
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStore_Replae_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;

    int ret = store->Replace(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> result = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(result, nullptr);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    double dVal;
    std::vector<uint8_t> blob;

    ret = result->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(100.5, dVal);

    ret = result->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(1, blob[0]);
    EXPECT_EQ(2, blob[1]);
    EXPECT_EQ(3, blob[2]);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = result->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Replace_006
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStre_Replace_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket value;
    ValuesBucket values;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    value.Clear();
    value.PutInt("id", 1);
    value.PutString("name", std::string("zhangsan"));
    value.PutInt("age", 18);
    value.PutDouble("salary", 200.5);
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    value.PutString("name2", NAME);
    values.PutString("name13", NAME);
    value.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    value.PutString("name24", NAME);
    values.PutString("name25", NAME);
    ret = store->Replace(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> result = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(result, nullptr);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    double dVal;
    std::vector<uint8_t> blob;

    ret = result->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(200.5, dVal);

    ret = result->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(1, blob[0]);
    EXPECT_EQ(2, blob[1]);
    EXPECT_EQ(3, blob[2]);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = result->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_001_002
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStore_InserithConflictResution_001_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket value;
    ValuesBucket values;

    value.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    value.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    value.PutString("name2", NAME);
    values.PutString("name13", NAME);

    // default is ConflictResolution::ON_CONFLICT_NONE
    int ret = store->InsertWithConflictResolution(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    value.PutString("name", std::string("zhangsan"));
    value.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    value.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    value.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    value.PutString("name25", NAME);
    values.PutString("name33", NAME);
    value.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    value.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", std::string("zhangsan"));
    values.PutString("name54", NAME);
    value.PutString("name55", NAME);
    valvalueues.PutString("name63", NAME);
    ret = store->InsertWithConflictResolution(id, "test", value);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_003_004
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStore_InsertWitonflictResolution_003_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket value;
    ValuesBucket values;

    value.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    value.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    value.PutString("name2", NAME);
    values.PutString("name13", NAME);
    value.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    value.PutString("name25", NAME);
    int ret = store->InsertWithConflictResolution(id, "test", value, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    value.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    value.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    value.PutString("name23", NAME);
    values.PutString("name24", std::string("zhangsan"));
    values.PutString("name25", NAME);
    value.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    value.PutString("name43", NAME);
    values.PutString("name44", NAME);
    value.PutString("name45", NAME);
    values.PutString("name53", NAME);
    ret = store->InsertWithConflictResolution(id, "test", value, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_005
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStore_InsertWithConfictReolution_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket value;
    ValuesBucket values;

    values.PutInt("id", 1);
    value.PutString("name", std::string("zhangsan"));
    value.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    value.PutString("name1", NAME);
    values.PutString("name2", NAME);
    value.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    value.PutString("name24", NAME);
    values.PutString("name25", std::string("zhangsan"));
    int ret = store->InsertWithConflictResolution(id, "test", value, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    valvalueues.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    value.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    value.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    value.PutString("name33", NAME);
    values.PutString("name34", std::string("zhangsan"));
    values.PutString("name35", NAME);
    value.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    ret = store->InsertWithConflictResolution(id, "test", value, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, -1);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_006
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStore_InsertWithConflctResolution_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket value;
    ValuesBucket values;

    int ret = store->InsertWithConflictResolution(
        id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]), ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    value.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    value.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    value.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    ret = store->InsertWithConflictResolution(id, "test", value, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

    std::shared_ptr<ResultSet> result = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(result, nullptr);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    int intVal;
    std::string strVal;

    ret = result->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = result->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    ret = result->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(18, intVal);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = result->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_007
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbStore_InsertWithConflictResolutin_007, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket value;
    ValuesBucket values;

    int ret = store->InsertWithConflictResolution(
        id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]), ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    value.Clear();
    value.PutInt("id", 1);
    value.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    value.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    values.PutString("name1", NAME);
    value.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    value.PutString("name15", NAME);
    values.PutString("name23", NAME);
    ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

    std::shared_ptr<ResultSet> result = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(result, nullptr);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    double dVal;
    std::vector<uint8_t> blob;

    ret = result->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(200.5, dVal);

    ret = result->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = result->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(4, blob[0]);
    EXPECT_EQ(5, blob[1]);
    EXPECT_EQ(6, blob[2]);

    ret = result->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = result->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_008
 * @tc.desc: Abnormal testCase of InsertWithConflictResolution, if conflictResolution is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, RdbSore_InsertWithConflictResolution_008, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id = 0;
    ValuesBucket values;
    ValuesBucket value;

    value.PutInt("id", 1);
    values.PutInt("age", 18);
    values.PutString("name1", NAME);
    value.PutString("name2", NAME);
    values.PutString("name13", NAME);
    value.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    value.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    value.PutString("name35", std::string("zhangsan"));
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    int ret = store->InsertWithConflictResolution(id, "test", values, static_cast<ConflictResolution>(6));
    EXPECT_EQ(E_INVALID_CONFLICT_FLAG, ret);
    EXPECT_EQ(0, id);

    values.Clear();
    values.PutInt("id", 1);
    value.PutInt("age", 18);
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    value.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    value.PutString("name43", NAME);
    values.PutString("name44", std::string("zhangsan"));
    values.PutString("name45", NAME);
    value.PutString("name53", NAME);
    values.PutString("name54", NAME);
    ret = store->InsertWithConflictResolution(id, "test", value, static_cast<ConflictResolution>(-1));
    EXPECT_EQ(E_INVALID_CONFLICT_FLAG, ret);
    EXPECT_EQ(0, id);
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Inert_0011, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", std::string("zhangsan"));
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", std::string("zhangsan"));
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", std::string("zhangsan"));
    values.PutString("name95", NAME);
    values.PutString("name103", NAME);
    values.PutString("name104", NAME);
    values.PutString("name105", NAME);
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Inset_0021, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", std::string("zhangsan"));
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", std::string("zhangsan"));
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", std::string("zhangsan"));
    values.PutString("name95", NAME);
    values.PutString("name103", NAME);
    values.PutString("name104", NAME);
    values.PutString("name105", NAME);
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_0031, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", std::string("zhangsan"));
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", std::string("zhangsan"));
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", NAME);
    values.PutString("name104", std::string("zhangsan"));
    values.PutString("name105", NAME);
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_0041, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", std::string("zhangsan"));
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", std::string("zhangsan"));
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", NAME);
    values.PutString("name65", std::string("zhangsan"));
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", NAME);
    values.PutString("name104", std::string("zhangsan"));
    values.PutString("name105", NAME);
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_0051, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", std::string("zhangsan"));
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", std::string("zhangsan"));
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", std::string("zhangsan"));
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", std::string("zhangsan"));
    values.PutString("name104", NAME);
    values.PutString("name105", NAME);
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_0061, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", std::string("zhangsan"));
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", std::string("zhangsan"));
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", std::string("zhangsan"));
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", NAME);
    values.PutString("name104", NAME);
    values.PutString("name105", std::string("zhangsan"));
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_0071, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", std::string("zhangsan"));
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", std::string("zhangsan"));
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", std::string("zhangsan"));
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", NAME);
    values.PutString("name104", NAME);
    values.PutString("name105", NAME);
    values.PutString("name113", std::string("zhangsan"));
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_0081, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", std::string("zhangsan"));
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", std::string("zhangsan"));
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", NAME);
    values.PutString("name65", std::string("zhangsan"));
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", std::string("zhangsan"));
    values.PutString("name104", NAME);
    values.PutString("name105", NAME);
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_0091, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", std::string("zhangsan"));
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", std::string("zhangsan"));
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", std::string("zhangsan"));
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", NAME);
    values.PutString("name104", NAME);
    values.PutString("name105", std::string("zhangsan"));
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_1001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", NAME);
    values.PutString("name15", NAME);
    values.PutString("name23", std::string("zhangsan"));
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", std::string("zhangsan"));
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", std::string("zhangsan"));
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", NAME);
    values.PutString("name104", NAME);
    values.PutString("name105", std::string("zhangsan"));
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_0111, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", std::string("zhangsan"));
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", NAME);
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", std::string("zhangsan"));
    values.PutString("name53", NAME);
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", std::string("zhangsan"));
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", NAME);
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", std::string("zhangsan"));
    values.PutString("name103", NAME);
    values.PutString("name104", NAME);
    values.PutString("name105", NAME);
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}

/**
 * @tc.name: Rdb_Insert_001
 * @tc.desc: test Rdb insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbInsertTest, Rdbe_Insert_0015, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreInsertTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutString("name1", NAME);
    values.PutString("name2", NAME);
    values.PutString("name13", NAME);
    values.PutString("name14", std::string("zhangsan"));
    values.PutString("name15", NAME);
    values.PutString("name23", NAME);
    values.PutString("name24", NAME);
    values.PutString("name25", NAME);
    values.PutString("name33", std::string("zhangsan"));
    values.PutString("name34", NAME);
    values.PutString("name35", NAME);
    values.PutString("name43", NAME);
    values.PutString("name44", NAME);
    values.PutString("name45", NAME);
    values.PutString("name53", std::string("zhangsan"));
    values.PutString("name54", NAME);
    values.PutString("name55", NAME);
    values.PutString("name63", NAME);
    values.PutString("name64", NAME);
    values.PutString("name65", NAME);
    values.PutString("name73", NAME);
    values.PutString("name74", NAME);
    values.PutString("name75", NAME);
    values.PutString("name83", std::string("zhangsan"));
    values.PutString("name84", NAME);
    values.PutString("name85", NAME);
    values.PutString("name93", NAME);
    values.PutString("name94", NAME);
    values.PutString("name95", NAME);
    values.PutString("name103", std::string("zhangsan"));
    values.PutString("name104", NAME);
    values.PutString("name105", NAME);
    values.PutString("name113", NAME);
    values.PutString("name114", NAME);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
}