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
#define LOG_TAG "RdbCallbackIcuTest"
#include <gtest/gtest.h>

#include <string>

#include "common.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;

class RdbCallbackIcuTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string databaseName;
};

const std::string RdbCallbackIcuTest::databaseName = RDB_TEST_PATH + "open_helper.db";

void RdbCallbackIcuTest::SetUpTestCase(void)
{
}

void RdbCallbackIcuTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbCallbackIcuTest::databaseName);
}

void RdbCallbackIcuTest::SetUp(void)
{
}

void RdbCallbackIcuTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

class OpenCallbackIcu : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    int OnDowngrade(RdbStore &store, int oldVersion, int newVersion) override;
    int OnOpen(RdbStore &store) override;

    static std::string CreateTableSQL(const std::string &tableName);
    static std::string DropTableSQL(const std::string &tableName);
};

std::string OpenCallbackIcu::CreateTableSQL(const std::string &tableName)
{
    return "CREATE VIRTUAL TABLE IF NOT EXISTS " + tableName + " USING fts4(name, content, tokenize=icu zh_CN);";
}

std::string OpenCallbackIcu::DropTableSQL(const std::string &tableName)
{
    return "DROP TABLE IF EXISTS " + tableName + ";";
}

int OpenCallbackIcu::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CreateTableSQL("test1"));
}

int OpenCallbackIcu::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int OpenCallbackIcu::OnDowngrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int OpenCallbackIcu::OnOpen(RdbStore &store)
{
    return E_OK;
}

/**
 * @tc.name: RdbCallbackIcu_01
 * @tc.desc: test RdbCallbackIcu
 * @tc.type: FUNC
 */
HWTEST_F(RdbCallbackIcuTest, RdbCallbackIcu_01, TestSize.Level1)
{
    RdbStoreConfig config(RdbCallbackIcuTest::databaseName);
    config.SetTokenizer(ICU_TOKENIZER);
    OpenCallbackIcu helper;

    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    const char *sqlCreateTable = "CREATE VIRTUAL TABLE example USING fts4(name, content, tokenize=icu zh_CN);";
    ret = store->ExecuteSql(sqlCreateTable);
    EXPECT_EQ(ret, E_OK);

    const char *sqlInsert1 =
        "INSERT INTO example(name, content) VALUES('文档1', '这是一个测试文档，用于测试中文文本的分词和索引。');";
    ret = store->ExecuteSql(sqlInsert1);
    EXPECT_EQ(ret, E_OK);

    const char *sqlInsert2 =
        "INSERT INTO example(name, content) VALUES('文档2', '我们将使用这个示例来演示如何在SQLite中进行全文搜索。');";
    ret = store->ExecuteSql(sqlInsert2);
    EXPECT_EQ(ret, E_OK);

    const char *sqlInsert3 =
        "INSERT INTO example(name, content) VALUES('文档3', 'ICU分词器能够很好地处理中文文本的分词和分析。');";
    ret = store->ExecuteSql(sqlInsert3);
    EXPECT_EQ(ret, E_OK);

    const char *sqlQuery = "SELECT * FROM example WHERE example MATCH '测试';";
    ret = store->ExecuteSql(sqlQuery);
    EXPECT_EQ(ret, E_OK);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql(sqlQuery);
    ASSERT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    std::string strVal;

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("文档1", strVal);

    ret = resultSet->GetColumnIndex("content", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("这是一个测试文档，用于测试中文文本的分词和索引。", strVal);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}