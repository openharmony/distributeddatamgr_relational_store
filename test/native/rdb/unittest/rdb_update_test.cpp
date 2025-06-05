/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "sqlite_sql_builder.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace OHOS::RdbStoreUpdateTest {
struct RdbTestParam {
    std::shared_ptr<RdbStore> store;
    operator std::shared_ptr<RdbStore>()
    {
        return store;
    }
};
static RdbTestParam g_store;
static RdbTestParam g_memDb;

class RdbStoreUpdateTest : public testing::TestWithParam<RdbTestParam *> {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static void ExpectValue(const std::shared_ptr<OHOS::NativeRdb::ResultSet> &resultSet, const RowData &expect);
    void SetUp();
    void TearDown();
    std::shared_ptr<RdbStore> store_;

    static const std::string DATABASE_NAME;
};

const std::string RdbStoreUpdateTest::DATABASE_NAME = RDB_TEST_PATH + "update_test.db";

class UpdateTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};
constexpr const char *CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test ("
                                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                    "name TEXT UNIQUE, "
                                    "age INTEGER, "
                                    "salary REAL, "
                                    "blobType BLOB, "
                                    "assetType ASSET, "
                                    "assetsType ASSETS)";
int UpdateTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int UpdateTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreUpdateTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(RdbStoreUpdateTest::DATABASE_NAME);
    UpdateTestOpenCallback helper;
    g_store.store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(g_store.store, nullptr);

    config.SetStorageMode(StorageMode::MODE_MEMORY);
    g_memDb.store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(g_memDb.store, nullptr);
}

void RdbStoreUpdateTest::TearDownTestCase(void)
{
    RdbStoreConfig config(RdbStoreUpdateTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(config);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbHelper::DeleteRdbStore(config);
}

void RdbStoreUpdateTest::SetUp(void)
{
    store_ = *GetParam();
    ASSERT_NE(store_, nullptr);
    store_->ExecuteSql("DELETE FROM test");
}

void RdbStoreUpdateTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

/**
 * @tc.name: RdbStore_Update_001
 * @tc.desc: test RdbStore update, select id and update one row
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_001, TestSize.Level1)
{
    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store_->Update(changedRows, "test", values, "id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 2, "lisi", 20, 200.5, std::vector<uint8_t>{ 4, 5, 6 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Update_002
 * @tc.desc: test RdbStore update, no select and update all rows
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_002, TestSize.Level1)
{
    int64_t id;
    ValuesBucket values;
    int changedRows;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store_->Update(changedRows, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, changedRows);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 300.5, std::vector<uint8_t>{ 4, 5, 6 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 2, "lisi", 19, 300.5, std::vector<uint8_t>{ 4, 5, 6 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Update_003
 * @tc.desc: test RdbStore update
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_003, TestSize.Level1)
{
    int changedRows;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store_->Update(changedRows, "", values, "", std::vector<std::string>()); // empty table name
    EXPECT_EQ(ret, E_EMPTY_TABLE_NAME);

    ret = store_->Update(changedRows, "wrongTable", values, "", std::vector<std::string>()); // no such table
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Update_004
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_004, TestSize.Level1)
{
    int changedRows;
    ValuesBucket emptyBucket;
    int ret = store_->Update(changedRows, "test", emptyBucket);
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);

    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("wrongColumn", 100.5); // no such column
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->Update(changedRows, "test", values, "", std::vector<std::string>());
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Update_005
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_005, TestSize.Level1)
{
    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Update(changedRows, "test", values, "id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name: RdbStore_Update_006
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_006, TestSize.Level1)
{
    ValuesBucket values;
    int changedRows;
    int64_t id;

    values.Clear();
    values.PutString("id", "2");
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Update(changedRows, "test", values, "id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 2, "lisi", 20, 200.5, std::vector<uint8_t>{ 4, 5, 6 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Update_007
 * @tc.desc: test RdbStore update asset
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_007, TestSize.Level1)
{
    ValuesBucket values;
    AssetValue value{ .version = 1, .name = "123", .uri = "your test path", .createTime = "13", .modifyTime = "13" };
    int changedRows;
    int64_t id;
    values.PutNull("assetType");
    int ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);
    values.Clear();
    values.Put("assetType", value);
    ret = store_->Update(changedRows, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);
    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);

    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ .id = 3,
                                                   .asset{ .version = 1,
                                                       .status = AssetValue::STATUS_INSERT,
                                                       .name = "123",
                                                       .uri = "your test path",
                                                       .createTime = "13",
                                                       .modifyTime = "13" } });
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Update_008
 * @tc.desc: test RdbStore update asset
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_008, TestSize.Level1)
{
    ValuesBucket values;
    AssetValue valueDef{
        .version = 0,
        .name = "123",
        .uri = "my test path",
        .createTime = "12",
        .modifyTime = "12",
    };
    AssetValue value{ .version = 2, .name = "456", .uri = "your test path", .createTime = "15", .modifyTime = "15" };
    int changedRows;
    int64_t id;
    values.Put("assetType", valueDef);
    int ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(4, id);
    values.Clear();
    values.Put("assetType", value);
    ret = store_->Update(changedRows, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);
    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet,
        RowData{ .id = 4,
            .asset{ .version = 0, .name = "123", .uri = "my test path", .createTime = "12", .modifyTime = "12" } });
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Update_009
 * @tc.desc: test RdbStore update asset
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_009, TestSize.Level1)
{
    ValuesBucket values;
    AssetValue valueDef{ .version = 0,
        .status = AssetValue::STATUS_NORMAL,
        .name = "123",
        .uri = "my test path",
        .createTime = "12",
        .modifyTime = "12",
        .size = "543",
        .hash = "321" };
    AssetValue value{ .name = "123" };
    value.status = AssetValue::STATUS_DELETE;
    int changedRows;
    int64_t id;
    values.Put("assetType", valueDef);
    int ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(5, id);
    values.Clear();
    values.Put("assetType", value);
    ret = store_->Update(changedRows, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);
    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ .id = 5,
                                                   .asset{ .version = 0,
                                                       .status = AssetValue::Status::STATUS_DELETE,
                                                       .name = "123",
                                                       .uri = "my test path",
                                                       .createTime = "12",
                                                       .modifyTime = "",
                                                       .size = "",
                                                       .hash = "" } });
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Update_010
 * @tc.desc: test RdbStore update assets
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_Update_010, TestSize.Level1)
{
    ValuesBucket values;
    std::vector<AssetValue> assetsDef{
        { .version = 0, .name = "123", .uri = "my test path", .createTime = "12", .modifyTime = "12" }
    };
    AssetValue value1{ .version = 1, .name = "123", .uri = "your test path", .createTime = "13", .modifyTime = "13" };
    AssetValue value2{ .version = 2, .name = "123", .uri = "your test path", .createTime = "14", .modifyTime = "14" };
    AssetValue value3{ .version = 3, .name = "456", .uri = "your test path", .createTime = "15", .modifyTime = "15" };
    auto assets = ValueObject::Assets({ value1, value2, value3 });
    int changedRows;
    int64_t id;
    values.Put("assetsType", assetsDef);
    int ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(6, id);
    values.Clear();
    values.Put("assetsType", assets);

    ret = store_->Update(changedRows, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_001
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_001, TestSize.Level1)
{
    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to wangjing age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store_->UpdateWithConflictResolution(changedRows, "test", values, "age = 19");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 3, "wangjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_002
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_002, TestSize.Level1)
{
    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to zhangsan age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store_->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_003
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_003, TestSize.Level1)
{
    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to wangjing age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store_->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 3, "wangjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_004
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_004, TestSize.Level1)
{
    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to zhangsan age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store_->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_005
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_005, TestSize.Level1)
{
    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to wangjing age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store_->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 3, "wangjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_006
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_006, TestSize.Level1)
{
    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to zhangsan age=20
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    ret = store_->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(changedRows, 1);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{ 2, "zhangsan", 20, 300.5, std::vector<uint8_t>{ 4, 5, 6 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_007
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_007, TestSize.Level1)
{
    int changedRows = 0;
    int64_t id = -1;
    ValuesBucket values;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.PutInt("id", 2);
    values.PutInt("age", 19);
    ret = store_->UpdateWithConflictResolution(
        changedRows, "test", values, "age = ?", std::vector<std::string>{ "18" }, static_cast<ConflictResolution>(6));
    EXPECT_EQ(E_INVALID_CONFLICT_FLAG, ret);
    EXPECT_EQ(0, changedRows);

    values.Clear();
    values.PutInt("id", 2);
    values.PutInt("age", 19);
    ret = store_->UpdateWithConflictResolution(
        changedRows, "test", values, "age = ?", std::vector<std::string>{ "18" }, static_cast<ConflictResolution>(-1));
    EXPECT_EQ(E_INVALID_CONFLICT_FLAG, ret);
    EXPECT_EQ(0, changedRows);
}

void RdbStoreUpdateTest::ExpectValue(
    const std::shared_ptr<OHOS::NativeRdb::ResultSet> &resultSet, const RowData &expect)
{
    EXPECT_NE(nullptr, resultSet);
    int columnIndex;
    int intVal;
    int ret;

    if (expect.id != -1) {
        ret = resultSet->GetColumnIndex("id", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetInt(columnIndex, intVal);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.id, intVal);
    }
    if (expect.name != "") {
        std::string strVal;
        ret = resultSet->GetColumnIndex("name", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetString(columnIndex, strVal);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.name, strVal);
    }
    if (expect.age != -1) {
        ret = resultSet->GetColumnIndex("age", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetInt(columnIndex, intVal);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.age, intVal);
    }
    if (expect.salary != -1) {
        double dVal;
        ret = resultSet->GetColumnIndex("salary", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetDouble(columnIndex, dVal);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.salary, dVal);
    }
    if (expect.blobType.size() != 0) {
        std::vector<uint8_t> blob;
        ret = resultSet->GetColumnIndex("blobType", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetBlob(columnIndex, blob);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.blobType.size(), static_cast<int>(blob.size()));
        for (int i = 0; i < expect.blobType.size(); i++) {
            EXPECT_EQ(expect.blobType[i], blob[i]);
        }
    }
}

/**
 * @tc.name: OverLimitWithUpdate_001
 * @tc.desc: over limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_P(RdbStoreUpdateTest, OverLimitWithUpdate_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();
    auto [code, maxPageCount] = store->Execute("PRAGMA max_page_count;");
    auto recover = std::shared_ptr<const char>("recover", [defPageCount = maxPageCount, store](const char *) {
        store->Execute("PRAGMA max_page_count = " + static_cast<std::string>(defPageCount) + ";");
    });
    std::tie(code, maxPageCount) = store->Execute("PRAGMA max_page_count = 256;");

    int64_t id = -1;
    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(ret, E_OK);

    ValuesBucket row;
    row.PutInt("id", id);
    row.Put("name", std::string(1024 * 1024, 'e'));
    row.PutInt("age", 20);
    row.PutDouble("salary", 200.5);
    row.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    int changedRows;
    auto result = store->Update(changedRows, "test", row);
    ASSERT_EQ(result, E_SQLITE_FULL);
}

/**
 * @tc.name: UpdateWithReturning_001
 * @tc.desc: normal test
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_P(RdbStoreUpdateTest, UpdateWithReturning_001, TestSize.Level1)
{
    int64_t id;
    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ValuesBucket values;
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    AbsRdbPredicates predicates("test");
    auto [status, result] = store_->Update(values, predicates, { "id" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_EQ(result.results.RowSize(), 1);
    auto [code, val] = result.results.GetColumnValues("id");
    ASSERT_EQ(code, E_OK);
    ASSERT_EQ(val.size(), 1);
    EXPECT_EQ(int(val[0]), 2);
}

/**
 * @tc.name: UpdateWithReturning_002
 * @tc.desc: abnormal test, update with conflict ignore and partial Success
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_P(RdbStoreUpdateTest, UpdateWithReturning_002, TestSize.Level1)
{
    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim_" + std::to_string(i));
        rows.Put(row);
    }
    auto [status, result] = store_->BatchInsert("test", rows, {}, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(status, E_OK);
    ASSERT_EQ(result.changed, 5);
    ASSERT_TRUE(result.results.Empty());

    ValuesBucket row;
    row.PutString("name", "Jim_3");
    row.PutInt("age", 20);
    row.PutDouble("salary", 200.5);
    row.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    AbsRdbPredicates predicates("test");
    predicates.In("id", { 1, 2, 3 });
    std::tie(status, result) = store_->Update(row, predicates, { "name" }, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_EQ(result.results.RowSize(), 1);
    auto [code, val] = result.results.GetColumnValues("name");
    ASSERT_EQ(code, E_OK);
    ASSERT_EQ(val.size(), 1);
    EXPECT_EQ(std::string(val[0]), "Jim_3");
}

/**
 * @tc.name: UpdateWithReturning_003
 * @tc.desc: abnormal test, update with conflict abort and failed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_P(RdbStoreUpdateTest, UpdateWithReturning_003, TestSize.Level1)
{
    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim_" + std::to_string(i));
        rows.Put(row);
    }
    auto [status, result] = store_->BatchInsert("test", rows, {}, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(status, E_OK);
    ASSERT_EQ(result.changed, 5);
    ASSERT_TRUE(result.results.Empty());

    ValuesBucket row;
    row.PutString("name", "Jim_3");
    row.PutInt("age", 20);
    row.PutDouble("salary", 200.5);
    row.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    AbsRdbPredicates predicates("test");
    predicates.In("id", { 1, 2, 3 });
    std::tie(status, result) = store_->Update(row, predicates, { "blobType" }, ConflictResolution::ON_CONFLICT_ABORT);
    EXPECT_EQ(status, E_SQLITE_CONSTRAINT);
    EXPECT_EQ(result.changed, 0);
    ASSERT_EQ(result.results.RowSize(), 0);
}

/**
 * @tc.name: UpdateWithReturning_004
 * @tc.desc: abnormal test, update over returning limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_P(RdbStoreUpdateTest, UpdateWithReturning_004, TestSize.Level1)
{
    ValuesBuckets rows;
    for (int i = 0; i < 1124; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim_" + std::to_string(i));
        rows.Put(row);
    }
    auto [status, result] = store_->BatchInsert("test", rows, {}, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(status, E_OK);
    ASSERT_EQ(result.changed, 1124);
    ASSERT_TRUE(result.results.Empty());

    ValuesBucket row;
    row.PutInt("age", 20);
    row.PutDouble("salary", 200.5);
    row.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    AbsRdbPredicates predicates("test");
    std::tie(status, result) = store_->Update(row, predicates, { "age" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1124);
    ASSERT_EQ(result.results.RowSize(), 1024);
}

/**
 * @tc.name: UpdateWithReturning_005
 * @tc.desc: abnormal test, update with returning no exist field
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_P(RdbStoreUpdateTest, UpdateWithReturning_005, TestSize.Level1)
{
    int64_t id;
    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ValuesBucket values;
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20);
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 10000);
    auto [status, result] = store_->Update(values, predicates, { "noExist" });
    EXPECT_EQ(status, E_SQLITE_ERROR);
    EXPECT_EQ(result.changed, -1);
    ASSERT_EQ(result.results.RowSize(), 0);
}

/**
 * @tc.name: UpdateWithReturning_006
 * @tc.desc: abnormal test, update 0 rows
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_P(RdbStoreUpdateTest, UpdateWithReturning_006, TestSize.Level1)
{
    int64_t id;
    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ValuesBucket values;
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20);
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 10000);
    auto [status, result] = store_->Update(values, predicates, { "id" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 0);
    ASSERT_EQ(result.results.RowSize(), 0);
}

INSTANTIATE_TEST_SUITE_P(UpdateTest, RdbStoreUpdateTest, testing::Values(&g_store, &g_memDb));
} // namespace OHOS::RdbStoreUpdateTest