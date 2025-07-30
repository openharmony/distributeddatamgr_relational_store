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

#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "common.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;

namespace Test {

class RdbCorruptTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp();
    void TearDown();
    void GenerateData(int count);
    static void DestroyDbFile(const std::string &filePath, size_t offset, size_t len, unsigned char ch);
    static constexpr const char *DATABASE_NAME = "corrupt_test.db";
    static constexpr int DB_FILE_HEADER_LENGTH = 100;
    std::shared_ptr<RdbStore> store_;
};

class CorruptTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static constexpr const char *CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                                     "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                     "name TEXT NOT NULL, age INTEGER, salary "
                                                     "REAL, blobType BLOB)";
};

int CorruptTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int CorruptTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbCorruptTest::SetUp(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + DATABASE_NAME);
    RdbStoreConfig sqliteSharedRstConfig(RDB_TEST_PATH + DATABASE_NAME);
    CorruptTestOpenCallback openCallback;
    int errCode = E_OK;
    store_ = RdbHelper::GetRdbStore(sqliteSharedRstConfig, 1, openCallback, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
    // Preset 1000 entries into database file
    GenerateData(1000);
    store_ = nullptr;
    RdbHelper::ClearCache();
}

void RdbCorruptTest::TearDown(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + DATABASE_NAME);
}

void RdbCorruptTest::GenerateData(int count)
{
    for (int64_t i = 0; i < count; i++) {
        // Preset data into database
        RowData rowData = {1, "test", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 }};
        rowData.id += i;
        rowData.name += std::to_string(i + 1);
        rowData.salary += i;
        int64_t rowId = 0;
        auto ret = store_->Insert(rowId, "test", UTUtils::SetRowData(rowData));
        EXPECT_EQ(E_OK, ret);
        EXPECT_EQ(i + 1, rowId);
    }
}

void RdbCorruptTest::DestroyDbFile(const std::string &filePath, size_t offset, size_t len, unsigned char ch)
{
    std::fstream f;
    f.open(filePath.c_str());

    f.seekp(offset, std::ios::beg);
    std::vector<char> buf(len, ch);
    f.write(buf.data(), len);
    f.close();
}

/**
 * @tc.name: RdbCorruptTest001
 * @tc.desc: test Rdb corruption
 * @tc.type: FUNC
 */
HWTEST_F(RdbCorruptTest, RdbCorruptTest001, TestSize.Level2)
{
    // Destroy database file, set 1st byte of 3rd page into undefined flag, which indicate the btree page type
    RdbCorruptTest::DestroyDbFile(RDB_TEST_PATH + DATABASE_NAME, 8192, 1, 0xFF);
    
    // Get RDB store failed as database corrupted
    CorruptTestOpenCallback sqliteCallback;
    RdbStoreConfig sqliteConfig(RDB_TEST_PATH + DATABASE_NAME);
    int errCode = E_OK;
    store_ = RdbHelper::GetRdbStore(sqliteConfig, 1, sqliteCallback, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);

    std::shared_ptr<ResultSet> resultSet = store_->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_SQLITE_CORRUPT);
}

/**
 * @tc.name: RdbCorruptTest002
 * @tc.desc: test Rdb verify db file header's reserved bytes
 * @tc.type: FUNC
 */
HWTEST_F(RdbCorruptTest, RdbCorruptTest002, TestSize.Level2)
{
    std::fstream f;
    f.open(RDB_TEST_PATH + DATABASE_NAME);
    f.seekp(0, std::ios::beg);
    char buf[DB_FILE_HEADER_LENGTH] = {0};
    f.read(buf, sizeof(buf));
    f.close();
    // 20 is the offset of reserved bytes field, 10 means reserve bytes size
    EXPECT_EQ((unsigned int)buf[20], 10);
}
} // namespace Test