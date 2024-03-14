/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <sys/types.h>

#include "common.h"
#include "file_ex.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_security_manager.h"
#include "sqlite_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
class RdbRekeyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static std::string RemoveSuffix(const std::string &name);
    static std::chrono::system_clock::time_point GetKeyFileDate(const std::string &dbName);
    static bool ChangeKeyFileDate(const std::string &dbName, int rep);
    static RdbStoreConfig GetRdbConfig(const std::string &name);
    static void InsertData(std::shared_ptr<RdbStore> &store);
    static void CheckQueryData(std::shared_ptr<RdbStore> &store);

    static const std::string encryptedDatabaseName;
    static const std::string encryptedDatabasePath;
    static const std::string encryptedDatabaseKeyDir;
    static const std::string encryptedDatabaseMockName;
    static const std::string encryptedDatabaseMockPath;
    static constexpr int HOURS_EXPIRED = (24 * 365) + 1;
    static constexpr int HOURS_NOT_EXPIRED = (24 * 30);
};

const std::string RdbRekeyTest::encryptedDatabaseName = "encrypted.db";
const std::string RdbRekeyTest::encryptedDatabasePath = RDB_TEST_PATH + encryptedDatabaseName;
const std::string RdbRekeyTest::encryptedDatabaseKeyDir = RDB_TEST_PATH + "key/";
const std::string RdbRekeyTest::encryptedDatabaseMockName = "encrypted_mock.db";
const std::string RdbRekeyTest::encryptedDatabaseMockPath = RDB_TEST_PATH + encryptedDatabaseMockName;

class RekeyTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string createTableTest;
};

std::string const RekeyTestOpenCallback::createTableTest = "CREATE TABLE IF NOT EXISTS test "
                                                           "(id INTEGER PRIMARY KEY "
                                                           "AUTOINCREMENT, "
                                                           "name TEXT NOT NULL, age INTEGER, "
                                                           "salary "
                                                           "REAL, blobType BLOB)";

int RekeyTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(createTableTest);
}

int RekeyTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbRekeyTest::SetUpTestCase() {}

void RdbRekeyTest::TearDownTestCase() {}

void RdbRekeyTest::SetUp()
{
    RdbStoreConfig config = GetRdbConfig(encryptedDatabasePath);
    RekeyTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    InsertData(store);
    store.reset();
    RdbHelper::ClearCache();
}

void RdbRekeyTest::TearDown()
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbRekeyTest::encryptedDatabasePath);
}

std::string RdbRekeyTest::RemoveSuffix(const std::string &name)
{
    std::string suffix(".db");
    auto pos = name.rfind(suffix);
    if (pos == std::string::npos || pos < name.length() - suffix.length()) {
        return name;
    }
    return { name, 0, pos };
}

std::chrono::system_clock::time_point RdbRekeyTest::GetKeyFileDate(const std::string &dbName)
{
    std::chrono::system_clock::time_point timePoint;
    std::string name = RemoveSuffix(dbName);
    auto keyPath = RDB_TEST_PATH + "key/" + name + ".pub_key";
    if (!OHOS::FileExists(keyPath)) {
        return timePoint;
    }
    std::vector<char> content;
    auto loaded = OHOS::LoadBufferFromFile(keyPath, content);
    if (!loaded) {
        return timePoint;
    }
    auto iter = content.begin();
    iter++;
    constexpr uint32_t dateFileLength = sizeof(time_t) / sizeof(uint8_t);
    std::vector<uint8_t> date;
    date.assign(iter, iter + dateFileLength);
    timePoint = std::chrono::system_clock::from_time_t(*reinterpret_cast<time_t *>(const_cast<uint8_t *>(&date[0])));
    return timePoint;
}

bool RdbRekeyTest::ChangeKeyFileDate(const std::string &dbName, int rep)
{
    std::string name = RemoveSuffix(dbName);
    auto keyPath = RDB_TEST_PATH + "key/" + name + ".pub_key";
    if (!OHOS::FileExists(keyPath)) {
        return false;
    }
    std::vector<char> content;
    auto loaded = OHOS::LoadBufferFromFile(keyPath, content);
    if (!loaded) {
        return false;
    }
    auto time =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::system_clock::now() - std::chrono::hours(rep));
    std::vector<char> date(reinterpret_cast<uint8_t *>(&time), reinterpret_cast<uint8_t *>(&time) + sizeof(time));
    std::copy(date.begin(), date.end(), ++content.begin());

    auto saved = OHOS::SaveBufferToFile(keyPath, content);
    return saved;
}

RdbStoreConfig RdbRekeyTest::GetRdbConfig(const std::string &name)
{
    RdbStoreConfig config(name);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.test_rekey");
    return config;
}

void RdbRekeyTest::InsertData(std::shared_ptr<RdbStore> &store)
{
    int64_t id;
    ValuesBucket values;
    std::string name = "zhangsan";
    int age = 18;
    double salary = 100.5;
    std::vector<uint8_t> blob{ 1, 2, 3 };
    values.PutString("name", name);
    values.PutInt("age", age);
    values.PutDouble("salary", salary);
    values.PutBlob("blobType", blob);
    int insertRet = store->Insert(id, "test", values);
    EXPECT_EQ(insertRet, E_OK);
}

void RdbRekeyTest::CheckQueryData(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    EXPECT_NE(resultSet, nullptr);
    int result = resultSet->GoToFirstRow();
    EXPECT_EQ(result, E_OK);
    int columnIndex;
    std::string strVal;
    ColumnType columnType;
    result = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(result, E_OK);
    result = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_STRING);
    result = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    result = resultSet->Close();
    EXPECT_EQ(result, E_OK);
}

/**
* @tc.name: Rdb_Rekey_Test_001
* @tc.desc: test RdbStore rekey function
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_01, TestSize.Level1)
{
    std::string keyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    std::string newKeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key.new";

    bool isFileExists = OHOS::FileExists(keyPath);
    ASSERT_TRUE(isFileExists);

    bool isFileDateChanged = ChangeKeyFileDate(encryptedDatabaseName, RdbRekeyTest::HOURS_EXPIRED);
    ASSERT_TRUE(isFileDateChanged);

    auto changedDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_TRUE(std::chrono::system_clock::now() - changedDate > std::chrono::hours(RdbRekeyTest::HOURS_EXPIRED));

    RdbStoreConfig config = GetRdbConfig(RdbRekeyTest::encryptedDatabasePath);
    RekeyTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    isFileExists = OHOS::FileExists(keyPath);
    ASSERT_TRUE(isFileExists);
    isFileExists = OHOS::FileExists(newKeyPath);
    ASSERT_FALSE(isFileExists);

    auto newDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_TRUE(std::chrono::system_clock::now() - newDate < std::chrono::seconds(2));
    CheckQueryData(store);
}

/**
* @tc.name: Rdb_Rekey_Test_002
* @tc.desc: test RdbStore with not outdated password
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_02, TestSize.Level1)
{
    std::string keyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    bool isFileExists = OHOS::FileExists(keyPath);
    ASSERT_TRUE(isFileExists);

    bool isFileDateChanged = ChangeKeyFileDate(encryptedDatabaseName, RdbRekeyTest::HOURS_NOT_EXPIRED);
    ASSERT_TRUE(isFileDateChanged);

    auto changedDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_TRUE(std::chrono::system_clock::now() - changedDate > std::chrono::hours(RdbRekeyTest::HOURS_NOT_EXPIRED));

    RdbStoreConfig config = GetRdbConfig(RdbRekeyTest::encryptedDatabasePath);
    RekeyTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    CheckQueryData(store);
}

/**
* @tc.name: Rdb_Rekey_Test_003
* @tc.desc: try to open store and execute RekeyRecover() without key and new key files.
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_03, TestSize.Level1)
{
    std::string keyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    std::string newKeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key.new";

    bool isFileExists = OHOS::FileExists(keyPath);
    ASSERT_TRUE(isFileExists);

    SqliteUtils::DeleteFile(keyPath);
    isFileExists = OHOS::FileExists(keyPath);
    ASSERT_FALSE(isFileExists);
    isFileExists = OHOS::FileExists(newKeyPath);
    ASSERT_FALSE(isFileExists);

    RekeyTestOpenCallback helper;
    int errCode;
    RdbStoreConfig config = GetRdbConfig(encryptedDatabasePath);
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_EQ(store, nullptr);
}

/**
* @tc.name: Rdb_Rekey_Test_004
* @tc.desc: try to open store and modify create date to a future time.
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_04, TestSize.Level1)
{
    std::string keyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    std::string newKeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key.new";

    bool isFileExists = OHOS::FileExists(keyPath);
    ASSERT_TRUE(isFileExists);

    auto keyFileDate = GetKeyFileDate(encryptedDatabaseName);

    bool isFileDateChanged = ChangeKeyFileDate(encryptedDatabaseName, -RdbRekeyTest::HOURS_EXPIRED);
    ASSERT_TRUE(isFileDateChanged);

    auto changedDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_GT(changedDate, keyFileDate);

    RdbStoreConfig config = GetRdbConfig(RdbRekeyTest::encryptedDatabasePath);
    RekeyTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    isFileExists = OHOS::FileExists(keyPath);
    ASSERT_TRUE(isFileExists);
    isFileExists = OHOS::FileExists(newKeyPath);
    ASSERT_FALSE(isFileExists);

    keyFileDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_EQ(changedDate, keyFileDate);

    CheckQueryData(store);
}