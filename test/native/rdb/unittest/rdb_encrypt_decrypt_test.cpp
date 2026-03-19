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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "common.h"
#include "file_ex.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_security_manager.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbEncryptTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string ENCRYPTED_DATABASE_NAME;
    static const std::string ENCRYPTED_DATABASE_BACKUP_NAME;
    static const std::string ENCRYPTED_DATABASE_NAME2;
    static const std::string ENCRYPTED_DATABASE_BACKUP_NAME2;
    static const std::string UNENCRYPTED_DATABASE_NAME;
    static std::shared_ptr<RdbStore> testStore;
};

const std::string RdbEncryptTest::ENCRYPTED_DATABASE_NAME = RDB_TEST_PATH + "encrypted.db";
const std::string RdbEncryptTest::ENCRYPTED_DATABASE_BACKUP_NAME = RDB_TEST_PATH + "encrypted_bak.db";
const std::string RdbEncryptTest::ENCRYPTED_DATABASE_NAME2 = RDB_TEST_PATH + "encrypted2.db";
const std::string RdbEncryptTest::ENCRYPTED_DATABASE_BACKUP_NAME2 = RDB_TEST_PATH + "encrypted2_bak.db";
const std::string RdbEncryptTest::UNENCRYPTED_DATABASE_NAME = RDB_TEST_PATH + "unencrypted.db";

std::shared_ptr<RdbStore> RdbEncryptTest::testStore = nullptr;

class EncryptTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const EncryptTestOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY "
                                                               "KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, "
                                                               "salary REAL, blobType BLOB)";

int EncryptTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int EncryptTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbEncryptTest::SetUpTestCase(void)
{
}

void RdbEncryptTest::TearDownTestCase(void)
{
}

void RdbEncryptTest::SetUp(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbEncryptTest::UNENCRYPTED_DATABASE_NAME);
}

void RdbEncryptTest::TearDown(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbEncryptTest::UNENCRYPTED_DATABASE_NAME);
}

/**
  * @tc.name: RdbStore_Encrypt_012
  * @tc.desc: test key damage, open encrypted database ,then E_INVALID_SECRET_KEY
  * @tc.type: FUNC
  */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_012, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    RdbSecurityManager::KeyFiles keyFile(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    std::string file = keyFile.GetKeyFile(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
    RdbHelper::ClearCache();

    std::ofstream fsDb(file, std::ios_base::binary | std::ios_base::out);
    fsDb.seekp(64);
    fsDb.write("hello", 5);
    fsDb.close();

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_INVALID_SECRET_KEY);
    ASSERT_EQ(store, nullptr);
}

/**
  * @tc.name: RdbStore_Encrypt_013
  * @tc.desc: test key damage, allowing rebuild and open encrypted database ,then E_OK
  * @tc.type: FUNC
  */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_013, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    int64_t rowid;
    ValuesBucket values;
    values.Put("id", 1);
    values.Put("name", "zhangsan");
    values.Put("age", 18);
    values.Put("salary", 100.5);
    values.Put("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    auto ret = store->Insert(rowid, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowid, 1);
    RdbSecurityManager::KeyFiles keyFile(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    std::string file = keyFile.GetKeyFile(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
    RdbHelper::ClearCache();

    std::ofstream fsDb(file, std::ios_base::binary | std::ios_base::out);
    fsDb.seekp(64);
    fsDb.write("hello", 5);
    fsDb.close();

    config.SetAllowRebuild(true);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    int count = 1;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 0);
}

/** 
  * @tc.name: RdbStore_RdbPassword_001
  * @tc.desc: Abnomal test RdbStore RdbPassword class
  * @tc.type: FUNC
  */
HWTEST_F(RdbEncryptTest, AbnomalRdbStore_RdbPassword_001, TestSize.Level2)
{
    RdbPassword password1;
    RdbPassword password2;
    int errCode = E_OK;
    uint8_t inputData[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::ostringstream ss;
    std::copy(inputData, inputData + sizeof(inputData), std::ostream_iterator<int>(ss));

    // if size_t > 128
    errCode = password1.SetValue(inputData, 256);
    EXPECT_EQ(E_ERROR, errCode);

    // if inputData is nullptr
    errCode = password1.SetValue(nullptr, sizeof(inputData));
    EXPECT_EQ(E_ERROR, errCode);

    errCode = password1.SetValue(inputData, sizeof(inputData));
    EXPECT_EQ(E_OK, errCode);
    errCode = password2.SetValue(inputData, sizeof(inputData));
    EXPECT_EQ(E_OK, errCode);

    EXPECT_EQ(true, password1 == password2);
}

/** 
  * @tc.name: KeyCorruptTest
  * @tc.desc: test key file corrupt readonly
  * @tc.type: FUNC
  */
HWTEST_F(RdbEncryptTest, KeyCorruptTest_01, TestSize.Level1)
{
    RdbStoreConfig config1(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config1.SetEncryptStatus(true);
    config1.SetBundleName("com.example.TestEncrypt1");
    EncryptTestOpenCallback helper1;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config1, 1, helper1, errCode);
    ASSERT_NE(nullptr, store1);
    ASSERT_EQ(E_OK, errCode);
    int64_t id;
    int ret = store1->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);
    store1 = nullptr;

    RdbSecurityManager::KeyFiles keyFile(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    std::string file = keyFile.GetKeyFile(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
    ASSERT_TRUE(OHOS::FileExists(file));
    std::vector<char> keyfileData;
    ASSERT_TRUE(OHOS::LoadBufferFromFile(file, keyfileData));

    std::vector<char> keyCorrupted = keyfileData;
    // fill bytes of keyfile index 10 to 19 with 0
    for (size_t i = 10; i < 20 && i < keyCorrupted.size(); ++i) {
        keyCorrupted[i] = 0;
    }
    ASSERT_TRUE(OHOS::SaveBufferToFile(file, keyCorrupted));

    RdbStoreConfig config2(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config2.SetEncryptStatus(true);
    config2.SetBundleName("com.example.TestEncrypt1");
    config2.SetReadOnly(true);
    EncryptTestOpenCallback helper2;
    std::shared_ptr<RdbStore> store2 = RdbHelper::GetRdbStore(config2, 1, helper2, errCode);
    ASSERT_NE(nullptr, store2);
    ASSERT_EQ(E_OK, errCode);

    std::shared_ptr<ResultSet> resultSet = store2->QuerySql("SELECT * FROM test");
    ASSERT_NE(nullptr, resultSet);
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    RowEntity rowEntity;
    ASSERT_EQ(E_OK, resultSet->GetRow(rowEntity));
    ASSERT_EQ(1, int(rowEntity.Get("id")));
    resultSet->Close();
    store2 = nullptr;
}

/** 
  * @tc.name: KeyCorruptTest
  * @tc.desc: test key file not exist when readonly
  * @tc.type: FUNC
  */
HWTEST_F(RdbEncryptTest, KeyCorruptTest_02, TestSize.Level1)
{
    RdbStoreConfig config1(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config1.SetEncryptStatus(true);
    config1.SetBundleName("com.example.TestEncrypt1");
    EncryptTestOpenCallback helper1;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config1, 1, helper1, errCode);
    ASSERT_NE(nullptr, store1);
    ASSERT_EQ(E_OK, errCode);
    int64_t id;
    int ret = store1->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);
    store1 = nullptr;

    RdbSecurityManager::KeyFiles keyFile(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    std::string file = keyFile.GetKeyFile(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
    ASSERT_TRUE(OHOS::FileExists(file));
    std::remove(file.c_str());
    ASSERT_FALSE(OHOS::FileExists(file));

    RdbStoreConfig config2(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config2.SetEncryptStatus(true);
    config2.SetBundleName("com.example.TestEncrypt1");
    config2.SetReadOnly(true);
    EncryptTestOpenCallback helper2;
    std::shared_ptr<RdbStore> store2 = RdbHelper::GetRdbStore(config2, 1, helper2, errCode);
    ASSERT_NE(nullptr, store2);
    ASSERT_EQ(E_OK, errCode);

    std::shared_ptr<ResultSet> resultSet = store2->QuerySql("SELECT * FROM test");
    ASSERT_NE(nullptr, resultSet);
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    RowEntity rowEntity;
    ASSERT_EQ(E_OK, resultSet->GetRow(rowEntity));
    ASSERT_EQ(1, int(rowEntity.Get("id")));
    resultSet->Close();
    store2 = nullptr;
}

/**
  * @tc.name: KeyCorruptTest
  * @tc.desc: test save key data to file failed
  * @tc.type: FUNC
  */
HWTEST_F(RdbEncryptTest, KeyCorruptTest_03, TestSize.Level0)
{
    RdbStoreConfig config1(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config1.SetEncryptStatus(true);
    config1.SetBundleName("com.example.TestEncrypt1");
    EncryptTestOpenCallback helper1;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config1, 1, helper1, errCode);
    ASSERT_NE(nullptr, store1);
    ASSERT_EQ(E_OK, errCode);
    store1 = nullptr;

    RdbSecurityManager::KeyFiles keyFile(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    std::string file = keyFile.GetKeyFile(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
    ASSERT_TRUE(OHOS::FileExists(file));
    std::vector<char> keyfileData;
    ASSERT_TRUE(OHOS::LoadBufferFromFile(file, keyfileData));

    std::vector<char> keyCorrupted = keyfileData;
    // fill bytes of keyfile index 10 to 19 with 0
    for (size_t i = 10; i < 20 && i < keyCorrupted.size(); ++i) {
        keyCorrupted[i] = 0;
    }
    ASSERT_TRUE(OHOS::SaveBufferToFile(file, keyCorrupted));

    std::string chattrAddiCmd = "chattr +i " + file;
    ASSERT_EQ(E_OK, system(chattrAddiCmd.c_str()));

    RdbStoreConfig config2(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config2.SetEncryptStatus(true);
    config2.SetBundleName("com.example.TestEncrypt1");
    EncryptTestOpenCallback helper2;
    std::shared_ptr<RdbStore> store2 = RdbHelper::GetRdbStore(config2, 1, helper2, errCode);
    ASSERT_NE(nullptr, store2);
    ASSERT_EQ(E_OK, errCode);

    // Enable the wal file operation.
    std::string chattrSubiCmd = "chattr -i " + file;
    ASSERT_EQ(E_OK, system(chattrSubiCmd.c_str()));
}