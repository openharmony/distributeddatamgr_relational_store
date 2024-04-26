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
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_001
 * @tc.desc: test RdbStore Get Encrypt Store
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_01, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt1");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_002
 * @tc.desc: test RdbStore Get Unencrypted Store
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_02, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::UNENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(false);
    config.SetBundleName("com.example.TestEncrypt2");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_003
 * @tc.desc: test create encrypted Rdb and insert data ,then query
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_03, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt3");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    int intVal;
    std::string strVal;

    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_004
 * @tc.desc: test RdbStore key file.
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_04, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt4");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    std::string keyPath = RDB_TEST_PATH + "key/encrypted.pub_key";
    int ret = access(keyPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    ret = access(keyPath.c_str(), F_OK);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_005
 * @tc.desc: test RdbStore Get Encrypted Store with empty boundlename
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_05, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_006
 * @tc.desc: test GetRdbStore with specified key
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_06, TestSize.Level1)
{
    std::vector<uint8_t> key{ 1, 2, 3 };
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptKey(key);
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    std::string keyPath = RDB_TEST_PATH + "key/" + "encrypted.pub_key";
    std::string newKeyPath = RDB_TEST_PATH + "key/" + +"encrypted.pub_key.new";
    bool isFileExists = OHOS::FileExists(keyPath);
    EXPECT_EQ(isFileExists, false);
    isFileExists = OHOS::FileExists(newKeyPath);
    EXPECT_EQ(isFileExists, false);

    store.reset();
    RdbHelper::ClearCache();

    std::vector<uint8_t> wrongKey{ 4, 5, 6 };
    config.SetEncryptKey(wrongKey);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(store, nullptr);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_007
 * @tc.desc: test RemoveSuffix when pos == std::string::npos
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_07, TestSize.Level1)
{
    std::string path = RDB_TEST_PATH + "test";
    RdbHelper::DeleteRdbStore(path);
    RdbStoreConfig config(path);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt7");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    store = nullptr;
    errCode = RdbHelper::DeleteRdbStore(path);
    EXPECT_EQ(errCode, E_OK);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_008
 * @tc.desc: test RdbStore Get Encrypt Store without SetBundleName
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_008, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_009
 * @tc.desc: test create encrypted Rdb and insert data ,then query
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_009, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt9");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    double dVal;
    std::vector<uint8_t> blob;

    ret = resultSet->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(100.5, dVal);

    ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(1, blob[0]);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
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
    uint8_t inputData[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    std::ostringstream ss;
    std::copy(inputData, inputData+sizeof(inputData), std::ostream_iterator<int>(ss));

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
 * @tc.name: KeyFilePath_test_001, open different databases and obtain the corresponding key files
 * @tc.desc: 1.create db1
 *           2.create db2
 *           3.create table in the db2
 *           4.backup db1
 *           5.restore db1
 *
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptTest, KeyFilePath_test_001, TestSize.Level2)
{
    RdbStoreConfig config1(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config1.SetEncryptStatus(true);
    config1.SetBundleName("com.example.TestEncrypt1");
    EncryptTestOpenCallback helper1;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config1, 1, helper1, errCode);
    EXPECT_NE(nullptr, store1);
    EXPECT_EQ(E_OK, errCode);

    RdbStoreConfig config2(RdbEncryptTest::ENCRYPTED_DATABASE_NAME2);
    config2.SetEncryptStatus(true);
    config2.SetBundleName("com.example.TestEncrypt1");
    EncryptTestOpenCallback helper2;
    std::shared_ptr<RdbStore> store2 = RdbHelper::GetRdbStore(config2, 1, helper2, errCode);
    EXPECT_NE(nullptr, store2);
    EXPECT_EQ(E_OK, errCode);

    EXPECT_EQ(E_OK, store1->Backup(RdbEncryptTest::ENCRYPTED_DATABASE_BACKUP_NAME));
    EXPECT_EQ(E_OK, store1->Restore(RdbEncryptTest::ENCRYPTED_DATABASE_BACKUP_NAME));

    EXPECT_EQ(E_OK, store2->Backup(RdbEncryptTest::ENCRYPTED_DATABASE_BACKUP_NAME2));
    EXPECT_EQ(E_OK, store2->Restore(RdbEncryptTest::ENCRYPTED_DATABASE_BACKUP_NAME2));
}