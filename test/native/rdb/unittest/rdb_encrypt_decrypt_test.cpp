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
    static const std::string UNENCRYPTED_DATABASE_NAME;
    static std::shared_ptr<RdbStore> testStore;
};

const std::string RdbEncryptTest::ENCRYPTED_DATABASE_NAME = RDB_TEST_PATH + "encrypted.db";
const std::string RdbEncryptTest::UNENCRYPTED_DATABASE_NAME = RDB_TEST_PATH + "unencrypted.db";

std::shared_ptr<RdbStore> RdbEncryptTest::testStore = nullptr;

class EncryptTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const EncryptTestOpenCallback::CREATE_TABLE_TEST = std::string("CREATE TABLE IF NOT EXISTS test ")
                                                               + std::string("(id INTEGER PRIMARY KEY "
                                                                             "AUTOINCREMENT, "
                                                                             "name TEXT NOT NULL, age INTEGER, "
                                                                             "salary "
                                                                             "REAL, blobType BLOB)");

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
 * @tc.require:
 * @tc.author:
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
 * @tc.require:
 * @tc.author:
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
 * @tc.require:
 * @tc.author:
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
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    int intVal;
    std::string strVal;
    double dVal;
    std::vector<uint8_t> blob;

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

    ret = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(18, intVal);

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
    EXPECT_EQ(ret, E_ERROR);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_004
 * @tc.desc: test RdbStore key file.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
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

    RdbHelper::DeleteRdbStore(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    ret = access(keyPath.c_str(), F_OK);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_005
 * @tc.desc: test RdbStore Get Encrypted Store with empty boundlename
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_05, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(store, nullptr);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_006
 * @tc.desc: test SaveSecretKeyToFile when KeyFileType isNot PUB_KEY_FILE
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_06, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt6");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool ret =
        RdbSecurityManager::GetInstance().CheckKeyDataFileExists(RdbSecurityManager::KeyFileType::PUB_KEY_BAK_FILE);
    EXPECT_EQ(ret, false);
    std::vector<uint8_t> key = RdbSecurityManager::GetInstance().GenerateRandomNum(RdbSecurityManager::RDB_KEY_SIZE);
    bool flag = RdbSecurityManager::GetInstance().SaveSecretKeyToFile(
        RdbSecurityManager::KeyFileType::PUB_KEY_BAK_FILE, key);
    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_007
 * @tc.desc: test GetRdbPassword when KeyFileType isNot PUB_KEY_FILE
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_07, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt7");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    auto key = RdbSecurityManager::GetInstance().GetRdbPassword(RdbSecurityManager::KeyFileType::PUB_KEY_BAK_FILE);
    RdbPassword password = {};
    EXPECT_EQ(key, password);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_008
 * @tc.desc: test RemoveSuffix when pos == std::string::npos
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_08, TestSize.Level1)
{
    std::string path = RDB_TEST_PATH + "test";
    RdbStoreConfig config(path);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt8");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_009
 * @tc.desc: test GetKeyDistributedStatus and SetKeyDistributedStatus
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbEncryptTest, RdbStore_Encrypt_09, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt9");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    bool distributedStatus = false;
    int ret = RdbSecurityManager::GetInstance().GetKeyDistributedStatus(
        RdbSecurityManager::KeyFileType::PUB_KEY_FILE, distributedStatus);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(distributedStatus, false);
    ret = RdbSecurityManager::GetInstance().GetKeyDistributedStatus(
        RdbSecurityManager::KeyFileType::PUB_KEY_BAK_FILE, distributedStatus);
    EXPECT_EQ(ret, E_ERROR);
    EXPECT_EQ(distributedStatus, false);
    ret = RdbSecurityManager::GetInstance().SetKeyDistributedStatus(
        RdbSecurityManager::KeyFileType::PUB_KEY_FILE, true);
    EXPECT_EQ(ret, E_OK);
    ret = RdbSecurityManager::GetInstance().GetKeyDistributedStatus(
        RdbSecurityManager::KeyFileType::PUB_KEY_FILE, distributedStatus);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(distributedStatus, true);
    ret = RdbSecurityManager::GetInstance().SetKeyDistributedStatus(
        RdbSecurityManager::KeyFileType::PUB_KEY_BAK_FILE, distributedStatus);
    EXPECT_EQ(ret, E_ERROR);
}
