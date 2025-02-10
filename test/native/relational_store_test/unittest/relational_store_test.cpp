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
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void QueryCheck1(std::shared_ptr<RdbStore> &store) const;
    void QueryCheck2(std::shared_ptr<RdbStore> &store) const;

    static const std::string MAIN_DATABASE_NAME;
    static const std::string ATTACHED_DATABASE_NAME;
    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

const std::string RdbTest::MAIN_DATABASE_NAME = RDB_TEST_PATH + "main.db";
const std::string RdbTest::DATABASE_NAME = RDB_TEST_PATH + "delete_test.db";
const std::string RdbTest::DATABASE_NAME = RDB_TEST_PATH + "update_test.db";
std::shared_ptr<RdbStore> RdbTest::store = nullptr;

class DeleteTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const DeleteTestOpenCallback::CREATE_TABLE_TEST =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");

int DeleteTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int DeleteTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

class MainOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const MainOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test1(id INTEGER PRIMARY KEY "
                                                        "AUTOINCREMENT, name TEXT NOT NULL)";

int MainOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int MainOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

const std::string RdbTest::ATTACHED_DATABASE_NAME = RDB_TEST_PATH + "attached.db";

class AttachedOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const AttachedOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test2(id INTEGER PRIMARY KEY "
                                                            "AUTOINCREMENT, name TEXT NOT NULL)";

int AttachedOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int AttachedOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbTest::SetUpTestCase(void)
{
    RdbStoreConfig attachedConfig(RdbTest::ATTACHED_DATABASE_NAME);
    AttachedOpenCallback attachedHelper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> attachedStore = RdbHelper::GetRdbStore(attachedConfig, 1, attachedHelper, errCode);
    EXPECT_NE(attachedStore, nullptr);
}

void RdbTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
    RdbHelper::DeleteRdbStore(ATTACHED_DATABASE_NAME);
}

void RdbTest::SetUp(void)
{
}

void RdbTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

/**
 * @tc.name: RdbStore_Attach_001
 * @tc.desc: test attach, attach is not supported in wal mode
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Attach_001, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::MAIN_DATABASE_NAME);
    MainOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int ret = store->ExecuteSql("ATTACH '" + ATTACHED_DATABASE_NAME + "' as attached");
    EXPECT_EQ(ret, E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE);

    ret = store->ExecuteSql("attach '" + ATTACHED_DATABASE_NAME + "' as attached");
    EXPECT_EQ(ret, E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE);
}

/**
 * @tc.name: RdbStore_Attach_002
 * @tc.desc: test RdbStore attach
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Attach_002, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::MAIN_DATABASE_NAME);
    config.SetJournalMode(JournalMode::MODE_TRUNCATE);
    MainOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int ret = store->ExecuteSql("ATTACH DATABASE '" + ATTACHED_DATABASE_NAME + "' as 'attached'");
    EXPECT_EQ(ret, E_OK);

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("lisi"));
    ret = store->Insert(id, "test2", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

    QueryCheck1(store);

    ret = store->ExecuteSql("DETACH DATABASE 'attached'");
    EXPECT_EQ(ret, E_OK);

    QueryCheck2(store);

    ret = store->ExecuteSql("attach database '" + ATTACHED_DATABASE_NAME + "' as 'attached'");
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteSql("detach database 'attached'");
    EXPECT_EQ(ret, E_OK);
}

void RdbTest::QueryCheck1(std::shared_ptr<RdbStore> &store) const
{
    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test1");
    EXPECT_NE(resultSet, nullptr);
    int ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    int columnIndex;
    int intVal;
    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(intVal, 1);
    std::string strVal;
    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(strVal, "zhangsan");

    resultSet = store->QuerySql("SELECT * FROM test2");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(intVal, 1);
    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(strVal, "lisi");
}

void RdbTest::QueryCheck2(std::shared_ptr<RdbStore> &store) const
{
    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test1");
    EXPECT_NE(resultSet, nullptr);
    int ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    int columnIndex;
    int intVal;
    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(intVal, 1);
    std::string strVal;
    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(strVal, "zhangsan");

    // detached, no table test2
    resultSet = store->QuerySql("SELECT * FROM test2");
    EXPECT_NE(resultSet, nullptr);
}

/**
 * @tc.name: RdbStore_Delete_001
 * @tc.desc: test RdbStore update, select id and update one row
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Delete_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;
    int deletedRows;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, deletedRows);

    std::unique_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE id = ?", std::vector<std::string>{ "1" });
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ERROR);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    resultSet = store->QuerySql("SELECT * FROM test WHERE id = ?", std::vector<std::string>{ "2" });
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ERROR);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    resultSet = store->QuerySql("SELECT * FROM test WHERE id = 3", std::vector<std::string>());
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ERROR);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Delete_002
 * @tc.desc: test RdbStore update, select id and update one row
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Delete_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;
    int deletedRows;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, deletedRows);

    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ERROR);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_001
 * @tc.desc: test RdbStore Get Encrypt Store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbTest, RdbStore_Encrypt_01, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::ENCRYPTED_DATABASE_NAME);
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
HWTEST_F(RdbTest, RdbStore_Encrypt_02, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::UNENCRYPTED_DATABASE_NAME);
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
HWTEST_F(RdbTest, RdbStore_Encrypt_03, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::ENCRYPTED_DATABASE_NAME);
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
HWTEST_F(RdbTest, RdbStore_Encrypt_04, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::ENCRYPTED_DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.TestEncrypt4");
    EncryptTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    std::string keyPath = RDB_TEST_PATH + "key/encrypted.pub_key";
    int ret = access(keyPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    RdbHelper::DeleteRdbStore(RdbTest::ENCRYPTED_DATABASE_NAME);
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
HWTEST_F(RdbTest, RdbStore_Encrypt_05, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::ENCRYPTED_DATABASE_NAME);
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
HWTEST_F(RdbTest, RdbStore_Encrypt_06, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::ENCRYPTED_DATABASE_NAME);
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
    bool flag =
        RdbSecurityManager::GetInstance().SaveSecretKeyToFile(RdbSecurityManager::KeyFileType::PUB_KEY_BAK_FILE, key);
    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: RdbStore_Encrypt_Decrypt_Test_007
 * @tc.desc: test GetRdbPassword when KeyFileType isNot PUB_KEY_FILE
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbTest, RdbStore_Encrypt_07, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::ENCRYPTED_DATABASE_NAME);
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
HWTEST_F(RdbTest, RdbStore_Encrypt_08, TestSize.Level1)
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
HWTEST_F(RdbTest, RdbStore_Encrypt_09, TestSize.Level1)
{
    RdbStoreConfig config(RdbTest::ENCRYPTED_DATABASE_NAME);
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
    ret =
        RdbSecurityManager::GetInstance().SetKeyDistributedStatus(RdbSecurityManager::KeyFileType::PUB_KEY_FILE, true);
    EXPECT_EQ(ret, E_OK);
    ret = RdbSecurityManager::GetInstance().GetKeyDistributedStatus(
        RdbSecurityManager::KeyFileType::PUB_KEY_FILE, distributedStatus);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(distributedStatus, true);
    ret = RdbSecurityManager::GetInstance().SetKeyDistributedStatus(
        RdbSecurityManager::KeyFileType::PUB_KEY_BAK_FILE, distributedStatus);
    EXPECT_EQ(ret, E_ERROR);
}

/**
 * @tc.name: RdbStore_Execute_001
 * @tc.desc: test RdbStore Execute
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Execute_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

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

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    ret = store->ExecuteSql("DELETE FROM test WHERE age = ? OR age = ?",
        std::vector<ValueObject>{ ValueObject(std::string("18")), ValueObject(std ::string("20")) });
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test where age = 19");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 1);

    ret = store->ExecuteSql("DELETE FROM test WHERE age = 19");
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 0);
}

/**
 * @tc.name: RdbStore_Execute_002
 * @tc.desc: test RdbStore Execute
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Execute_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

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

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(3, id);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test", std::vector<ValueObject>());
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    ret = store->ExecuteSql("DELETE FROM test WHERE age = ? OR age = ?",
        std::vector<ValueObject>{ ValueObject(std::string("18")), ValueObject(std ::string("20")) });
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(
        count, "SELECT COUNT(*) FROM test where age = ?", std::vector<ValueObject>{ ValueObject(std::string("19")) });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 1);

    ret = store->ExecuteSql("DELETE FROM test WHERE age = 19");
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test", std::vector<ValueObject>());
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 0);

    ret = store->ExecuteSql("DROP TABLE IF EXISTS test");
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: RdbStore_Execute_003
 * @tc.desc: test RdbStore Execute
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Execute_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t pageSize;
    int ret = store->ExecuteAndGetLong(pageSize, "PRAGMA page_size");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(pageSize, 4096);

    std::string journalMode;
    ret = store->ExecuteAndGetString(journalMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(journalMode, "wal");
}

/**
 * @tc.name: RdbStore_Insert_001
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Insert_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

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

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20L);
    values.PutDouble("salary", 100.5f);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    RdbTest::CheckResultSet(store);
}

void RdbTest::CheckResultSet(std::shared_ptr<RdbStore> &store)
{
    std::unique_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    EXPECT_NE(resultSet, nullptr);

    int columnIndex;
    int intVal;
    std::string strVal;
    ColumnType columnType;
    int position;
    int ret = resultSet->GetRowIndex(position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, -1);

    ret = resultSet->GetColumnType(0, columnType);
    EXPECT_EQ(ret, E_INVALID_STATEMENT);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);

    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnIndex, 0);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_STRING);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    RdbTest::CheckAge(resultSet);
    RdbTest::CheckSalary(resultSet);
    RdbTest::CheckBlob(resultSet);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ERROR);

    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_INVALID_STATEMENT);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

void RdbTest::CheckAge(std::unique_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    int intVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(18, intVal);
}

void RdbTest::CheckSalary(std::unique_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    double dVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_FLOAT);
    ret = resultSet->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(100.5, dVal);
}

void RdbTest::CheckBlob(std::unique_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    std::vector<uint8_t> blob;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_BLOB);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(1, blob[0]);
    EXPECT_EQ(2, blob[1]);
    EXPECT_EQ(3, blob[2]);
}

/**
 * @tc.name: RdbStore_Replace_001
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Replace_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Replace(id, "test", values);
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
    EXPECT_EQ(2, blob[1]);
    EXPECT_EQ(3, blob[2]);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ERROR);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Replace_002
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_Replace_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

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

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Replace(id, "test", values);
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
    EXPECT_EQ(200.5, dVal);

    ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(1, blob[0]);
    EXPECT_EQ(2, blob[1]);
    EXPECT_EQ(3, blob[2]);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ERROR);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_001_002
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_InsertWithConflictResolution_001_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    // default is ConflictResolution::ON_CONFLICT_NONE
    int ret = store->InsertWithConflictResolution(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->InsertWithConflictResolution(id, "test", values);
    EXPECT_EQ(ret, RdbTest::E_SQLITE_CONSTRAINT);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_003_004
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_InsertWithConflictResolution_003_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, RdbTest::E_SQLITE_CONSTRAINT);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_005
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_InsertWithConflictResolution_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, -1);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_006_007
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, RdbStore_InsertWithConflictResolution_006_007, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

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
    EXPECT_EQ(200.5, dVal);

    ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(4, blob[0]);
    EXPECT_EQ(5, blob[1]);
    EXPECT_EQ(6, blob[2]);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ERROR);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_BatchInsert_001
 * @tc.desc: test RdbStore BatchInsert
 * @tc.type: FUNC
 * @tc.require: issueI5GZGX
 */
HWTEST_F(RdbTest, RdbStore_BatchInsert_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    ValuesBucket values;

    values.PutString("name", "zhangsan");
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 100; i++) {
        valuesBuckets.push_back(values);
    }
    int64_t insertNum = 0;
    int ret = store->BatchInsert(insertNum, "test", valuesBuckets);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(100, insertNum);
    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    int rowCount = 0;
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(100, rowCount);
}

/**
 * @tc.name: ValueObject_TEST_001
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, ValueObject_TEST_001, TestSize.Level1)
{
    ValueObject obj = ValueObject();
    ValueObjectType type = obj.GetType();
    EXPECT_EQ(type, ValueObjectType::TYPE_NULL);
}

/**
 * @tc.name: ValueObject_TEST_002
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, ValueObject_TEST_002, TestSize.Level1)
{
    int inputVal = 5;
    int outputVal = 0;
    ValueObject obj = ValueObject(inputVal);
    ValueObjectType type = obj.GetType();
    EXPECT_EQ(type, ValueObjectType::TYPE_INT);
    int ret = obj.GetInt(outputVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outputVal, 5);
}

/**
 * @tc.name: ValueObject_TEST_003
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, ValueObject_TEST_003, TestSize.Level1)
{
    bool inputVal = true;
    bool outputVal = false;
    ValueObject obj = ValueObject(inputVal);
    ValueObjectType type = obj.GetType();
    EXPECT_EQ(type, ValueObjectType::TYPE_BOOL);
    int ret = obj.GetBool(outputVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outputVal, true);
}

/**
 * @tc.name: ValueObject_TEST_004
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, ValueObject_TEST_004, TestSize.Level1)
{
    std::string inputVal = "hello";
    std::string outputVal = "";
    ValueObject obj = ValueObject(inputVal);
    ValueObjectType type = obj.GetType();
    EXPECT_EQ(type, ValueObjectType::TYPE_STRING);
    int ret = obj.GetString(outputVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outputVal, "hello");
}

/**
 * @tc.name: ValueObject_TEST_005
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, ValueObject_TEST_005, TestSize.Level1)
{
    std::vector<uint8_t> inputVal = { 'h', 'e', 'l', 'l', 'o' };
    std::vector<uint8_t> outputVal;
    ValueObject obj = ValueObject(inputVal);
    ValueObjectType type = obj.GetType();
    EXPECT_EQ(type, ValueObjectType::TYPE_BLOB);
    int ret = obj.GetBlob(outputVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(static_cast<int>(outputVal.size()), 5);
    EXPECT_EQ(outputVal[0], 'h');
    EXPECT_EQ(outputVal[1], 'e');
    EXPECT_EQ(outputVal[2], 'l');
    EXPECT_EQ(outputVal[3], 'l');
    EXPECT_EQ(outputVal[4], 'o');
}

/**
 * @tc.name: ValueObject_TEST_006
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, ValueObject_TEST_006, TestSize.Level1)
{
    int inputVal = 5;
    ValueObject obj = ValueObject(inputVal);
    ValueObject obj1 = ValueObject();
    obj1 = obj;
    ValueObjectType type = obj1.GetType();
    EXPECT_EQ(type, ValueObjectType::TYPE_INT);
}

/**
 * @tc.name: ValuesBucket_001
 * @tc.desc: test ValuesBucket
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, ValuesBucket_001, TestSize.Level1)
{
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutNull("name");
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    int size = values.Size();
    EXPECT_EQ(size, 5);
    bool contains = values.HasColumn("name");
    EXPECT_EQ(contains, true);
    ValueObject obj;
    contains = values.GetObject("salary", obj);
    double val = 0.0;
    ValueObjectType type = obj.GetType();
    EXPECT_EQ(type, ValueObjectType::TYPE_DOUBLE);
    int ret = obj.GetDouble(val);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(val, 100.5);

    values.Delete("name");
    size = values.Size();
    EXPECT_EQ(size, 4);
    contains = values.HasColumn("name");
    EXPECT_EQ(contains, false);

    values.Clear();
    size = values.Size();
    EXPECT_EQ(size, 0);
    contains = values.HasColumn("salary");
    EXPECT_EQ(contains, false);
}

/**
 * @tc.name: ValuesBucket_002
 * @tc.desc: test ValuesBucket
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, ValuesBucket_002, TestSize.Level1)
{
    int errCode = E_OK;
    const std::string dbPath = RDB_TEST_PATH + "InterfaceTest.db";
    RdbStoreConfig config(dbPath);
    MyOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutNull("name");
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    int columnIndex;
    std::string strVal;

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);

    resultSet->Close();
    resultSet = nullptr;
    store = nullptr;
    ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: ValuesBucket_003
 * @tc.desc: test ValuesBucket
 * @tc.type: FUNC
 * @tc.author: 
 */
HWTEST_F(RdbTest, ValuesBucket_003, TestSize.Level1)
{
    ValuesBucket values;
    values.PutBool("boolType", true);
    values.PutLong("longType", 1);

    int size = values.Size();
    EXPECT_EQ(size, 2);
    bool contains = values.HasColumn("boolType");
    EXPECT_EQ(contains, true);
    ValueObject obj;
    contains = values.GetObject("boolType", obj);
    ValueObjectType type = obj.GetType();
    EXPECT_EQ(type, ValueObjectType::TYPE_BOOL);
    bool val1 = false;
    int ret = obj.GetBool(val1);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(val1, true);

    contains = values.HasColumn("longType");
    EXPECT_EQ(contains, true);
    contains = values.GetObject("longType", obj);
    type = obj.GetType();
    EXPECT_EQ(type, ValueObjectType::TYPE_INT64);
    int64_t val2 = 0;
    ret = obj.GetLong(val2);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(val2, 1);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_001
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, RdbStore_UpdateWithConflictResolution_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to wangjing age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = 19");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 3, "wangjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } });

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
HWTEST_F(RdbTest, RdbStore_UpdateWithConflictResolution_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to zhangsan age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 } });

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
HWTEST_F(RdbTest, RdbStore_UpdateWithConflictResolution_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to wangjing age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 3, "wangjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } });

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
HWTEST_F(RdbTest, RdbStore_UpdateWithConflictResolution_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to zhangsan age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 } });

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
HWTEST_F(RdbTest, RdbStore_UpdateWithConflictResolution_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to wangjing age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } });

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbTest::ExpectValue(resultSet, RowData{ 3, "wangjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } });

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
HWTEST_F(RdbTest, RdbStore_UpdateWithConflictResolution_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to zhangsan age=20
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?", std::vector<std::string>{ "19" },
        ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(changedRows, 1);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    RdbTest::ExpectValue(resultSet, RowData{ 2, "zhangsan", 20, 300.5, std::vector<uint8_t>{ 4, 5, 6 } });

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
HWTEST_F(RdbTest, RdbStore_UpdateWithConflictResolution_007, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int changedRows;
    int64_t id;
    ValuesBucket values;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.PutInt("id", 2);
    values.PutInt("age", 19);
    ret = store->UpdateWithConflictResolution(
        changedRows, "test", values, "age = ?", std::vector<std::string>{ "18" }, static_cast<ConflictResolution>(6));
    EXPECT_EQ(E_INVALID_CONFLICT_FLAG, ret);
    EXPECT_EQ(0, changedRows);

    values.Clear();
    values.PutInt("id", 2);
    values.PutInt("age", 19);
    ret = store->UpdateWithConflictResolution(
        changedRows, "test", values, "age = ?", std::vector<std::string>{ "18" }, static_cast<ConflictResolution>(-1));
    EXPECT_EQ(E_INVALID_CONFLICT_FLAG, ret);
    EXPECT_EQ(0, changedRows);
}

/**
 * @tc.name: RdbStore_UpdateSqlBuilder_001
 * @tc.desc: test RdbStore UpdateSqlBuilder
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, RdbStore_UpdateSqlBuilder_001, TestSize.Level1)
{
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);

    std::vector<ValueObject> bindArgs;
    std::string updateSql = SqliteSqlBuilder::BuildUpdateString(values, "test", std::vector<std::string>{ "19" }, "",
        "age = ?", "", "", INT_MIN, INT_MIN, bindArgs, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(updateSql, "UPDATE test SET age=?,name=?,salary=? WHERE age = ?");

    updateSql = SqliteSqlBuilder::BuildUpdateString(values, "test", std::vector<std::string>{}, "", "", "", "",
        INT_MIN, INT_MIN, bindArgs, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(updateSql, "UPDATE test SET age=?,name=?,salary=?");
}

void RdbTest::ExpectValue(const std::shared_ptr<OHOS::NativeRdb::ResultSet> &resultSet, const RowData &expect)
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
