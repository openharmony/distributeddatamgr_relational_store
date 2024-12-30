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

#include "common.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include <string>

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbStoreUnittest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void QueryCheckVirtual1(std::shared_ptr<RdbStoreTest> &store11) const;
    void QueryCheckVirtual2(std::shared_ptr<RdbStoreTest> &store11) const;

    static const std::string rdbMainRdbDatabaseName;
    static const std::string rdbDatabaseName;
    static const std::string rdbDatabaseName;
    static std::shared_ptr<RdbStoreTest> store11;
};

const std::string RdbStoreUnittest::rdbMainRdbDatabaseName = RDB_UNITTEST_PATH + "main.db";
const std::string RdbStoreUnittest::rdbDatabaseName = RDB_UNITTEST_PATH + "delete_test.db";
const std::string RdbStoreUnittest::rdbDatabaseName = RDB_UNITTEST_PATH + "update_test.db";
std::shared_ptr<RdbStoreTest> RdbStoreUnittest::store11 = nullptr;

class DeleteOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStoreTest &rdbStore) override;
    int OnUpgrade(RdbStoreTest &rdbStore, int oldVersion, int newVersion) override;
    static const std::string createTableUnittest;
};

std::string const DeleteOpenCallback::createTableUnittest =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(idTest INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "nametest TEXT NOT NULL, age INTEGER, salaryTest "
                                                                  "REAL, blobType BLOB)");

int DeleteOpenCallback::OnUpgrade(RdbStoreTest &store11, int oldVersion, int newVersion)
{
    return E_OK;
}

int DeleteOpenCallback::OnCreate(RdbStoreTest &store11)
{
    return store11.ExecuteSql(createTableUnittest);
}

class MainOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStoreTest &rdbStore) override;
    int OnUpgrade(RdbStoreTest &rdbStore, int oldVersion, int newVersion) override;
    static const std::string createTableUnittest;
};

std::string const MainOpenCallback::createTableUnittest = "CREATE TABLE IF NOT EXISTS (idTest INTEGER PRIMARY KEY "
                                                        "AUTOINCREMENT, nametest TEXT NOT NULL)";

int MainOpenCallback::OnCreate(RdbStoreTest &store11)
{
    return store11.ExecuteSql(createTableUnittest);
}

int MainOpenCallback::OnUpgrade(RdbStoreTest &store11, int oldVersion, int newVersion)
{
    return E_OK;
}

const std::string RdbStoreUnittest::rdbDatabaseName = RDB_UNITTEST_PATH + "attached.db";

class AttachOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStoreTest &rdbStore) override;
    int OnUpgrade(RdbStoreTest &rdbStore, int oldVersion, int newVersion) override;
    static const std::string createTableUnittest;
};

std::string const AttachOpenCallback::createTableUnittest = "CREATE TABLE IF NOT EXISTS (idTest INTEGER PRIMARY KEY "
                                                            "AUTOINCREMENT, nametest TEXT NOT NULL)";

int AttachOpenCallback::OnCreate(RdbStoreTest &store11)
{
    return store11.ExecuteSql(createTableUnittest);
}

int AttachOpenCallback::OnUpgrade(RdbStoreTest &store11, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreUnittest::SetUpTestCase(void)
{
    RdbStoreConfig attachedConfig(RdbStoreUnittest::rdbMainRdbDatabaseName);
    AttachOpenCallback attachedHelper;
    int errorCode = E_OK;
    std::shared_ptr<RdbStoreTest> attachedStore = RdbHelper::GetRdbStore(attachedConfig, 1, attachedHelper, errorCode);
    ASSERT_NE(attachedStore, nullptr);
}

void RdbStoreUnittest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdb(rdbMainRdbDatabaseName);
    RdbHelper::DeleteRdb(rdbMainRdbDatabaseName);
}

void RdbStoreUnittest::SetUp(void)
{
}

void RdbStoreUnittest::TearDown(void)
{
    RdbHelper::ClearCache();
}

/**
 * @tc.nametest: RdbStore_Attach_001
 * @tc.desc: test attach, attach is not supported in wal mode
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Attach_001Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::rdbMainRdbDatabaseName);
    MainOpenCallback helperTest;
    int errorCode = E_OK;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);

    int result = store11->ExecuteSql("ATTACH '" + rdbMainRdbDatabaseName + "' as attached");
    ASSERT_EQ(result, E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE);

    result = store11->ExecuteSql("attach '" + rdbMainRdbDatabaseName + "' as attached");
    ASSERT_EQ(result, E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE);
}

/**
 * @tc.nametest: RdbStore_Attach_002
 * @tc.desc: test RdbStoreTest attach
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Attach_002Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::rdbMainRdbDatabaseName);
    rdbConfig.SetJournalMode(JournalMode::MODE_TRUNCATE);
    MainOpenCallback helperTest;
    int errorCode = E_OK;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);
    int result = store11->ExecuteSql("ATTACH DATABASE '" + rdbMainRdbDatabaseName + "' as 'attached'");
    ASSERT_EQ(result, E_OK);
    int64_t idTest;
    ValuesBucket valuesItem;
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    result = store11->Insert(idTest, "test1", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(idTest, 1);
    valuesItem.Clear();
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("lisi"));
    result = store11->Insert(idTest, "test2", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(idTest, 1);

    QueryCheckVirtual1(store11);
    result = store11->ExecuteSql("DETACH DATABASE 'attached'");
    ASSERT_EQ(result, E_OK);
    QueryCheckVirtual2(store11);
    result = store11->ExecuteSql("attach database '" + rdbMainRdbDatabaseName + "' as 'attached'");
    ASSERT_EQ(result, E_OK);
    result = store11->ExecuteSql("detach database 'attached'");
    ASSERT_EQ(result, E_OK);
}

void RdbStoreUnittest::QueryCheckVirtual1(std::shared_ptr<RdbStoreTest> &store11) const
{
    std::unique_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test1");
    ASSERT_NE(resSet, nullptr);
    int result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    int colIndex;
    int intValue;
    result = resSet->GetColumnIndex("idTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(intValue, 1);
    std::string strValue;
    result = resSet->GetColumnIndex("nametest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetString(colIndex, strValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(strValue, "gdbdbg");

    resSet = store11->QuerySql("SELECT * FROM test2");
    ASSERT_NE(resSet, nullptr);
    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    result = resSet->GetColumnIndex("idTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(intValue, 1);
    result = resSet->GetColumnIndex("nametest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetString(colIndex, strValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(strValue, "lisi");
}

void RdbStoreUnittest::QueryCheckVirtual2(std::shared_ptr<RdbStoreTest> &store11) const
{
    std::unique_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test1");
    ASSERT_NE(resSet, nullptr);
    int result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    int colIndex;
    int intValue;
    result = resSet->GetColumnIndex("idTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(intValue, 1);
    std::string strValue;
    result = resSet->GetColumnIndex("nametest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetString(colIndex, strValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(strValue, "gdbdbg");

    resSet = store11->QuerySql("SELECT * FROM test2");
    ASSERT_NE(resSet, nullptr);
}

/**
 * @tc.nametest: RdbStore_Delete_001
 * @tc.desc: test RdbStoreTest update, select idTest and update one row
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Delete_001Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t idTest;
    ValuesBucket valuesItem;
    int deleteRows;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 2);
    valuesItem.PutString("nametest", std::string("lisi"));
    valuesItem.PutInt("age", 19);
    valuesItem.PutDouble("salaryTest", 200.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);
}

/**
 * @tc.nametest: RdbStore_Delete_002
 * @tc.desc: test RdbStoreTest update, select idTest and update one row
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Delete_002Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t idTest;
    ValuesBucket valuesItem;
    int deleteRows;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 2);
    valuesItem.PutString("nametest", std::string("lisi"));
    valuesItem.PutInt("age", 19);
    valuesItem.PutDouble("salaryTest", 200.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("sfgbngrh"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(3, idTest);

    std::unique_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);
    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ERROR);
    result = resSet->Close();
    ASSERT_EQ(result, E_OK);

    result = store11->Delete(deleteRows, "test");
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(3, deleteRows);
}

/**
 * @tc.nametest: RdbStore_Encrypt_Decrypt_Test_001
 * @tc.desc: test RdbStoreTest Get Encrypt Store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Encrypt_01Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::ENCRYPTED_RDB_DATABASE_NAME);
    rdbConfig.SetEncryptStatus(true);
    rdbConfig.SetBundleName("com.example.Encrypt1");
    EncryptOpenCallback helperTest;
    int errorCode;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);

    resSet = store11->QuerySql("SELECT * FROM test WHERE idTest = 3", std::vector<std::string>());
    ASSERT_NE(resSet, nullptr);
    result = resSet->GoToFirstRow();
    ASSERT_EQ(result, E_OK);
    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ERROR);
    result = resSet->Close();
    ASSERT_EQ(result, E_OK);

    resSet = store11->QuerySql("SELECT * FROM test WHERE idTest = ?", std::vector<std::string>{ "2" });
    ASSERT_NE(resSet, nullptr);
    result = resSet->GoToFirstRow();
    ASSERT_EQ(result, E_OK);
    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ERROR);
    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_Encrypt_Decrypt_Test_002
 * @tc.desc: test RdbStoreTest Get Unencrypted Store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Encrypt_02Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::UNENCRYPTED_RDB_DATABASE_NAME);
    rdbConfig.SetEncryptStatus(false);
    rdbConfig.SetBundleName("com.example.Encrypt2");
    EncryptOpenCallback helperTest;
    int errorCode;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("sfgbngrh"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(3, idTest);

    result = store11->Delete(deleteRows, "test", "idTest = 1");
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, deleteRows);

    std::unique_ptr<ResultSet> resSet =
        store11->QuerySql("SELECT * FROM test WHERE idTest = ?", std::vector<std::string>{ "1" });
    ASSERT_NE(resSet, nullptr);
    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ERROR);
    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_Encrypt_Decrypt_Test_003
 * @tc.desc: test create encrypted Rdb and insert data ,then query
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Encrypt_03Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::ENCRYPTED_RDB_DATABASE_NAME);
    rdbConfig.SetEncryptStatus(true);
    rdbConfig.SetBundleName("com.example.Encrypt3");
    EncryptOpenCallback helperTest;
    int errorCode;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);

    int64_t idTest;
    ValuesBucket valuesItem;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    std::unique_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);

    int colIndex;
    int intValue;
    std::string strValue;
    double dValue;
    std::vector<uint8_t> bb;

    result = resSet->GetColumnIndex("idTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, intValue);
}

/**
 * @tc.nametest: RdbStore_Encrypt_Decrypt_Test_004
 * @tc.desc: test RdbStoreTest kk file.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Encrypt_04Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::ENCRYPTED_RDB_DATABASE_NAME);
    rdbConfig.SetEncryptStatus(true);
    rdbConfig.SetBundleName("com.example.Encrypt4");
    EncryptOpenCallback helperTest;
    int errorCode;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);
    std::string keyPath = RDB_UNITTEST_PATH + "kk/encrypted.pub_key";
    int result = access(keyPath.c_str(), F_OK);
    ASSERT_EQ(result, 0);

    RdbHelper::DeleteRdb(RdbStoreUnittest::ENCRYPTED_RDB_DATABASE_NAME);
    result = access(keyPath.c_str(), F_OK);
    ASSERT_EQ(result, -1);
}

/**
 * @tc.nametest: RdbStore_Encrypt_Decrypt_Test_005
 * @tc.desc: test RdbStoreTest Get Encrypted Store with empty boundlename
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Encrypt_05Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::ENCRYPTED_RDB_DATABASE_NAME);
    rdbConfig.SetEncryptStatus(true);
    rdbConfig.SetBundleName("");
    EncryptOpenCallback helperTest;
    int errorCode;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_EQ(store11, nullptr);

    result = resSet->GetColumnIndex("nametest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetString(colIndex, strValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ("gdbdbg", strValue);

    result = resSet->GetColumnIndex("age", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(18, intValue);

    result = resSet->GetColumnIndex("salaryTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetDouble(colIndex, dValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, dValue);
}

/**
 * @tc.nametest: RdbStore_Encrypt_Decrypt_Test_006
 * @tc.desc: test SaveSecretKeyToFile when KeyFileType isNot PUB_KEY_FILE
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Encrypt_06Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::ENCRYPTED_RDB_DATABASE_NAME);
    rdbConfig.SetEncryptStatus(true);
    rdbConfig.SetBundleName("com.example.Encrypt6");
    EncryptOpenCallback helperTest;
    int errorCode;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);
    bool result =
        RdbSecurManager::GetInstance().CheckKeyDataFileExists(RdbSecurManager::KeyFileType::PUB_KEY_BAK);
    ASSERT_EQ(result, false);
    std::vector<uint8_t> kk = RdbSecurManager::GetInstance().GenerateRandomNum(RdbSecurManager::RDB_KEY_SIZE);
    bool flag =
        RdbSecurManager::GetInstance().SaveSecretKeyToFile(RdbSecurManager::KeyFileType::PUB_KEY_BAK, kk);
    ASSERT_EQ(flag, true);
}

/**
 * @tc.nametest: RdbStore_Encrypt_Decrypt_Test_007
 * @tc.desc: test GetRdbPassword when KeyFileType isNot PUB_KEY_FILE
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Encrypt_07Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::ENCRYPTED_RDB_DATABASE_NAME);
    rdbConfig.SetEncryptStatus(true);
    rdbConfig.SetBundleName("com.example.Encrypt7");
    EncryptOpenCallback helperTest;
    int errorCode;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);
    auto kk = RdbSecurManager::GetInstance().GetRdbPassword(RdbSecurManager::KeyFileType::PUB_KEY_BAK);
    RdbPassword password = {};
    ASSERT_EQ(kk, password);
}

/**
 * @tc.nametest: RdbStore_Encrypt_Decrypt_Test_008
 * @tc.desc: test RemoveSuffix when pos == std::string::npos
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Encrypt_08Virtual, TestSize.Level1)
{
    std::string path = RDB_UNITTEST_PATH + "test";
    RdbStoreConfig rdbConfig(path);
    rdbConfig.SetEncryptStatus(true);
    rdbConfig.SetBundleName("com.example.Encrypt8");
    EncryptOpenCallback helperTest;
    int errorCode;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);
}

/**
 * @tc.nametest: RdbStore_Encrypt_Decrypt_Test_009
 * @tc.desc: test GetKeyDistributedStatus and SetKeyDistributedStatus
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Encrypt_09Virtual, TestSize.Level1)
{
    RdbStoreConfig rdbConfig(RdbStoreUnittest::ENCRYPTED_RDB_DATABASE_NAME);
    rdbConfig.SetEncryptStatus(true);
    rdbConfig.SetBundleName("com.example.Encrypt9");
    EncryptOpenCallback helperTest;
    int errorCode;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);

    bool dbStatus = false;
    int result = RdbSecurManager::GetInstance().GetKeyDistributedStatus(
        RdbSecurManager::KeyFileType::PUB_KEY_FILE, dbStatus);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(dbStatus, false);
    result = RdbSecurManager::GetInstance().GetKeyDistributedStatus(
        RdbSecurManager::KeyFileType::PUB_KEY_BAK, dbStatus);
    ASSERT_EQ(result, E_ERROR);
    ASSERT_EQ(dbStatus, false);
    result =
        RdbSecurManager::GetInstance().SetKeyDistributedStatus(RdbSecurManager::KeyFileType::PUB_KEY_FILE, true);
    ASSERT_EQ(result, E_OK);
    result = RdbSecurManager::GetInstance().GetKeyDistributedStatus(
        RdbSecurManager::KeyFileType::PUB_KEY_FILE, dbStatus);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(dbStatus, true);
    result = RdbSecurManager::GetInstance().SetKeyDistributedStatus(
        RdbSecurManager::KeyFileType::PUB_KEY_BAK, dbStatus);
    ASSERT_EQ(result, E_ERROR);
    int64_t countTest;
    result = store11->ExeAndGetLong(countTest, "SELECT COUNT(*) FROM test");
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(countTest, 3);
    result = store11->ExecuteSql("DELETE FROM test WHERE age = ? OR age = ?",
        std::vector<ValueObject>{ ValueObject(std::string("18")), ValueObject(std ::string("20")) });
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_Execute_001
 * @tc.desc: test RdbStoreTest Execute
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Execute_001Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;
    int64_t idTest;
    ValuesBucket valuesItem;
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);
    valuesItem.Clear();
    valuesItem.PutInt("idTest", 2);
    valuesItem.PutString("nametest", std::string("lisi"));
    valuesItem.PutInt("age", 19);
    valuesItem.PutDouble("salaryTest", 200.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);
    valuesItem.Clear();
    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("sfgbngrh"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(3, idTest);
    result = store11->ExeAndGetLong(countTest, "SELECT COUNT(*) FROM test where age = 19");
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(countTest, 1);
    result = store11->ExecuteSql("DELETE FROM test WHERE age = 19");
    ASSERT_EQ(result, E_OK);
    result = store11->ExeAndGetLong(countTest, "SELECT COUNT(*) FROM test");
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(countTest, 0);
}

/**
 * @tc.nametest: RdbStore_Execute_002
 * @tc.desc: test RdbStoreTest Execute
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Execute_002Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;
    int64_t idTest;
    ValuesBucket valuesItem;
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 2);
    valuesItem.PutString("nametest", std::string("lisi"));
    valuesItem.PutInt("age", 19);
    valuesItem.PutDouble("salaryTest", 200.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(2, idTest);
    valuesItem.Clear();
    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("sfgbngrh"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(3, idTest);
    int64_t countTest;
    result = store11->ExeAndGetLong(countTest, "SELECT COUNT(*) FROM test", std::vector<ValueObject>());
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(countTest, 3);
    result = store11->ExecuteSql("DELETE FROM test WHERE age = ? OR age = ?",
        std::vector<ValueObject>{ ValueObject(std::string("18")), ValueObject(std ::string("20")) });
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_Execute_003
 * @tc.desc: test RdbStoreTest Execute
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Execute_003Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t pageSizeTest;
    int result = store11->ExeAndGetLong(pageSizeTest, "PRAGMA page_size");
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(pageSizeTest, 4096);
    std::string journalMode;
    result = store11->ExecuteAndGetString(journalMode, "PRAGMA journal_mode");
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(journalMode, "wal");
    result = store11->ExeAndGetLong(
        countTest, "SELECT COUNT(*) FROM where age = ?", std::vector<ValueObject>{ ValueObject(std::string("19")) });
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(countTest, 1);
    result = store11->ExecuteSql("DELETE FROM test WHERE age = 19");
    ASSERT_EQ(result, E_OK);
    result = store11->ExeAndGetLong(countTest, "SELECT COUNT(*) FROM test", std::vector<ValueObject>());
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(countTest, 0);
    result = store11->ExecuteSql("DROP TABLE IF EXISTS test");
    ASSERT_EQ(result, E_OK);
    result = store11->ExeAndGetLong(countTest, "SELECT COUNT(*) FROM test");
    ASSERT_EQ(result, -1);
}

/**
 * @tc.nametest: RdbStore_Insert_001
 * @tc.desc: test RdbStoreTest insert
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Insert_001Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t idTest;
    ValuesBucket valuesItem;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 2);
    valuesItem.PutString("nametest", std::string("lisi"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("lisi"));
    valuesItem.PutInt("age", 20L);
    valuesItem.PutDouble("salaryTest", 100.5f);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(3, idTest);

    RdbStoreUnittest::CheckResultSetTest(store11);
}

void RdbStoreUnittest::CheckResultSetTest(std::shared_ptr<RdbStoreTest> &store11)
{
    std::unique_ptr<ResultSet> resSet =
        store11->QuerySql("SELECT * FROM test WHERE nametest = ?", std::vector<std::string>{ "gdbdbg" });
    ASSERT_NE(resSet, nullptr);

    int colIndex;
    int intValue;
    std::string strValue;
    ColumnTypeTest colType;
    int pos;
    int result = resSet->GetRowIndex(pos);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(pos, -1);

    result = resSet->GetColumnType(0, colType);
    ASSERT_EQ(result, E_INVALID_STATEMENT);
    result = resSet->GoToFirstRow();
    ASSERT_EQ(result, E_OK);
    result = resSet->GetColumnIndex("idTest", colIndex);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(colIndex, 0);
    result = resSet->GetColumnType(colIndex, colType);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(colType, ColumnTypeTest::TYPE_INTEGER);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, intValue);

    result = resSet->GetColumnIndex("nametest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetColumnType(colIndex, colType);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(colType, ColumnTypeTest::TYPE_STRING);
    result = resSet->GetString(colIndex, strValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ("gdbdbg", strValue);
}

void RdbStoreUnittest::CheckAgeTest(std::unique_ptr<ResultSet> &resSet)
{
    int colIndex;
    int intValue;
    ColumnTypeTest colType;
    int result = resSet->GetColumnIndex("age", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetColumnType(colIndex, colType);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(colType, ColumnTypeTest::TYPE_INTEGER);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, intValue);

    RdbStoreUnittest::CheckAgeTest(resSet);
    RdbStoreUnittest::CheckSalaryTest(resSet);
    RdbStoreUnittest::CheckBlobTest(resSet);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ERROR);

    result = resSet->GetColumnType(colIndex, colType);
    ASSERT_EQ(result, E_INVALID_STATEMENT);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

void RdbStoreUnittest::CheckSalaryTest(std::unique_ptr<ResultSet> &resSet)
{
    int colIndex;
    double dValue;
    ColumnTypeTest colType;
    int result = resSet->GetColumnIndex("salaryTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetColumnType(colIndex, colType);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(colType, ColumnTypeTest::TYPE_FLOAT);
    result = resSet->GetDouble(colIndex, dValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, dValue);
}

void RdbStoreUnittest::CheckBlobTest(std::unique_ptr<ResultSet> &resSet)
{
    int colIndex;
    std::vector<uint8_t> bb;
    ColumnTypeTest colType;
    int result = resSet->GetColumnIndex("blobType", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetColumnType(colIndex, colType);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(colType, ColumnTypeTest::TYPE_BLOB);
    result = resSet->GetBlob(colIndex, bb);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, static_cast<int>(bb.size()));
    ASSERT_EQ(1, bb[0]);
    ASSERT_EQ(1, bb[1]);
    ASSERT_EQ(1, bb[1]);
    result = resSet->GetColumnIndex("salaryTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetDouble(colIndex, dValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, dValue);

    result = resSet->GetColumnIndex("blobType", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetBlob(colIndex, bb);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, static_cast<int>(bb.size()));
    ASSERT_EQ(1, bb[0]);
    ASSERT_EQ(1, bb[1]);
    ASSERT_EQ(1, bb[1]);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ERROR);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_Replace_001
 * @tc.desc: test RdbStoreTest replace
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Replace_001Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t idTest;
    ValuesBucket valuesItem;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->Replace(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    std::unique_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);

    int colIndex;
    int intValue;
    std::string strValue;
    double dValue;
    std::vector<uint8_t> bb;
    result = resSet->GetColumnIndex("idTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, intValue);

    result = resSet->GetColumnIndex("nametest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetString(colIndex, strValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ("gdbdbg", strValue);

    result = resSet->GetColumnIndex("age", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(18, intValue);
}

/**
 * @tc.nametest: RdbStore_Replace_002
 * @tc.desc: test RdbStoreTest replace
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_Replace_002Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t idTest;
    ValuesBucket valuesItem;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 200.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    result = store11->Replace(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    std::unique_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);

    int colIndex;
    int intValue;
    std::string strValue;
    double dValue;
    std::vector<uint8_t> bb;
}

/**
 * @tc.nametest: RdbStore_InsertWithConflictResolution_001_002
 * @tc.desc: test RdbStoreTest InsertConflictResolution
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_InsertWithConflictResolution_001_002Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t idTest;
    ValuesBucket valuesItem;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    int result = store11->InsertConflictResolution(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 200.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    result = store11->InsertConflictResolution(idTest, "test", valuesItem);
    ASSERT_EQ(result, RdbStoreUnittest::E_SQLITE_CONSTRAINT);

    result = resSet->GetColumnIndex("blobType", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetBlob(colIndex, bb);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(3, static_cast<int>(bb.size()));
    ASSERT_EQ(1, bb[0]);
    ASSERT_EQ(2, bb[1]);
    ASSERT_EQ(3, bb[2]);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ERROR);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_InsertWithConflictResolution_003_004
 * @tc.desc: test RdbStoreTest InsertConflictResolution
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_InsertWithConflictResolution_003_004Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t idTest;
    ValuesBucket valuesItem;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->InsertConflictResolution(idTest, "test", valuesItem, ConfRes::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 200.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    result = store11->InsertConflictResolution(idTest, "test", valuesItem, ConfRes::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result, RdbStoreUnittest::E_SQLITE_CONSTRAINT);
}

/**
 * @tc.nametest: RdbStore_InsertWithConflictResolution_005
 * @tc.desc: test RdbStoreTest InsertConflictResolution
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_InsertWithConflictResolution_005Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t idTest;
    ValuesBucket valuesItem;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->InsertConflictResolution(idTest, "test", valuesItem, ConfRes::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 200.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    result = store11->InsertConflictResolution(idTest, "test", valuesItem, ConfRes::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(idTest, -1);
}

/**
 * @tc.nametest: RdbStore_InsertWithConflictResolution_006_007
 * @tc.desc: test RdbStoreTest InsertConflictResolution
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, RdbStore_InsertWithConflictResolution_006_007Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int64_t idTest;
    ValuesBucket valuesItem;

    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->InsertConflictResolution(idTest, "test", valuesItem, ConfRes::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 200.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    result = store11->InsertConflictResolution(idTest, "test", valuesItem, ConfRes::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(idTest, 1);

    std::unique_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);

    int colIndex;
    int intValue;
    std::string strValue;
    double dValue;
    std::vector<uint8_t> bb;
}

/**
 * @tc.nametest: RdbStore_BatchInsert_001
 * @tc.desc: test RdbStoreTest BatchInsert
 * @tc.type: FUNC
 * @tc.require: issueI5GZGX
 */
HWTEST_F(RdbStoreUnittest, RdbStore_BatchInsert_001Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    ValuesBucket valuesItem;

    valuesItem.PutString("nametest", "gdbdbg");
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 100; i++) {
        valuesBuckets.push_back(valuesItem);
    }
    int64_t insertNum = 0;
    int result = store11->BatchInsert(insertNum, "test", valuesBuckets);
    ASSERT_EQ(E_OK, result);
    ASSERT_EQ(100, insertNum);
    std::unique_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    int rowCount = 0;
    resSet->GetRowCount(rowCount);
    ASSERT_EQ(100, rowCount);

    result = resSet->GetColumnIndex("blobType", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetBlob(colIndex, bb);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(3, static_cast<int>(bb.size()));
    ASSERT_EQ(4, bb[0]);
    ASSERT_EQ(5, bb[1]);
    ASSERT_EQ(6, bb[2]);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ERROR);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: ValueObject_TEST_001
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, ValueObject_TEST_001Virtual, TestSize.Level1)
{
    ValueObject obj = ValueObject();
    ValueObjectType type = obj.GetType();
    ASSERT_EQ(type, ValueObjectType::TYPE_NULL);

    result = resSet->GetColumnIndex("idTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, intValue);

    result = resSet->GetColumnIndex("nametest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetString(colIndex, strValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ("gdbdbg", strValue);

    result = resSet->GetColumnIndex("age", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(18, intValue);

    result = resSet->GetColumnIndex("salaryTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetDouble(colIndex, dValue);
}

/**
 * @tc.nametest: ValueObject_TEST_002
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, ValueObject_TEST_002Virtual, TestSize.Level1)
{
    int inputValue = 5;
    int outputValue = 0;
    ValueObject obj = ValueObject(inputValue);
    ValueObjectType type = obj.GetType();
    ASSERT_EQ(type, ValueObjectType::TYPE_INT);
    int result = obj.GetInt(outputValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(outputValue, 5);

    result = resSet->GetColumnIndex("idTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, intValue);

    result = resSet->GetColumnIndex("nametest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetString(colIndex, strValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ("gdbdbg", strValue);

    result = resSet->GetColumnIndex("age", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetInt(colIndex, intValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(18, intValue);

    result = resSet->GetColumnIndex("salaryTest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetDouble(colIndex, dValue);
}

/**
 * @tc.nametest: ValueObject_TEST_003
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, ValueObject_TEST_003Virtual, TestSize.Level1)
{
    bool inputValue = true;
    bool outputValue = false;
    ValueObject obj = ValueObject(inputValue);
    ValueObjectType type = obj.GetType();
    ASSERT_EQ(type, ValueObjectType::TYPE_BOOL);
    int result = obj.GetBool(outputValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(outputValue, true);
}

/**
 * @tc.nametest: ValueObject_TEST_004
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, ValueObject_TEST_004Virtual, TestSize.Level1)
{
    std::string inputValue = "hello";
    std::string outputValue = "";
    ValueObject obj = ValueObject(inputValue);
    ValueObjectType type = obj.GetType();
    ASSERT_EQ(type, ValueObjectType::TYPE_STRING);
    int result = obj.GetString(outputValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(outputValue, "hello");
}

/**
 * @tc.nametest: ValueObject_TEST_005
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, ValueObject_TEST_005Virtual, TestSize.Level1)
{
    std::vector<uint8_t> inputValue = { 'h', 'e', 'l', 'l', 'o' };
    std::vector<uint8_t> outputValue;
    ValueObject obj = ValueObject(inputValue);
    ValueObjectType type = obj.GetType();
    ASSERT_EQ(type, ValueObjectType::TYPE_BLOB);
    int result = obj.GetBlob(outputValue);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(static_cast<int>(outputValue.size()), 5);
    ASSERT_EQ(outputValue[0], 'h');
    ASSERT_EQ(outputValue[1], 'e');
    ASSERT_EQ(outputValue[2], 'l');
    ASSERT_EQ(outputValue[3], 'l');
    ASSERT_EQ(outputValue[4], 'o');
}

/**
 * @tc.nametest: ValueObject_TEST_006
 * @tc.desc: test ValueObject
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, ValueObject_TEST_006Virtual, TestSize.Level1)
{
    int inputValue = 5;
    ValueObject obj = ValueObject(inputValue);
    ValueObject object = ValueObject();
    object = obj;
    ValueObjectType type = object.GetType();
    ASSERT_EQ(type, ValueObjectType::TYPE_INT);
}

/**
 * @tc.nametest: ValuesBucket_001
 * @tc.desc: test ValuesBucket
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, ValuesBucket_001Virtual, TestSize.Level1)
{
    ValuesBucket valuesItem;
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutNull("nametest");
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    int size = valuesItem.Size();
    ASSERT_EQ(size, 5);
    bool items = valuesItem.HasColumn("nametest");
    ASSERT_EQ(items, true);
    ValueObject obj;
    items = valuesItem.GetObject("salaryTest", obj);
    double val = 0.0;
    ValueObjectType type = obj.GetType();
    ASSERT_EQ(type, ValueObjectType::TYPE_DOUBLE);
    int result = obj.GetDouble(val);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(val, 1);

    valuesItem.Delete("nametest");
    size = valuesItem.Size();
    ASSERT_EQ(size, 4);
    items = valuesItem.HasColumn("nametest");
    ASSERT_EQ(items, false);

    valuesItem.Clear();
    size = valuesItem.Size();
    ASSERT_EQ(size, 0);
    items = valuesItem.HasColumn("salaryTest");
    ASSERT_EQ(items, false);
}

/**
 * @tc.nametest: ValuesBucket_002
 * @tc.desc: test ValuesBucket
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, ValuesBucket_002Virtual, TestSize.Level1)
{
    int errorCode = E_OK;
    const std::string dbPath = RDB_UNITTEST_PATH + "InterfaceTest.db";
    RdbStoreConfig rdbConfig(dbPath);
    MyOpenCallback helperTest;
    std::shared_ptr<RdbStoreTest> store11 = RdbHelper::GetRdbStore(rdbConfig, 1, helperTest, errorCode);
    ASSERT_NE(store11, nullptr);
    ASSERT_EQ(errorCode, E_OK);

    int64_t idTest;
    ValuesBucket valuesItem;
    valuesItem.PutInt("idTest", 1);
    valuesItem.PutNull("nametest");
    valuesItem.PutInt("age", 18);
    valuesItem.PutDouble("salaryTest", 1);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int result = store11->Insert(idTest, "test", valuesItem);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);
    std::unique_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    int colIndex;
    std::string strValue;

    result = resSet->GoToFirstRow();
    ASSERT_EQ(result, E_OK);
    result = resSet->GetColumnIndex("nametest", colIndex);
    ASSERT_EQ(result, E_OK);
    result = resSet->GetString(colIndex, strValue);
    ASSERT_EQ(result, E_OK);

    resSet->Close();
    resSet = nullptr;
    store11 = nullptr;
    result = RdbHelper::DeleteRdb(dbPath);
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: ValuesBucket_003
 * @tc.desc: test ValuesBucket
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author:
 */
HWTEST_F(RdbStoreUnittest, ValuesBucket_003Virtual, TestSize.Level1)
{
    ValuesBucket valuesItem;
    valuesItem.PutBool("boolType", true);
    valuesItem.PutLong("longType", 1);

    int size = valuesItem.Size();
    ASSERT_EQ(size, 2);
    bool items = valuesItem.HasColumn("boolType");
    ASSERT_EQ(items, true);
    ValueObject obj;
    items = valuesItem.GetObject("boolType", obj);
    ValueObjectType type = obj.GetType();
    ASSERT_EQ(type, ValueObjectType::TYPE_BOOL);
    bool val1 = false;
    int result = obj.GetBool(val1);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(val1, true);

    items = valuesItem.HasColumn("longType");
    ASSERT_EQ(items, true);
    items = valuesItem.GetObject("longType", obj);
    type = obj.GetType();
    ASSERT_EQ(type, ValueObjectType::TYPE_INT64);
    int64_t val2 = 0;
    result = obj.GetLong(val2);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(val2, 1);
}

/**
 * @tc.nametest: RdbStore_UpdateWithConflictResolution_001
 * @tc.desc: test RdbStoreTest UpdateConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUnittest, RdbStore_UpdateWithConflictResolution_001Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    ValuesBucket valuesItem;
    int changedRowsTest;
    int64_t idTest;

    int result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);

    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("xiaowang"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    result = store11->UpdateConflictResolution(changedRowsTest, "test", valuesItem, "age = 19");
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, changedRowsTest);

    std::shared_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 1, "gdbdbg", 18, 1, std::vector<uint8_t>{ 1, 2, 3 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 3, "xiaowang", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ROW_OUT_RANGE);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_UpdateWithConflictResolution_002
 * @tc.desc: test RdbStoreTest UpdateConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUnittest, RdbStore_UpdateWithConflictResolution_002Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    ValuesBucket valuesItem;
    int changedRowsTest;
    int64_t idTest;

    int result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);

    // update lisi age=19 to gdbdbg age=20
    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    result = store11->UpdateConflictResolution(changedRowsTest, "test", std::vector<std::string>{ "19" },
        ConfRes::ON_CONFLICT_NO);
    ASSERT_EQ(result, E_SQLITE_CONSTRAINT);

    std::shared_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 1, "gdbdbg", 18, 1, std::vector<uint8_t>{ 1, 2, 3 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ROW_OUT_RANGE);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_UpdateWithConflictResolution_003
 * @tc.desc: test RdbStoreTest UpdateConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUnittest, RdbStore_UpdateWithConflictResolution_003Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    ValuesBucket valuesItem;
    int changedRowsTest;
    int64_t idTest;

    int result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);

    // update lisi age=19 to xiaowang age=20
    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("xiaowang"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    result = store11->UpdateConflictResolution(
        changedRowsTest, "test", valuesItem, "age = ?", std::vector<std::string>{ "19" },
        ConfRes::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, changedRowsTest);

    std::shared_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 1, "gdbdbg", 18, 1, std::vector<uint8_t>{ 1, 2, 3 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 3, "xiaowang", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ROW_OUT_RANGE);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_UpdateWithConflictResolution_004
 * @tc.desc: test RdbStoreTest UpdateConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUnittest, RdbStore_UpdateWithConflictResolution_004Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    ValuesBucket valuesItem;
    int changedRowsTest;
    int64_t idTest;

    int result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);

    // update lisi age=19 to gdbdbg age=20
    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    result = store11->UpdateConflictResolution(changedRowsTest, "test", std::vector<std::string>{ "19" },
        ConfRes::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result, E_SQLITE_CONSTRAINT);

    std::shared_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 1, "gdbdbg", 18, 1, std::vector<uint8_t>{ 1, 2, 3 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ROW_OUT_RANGE);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_UpdateWithConflictResolution_005
 * @tc.desc: test RdbStoreTest UpdateConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUnittest, RdbStore_UpdateWithConflictResolution_005Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    ValuesBucket valuesItem;
    int changedRowsTest;
    int64_t idTest;

    int result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);

    // update lisi age=19 to xiaowang age=20
    valuesItem.PutInt("idTest", 3);
    valuesItem.PutString("nametest", std::string("xiaowang"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    valuesItem.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    result = store11->UpdateConflictResolution(changedRowsTest, "test", std::vector<std::string>{ "19" },
        ConfRes::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, changedRowsTest);

    std::shared_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 1, "gdbdbg", 18, 1, std::vector<uint8_t>{ 1, 2, 3 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);
    RdbStoreUnittest::ExpectValue(resSet, RowData{ 3, "xiaowang", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ROW_OUT_RANGE);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_UpdateWithConflictResolution_006
 * @tc.desc: test RdbStoreTest UpdateConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUnittest, RdbStore_UpdateWithConflictResolution_006Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    ValuesBucket valuesItem;
    int changedRowsTest;
    int64_t idTest;

    int result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(2, idTest);

    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);
    result = store11->UpdateConflictResolution(changedRowsTest, "test", std::vector<std::string>{ "19" },
        ConfRes::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(changedRowsTest, 1);

    std::shared_ptr<ResultSet> resSet = store11->QuerySql("SELECT * FROM test");
    ASSERT_NE(resSet, nullptr);

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_OK);

    RdbStoreUnittest::ExpectValue(resSet, RowData{ 2, "gdbdbg", 20, 300.5, std::vector<uint8_t>{ 4, 5, 6 } });

    result = resSet->GoToNextRow();
    ASSERT_EQ(result, E_ROW_OUT_RANGE);

    result = resSet->Close();
    ASSERT_EQ(result, E_OK);
}

/**
 * @tc.nametest: RdbStore_UpdateWithConflictResolution_007
 * @tc.desc: test RdbStoreTest UpdateConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUnittest, RdbStore_UpdateWithConflictResolution_007Virtual, TestSize.Level1)
{
    std::shared_ptr<RdbStoreTest> &store11 = RdbStoreUnittest::store11;

    int changedRowsTest;
    int64_t idTest;
    ValuesBucket valuesItem;

    int result = store11->Insert(idTest, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result, E_OK);
    ASSERT_EQ(1, idTest);

    valuesItem.PutInt("idTest", 2);
    valuesItem.PutInt("age", 19);
    result = store11->UpdateConflictResolution(
        changedRowsTest, "test", valuesItem, "age = ?", std::vector<std::string>{ "18" }, static_cast<ConfRes>(6));
    ASSERT_EQ(E_INVALID_CONFLICT_FLAG, result);
    ASSERT_EQ(0, changedRowsTest);

    valuesItem.Clear();
    valuesItem.PutInt("idTest", 2);
    valuesItem.PutInt("age", 19);
    result = store11->UpdateConflictResolution(
        changedRowsTest, "test", valuesItem, "age = ?", std::vector<std::string>{ "18" }, static_cast<ConfRes>(-1));
    ASSERT_EQ(E_INVALID_CONFLICT_FLAG, result);
    ASSERT_EQ(0, changedRowsTest);
}

/**
 * @tc.nametest: RdbStore_UpdateSqlBuilder_001
 * @tc.desc: test RdbStoreTest UpdateSqlBuilder
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUnittest, RdbStore_UpdateSqlBuilder_001Virtual, TestSize.Level1)
{
    ValuesBucket valuesItem;
    valuesItem.PutString("nametest", std::string("gdbdbg"));
    valuesItem.PutInt("age", 20);
    valuesItem.PutDouble("salaryTest", 300.5);

    std::vector<ValueObject> bindArg;

    updateSql = SqliteSqlBuilder::BuildUpdateString(valuesItem, "test", std::vector<std::string>{}, "", "", "", "",
        INT_MIN, INT_MIN, bindArg, ConfRes::ON_CONFLICT_NO);
    ASSERT_EQ(updateSql, "UPDATE test SET age=?,nametest=?,salaryTest=?");
}

void RdbStoreUnittest::ExpectValue(const std::shared_ptr<OHOS::NativeRdb::ResultSet> &resSet, const RowData &expect)
{
    ASSERT_NE(nullptr, resSet);
    int colIndex;
    int intValue;
    int result;

    if (expect.idTest != -1) {
        result = resSet->GetColumnIndex("idTest", colIndex);
        ASSERT_EQ(result, E_OK);
        result = resSet->GetInt(colIndex, intValue);
        ASSERT_EQ(result, E_OK);
        ASSERT_EQ(expect.idTest, intValue);
    }
    if (expect.nametest != "") {
        std::string strValue;
        result = resSet->GetColumnIndex("nametest", colIndex);
        ASSERT_EQ(result, E_OK);
        result = resSet->GetString(colIndex, strValue);
        ASSERT_EQ(result, E_OK);
        ASSERT_EQ(expect.nametest, strValue);
    }
    if (expect.age != -1) {
        result = resSet->GetColumnIndex("age", colIndex);
        ASSERT_EQ(result, E_OK);
        result = resSet->GetInt(colIndex, intValue);
        ASSERT_EQ(result, E_OK);
        ASSERT_EQ(expect.age, intValue);
    }
    if (expect.salaryTest != -1) {
        double dValue;
        result = resSet->GetColumnIndex("salaryTest", colIndex);
        ASSERT_EQ(result, E_OK);
        result = resSet->GetDouble(colIndex, dValue);
        ASSERT_EQ(result, E_OK);
        ASSERT_EQ(expect.salaryTest, dValue);
    }
    if (expect.blobType.size() != 0) {
        std::vector<uint8_t> bb;
        result = resSet->GetColumnIndex("blobType", colIndex);
        ASSERT_EQ(result, E_OK);
        result = resSet->GetBlob(colIndex, bb);
        ASSERT_EQ(result, E_OK);
        ASSERT_EQ(expect.blobType.size(), static_cast<int>(bb.size()));
        for (int i = 0; i < expect.blobType.size(); i++) {
            ASSERT_EQ(expect.blobType[i], bb[i]);
        }
    }
}
