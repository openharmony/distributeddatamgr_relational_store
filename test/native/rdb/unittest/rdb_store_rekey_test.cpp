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

#define LOG_TAG "RdbRekeyTest"
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <securec.h>

#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include "block_data.h"
#include "common.h"
#include "file_ex.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_security_manager.h"
#include "sqlite_connection.h"
#include "sqlite_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;
class RdbRekeyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static std::string RemoveSuffix(const std::string &name);
    static std::chrono::system_clock::time_point GetKeyFileDate(const std::string &dbName);
    static bool ChangeKeyFileDate(const std::string &dbName, int rep);
    static bool SaveNewKey(const std::string &dbName);
    static RdbStoreConfig GetRdbConfig(const std::string &name);
    static RdbStoreConfig GetRdbNotRekeyConfig(const std::string &name);
    static void InsertData(std::shared_ptr<RdbStore> &store);
    static void CheckQueryData(std::shared_ptr<RdbStore> &store);

    static const std::string encryptedDatabaseName;
    static const std::string encryptedDatabasePath;
    static const std::string encryptedDatabaseKeyDir;
    static const std::string encryptedDatabaseMockName;
    static const std::string encryptedDatabaseMockPath;
    static constexpr int HOURS_EXPIRED = (24 * 365) + 1;
    static constexpr int HOURS_LONG_LONG_AGO = 30 * (24 * 365);
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

void RdbRekeyTest::SetUpTestCase()
{
}

void RdbRekeyTest::TearDownTestCase()
{
}

void RdbRekeyTest::SetUp()
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbRekeyTest::encryptedDatabasePath);
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
    auto keyPath = RDB_TEST_PATH + "key/" + name + ".pub_key_v2";
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
    auto keyPath = RDB_TEST_PATH + "key/" + name + ".pub_key_v2";
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

bool RdbRekeyTest::SaveNewKey(const string &dbName)
{
    std::string name = RemoveSuffix(dbName);
    auto keyPath = RDB_TEST_PATH + "key/" + name + ".pub_key_v2";
    auto newKeyPath = RDB_TEST_PATH + "key/" + name + ".pub_key_v2.new";
    if (!OHOS::FileExists(keyPath)) {
        return false;
    }
    std::vector<char> content;
    auto loaded = OHOS::LoadBufferFromFile(keyPath, content);
    if (!loaded) {
        return false;
    }
    OHOS::SaveBufferToFile(newKeyPath, content);
    content[content.size() - 1] = 'E';
    return OHOS::SaveBufferToFile(keyPath, content);
}

RdbStoreConfig RdbRekeyTest::GetRdbConfig(const std::string &name)
{
    RdbStoreConfig config(name);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.test_rekey");
    config.EnableRekey(true);
    return config;
}

RdbStoreConfig RdbRekeyTest::GetRdbNotRekeyConfig(const std::string &name)
{
    RdbStoreConfig config(name);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.test_rekey");
    config.EnableRekey(false);
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
* @tc.name: Rdb_Rekey_Test_003
* @tc.desc: try to open store and execute RekeyRecover() without key and new key files.
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_03, TestSize.Level1)
{
    std::string keyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key_v2";
    std::string newKeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key_v2.new";

    bool isFileExists = OHOS::FileExists(keyPath);
    ASSERT_TRUE(isFileExists);

    SqliteUtils::DeleteFile(keyPath);
    isFileExists = OHOS::FileExists(keyPath);
    ASSERT_FALSE(isFileExists);
    isFileExists = OHOS::FileExists(newKeyPath);
    ASSERT_FALSE(isFileExists);

    RekeyTestOpenCallback helper;
    int errCode = E_OK;
    RdbStoreConfig config = GetRdbConfig(encryptedDatabasePath);
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
}


/**
* @tc.name: Rdb_Rekey_033
* @tc.desc: test transaction rekey
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_033, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetAllowRebuild(false);
    config.SetEncryptStatus(true);
    RdbStoreConfig::CryptoParam cryptoParam;
    config.SetCryptoParam(cryptoParam);
    config.SetBundleName("com.example.test_rekey");
    RekeyTestOpenCallback helper;
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(config);
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    store->ExecuteSql("CREATE TABLE IF NOT EXISTS test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)");

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(1, result.second);

    std::string keyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPath);
    ASSERT_TRUE(isFileExists);

    RdbStoreConfig::CryptoParam newCryptoParam;
    errCode = store->RekeyEx(newCryptoParam);
    ASSERT_EQ(errCode, E_SQLITE_BUSY);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(2, result.second);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 2);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 2);

    RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: Rdb_Rekey_034
* @tc.desc: readOnly rekey test
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_034, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    config.SetEncryptStatus(true);
    config.SetReadOnly(true);
    config.SetBundleName("com.example.test_rekey");
    RekeyTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam cryptoParam1;

    errCode = store->RekeyEx(cryptoParam1);
    ASSERT_EQ(errCode, E_NOT_SUPPORT);

    int ret = RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: Rdb_Rekey_035
* @tc.desc: mutltiThread rekey test
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_035, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    config.SetBundleName("com.example.test_rekey");
    config.SetEncryptStatus(true);
    RekeyTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    auto blockResult = std::make_shared<OHOS::BlockData<bool>>(3, false);
    std::thread thread([store, blockResult]() {
        RdbStoreConfig::CryptoParam cryptoParam;
        cryptoParam.encryptKey_ = std::vector<uint8_t>{ 6, 2, 3, 4, 5, 1 };
        int ret1 = store->RekeyEx(cryptoParam);
        LOG_INFO("Rdb_Rekey_035 thread Rekey finish, code:%{public}d", ret1);
        blockResult->SetValue(true);
    });
    thread.detach();
    RdbStoreConfig::CryptoParam cryptoParam2;
    cryptoParam2.encryptKey_ = std::vector<uint8_t>{ 6, 5, 3, 4, 2, 1 };
    int ret2 = store->RekeyEx(cryptoParam2);
    LOG_INFO("Rdb_Rekey_035 main Rekey finish, code:%{public}d", ret2);
    EXPECT_TRUE(blockResult->GetValue());

    store->ExecuteSql("CREATE TABLE IF NOT EXISTS test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)");

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan1"));
    values.PutInt("age", 50);
    values.PutDouble("salary", 263);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3, 4, 5 });
    int ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    int changedRows;
    values.Clear();
    values.PutInt("age", 30);
    ret = store->Update(changedRows, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
}

/**
* @tc.name: Rdb_Rekey_036
* @tc.desc: invalid param test
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_036, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.test_rekey");
    RekeyTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam cryptoParam1;
    cryptoParam1.encryptAlgo = -1;
    cryptoParam1.hmacAlgo = -1;
    cryptoParam1.kdfAlgo = -1;
    errCode = store->RekeyEx(cryptoParam1);
    ASSERT_EQ(errCode, E_INVALID_ARGS_NEW);
    auto conn = std::make_shared<SqliteConnection>(config, false);
    auto codecConfig = conn->ConvertCryptoParamToCodecConfig(cryptoParam1);
    EXPECT_EQ(codecConfig.pCipher, nullptr);
    EXPECT_EQ(codecConfig.pHmacAlgo, nullptr);
    EXPECT_EQ(codecConfig.pKdfAlgo, nullptr);
    cryptoParam1.encryptAlgo = 4;
    cryptoParam1.hmacAlgo = 4;
    cryptoParam1.kdfAlgo = 4;
    codecConfig = conn->ConvertCryptoParamToCodecConfig(cryptoParam1);
    EXPECT_EQ(codecConfig.pCipher, nullptr);
    EXPECT_EQ(codecConfig.pHmacAlgo, nullptr);
    EXPECT_EQ(codecConfig.pKdfAlgo, nullptr);
}

/**
* @tc.name: Rdb_Rekey_037
* @tc.desc: memory rekey test
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_037, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    config.SetBundleName("com.example.test_rekey");
    config.SetName("RekeyEx_Memmory_test.db");
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RekeyTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam cryptoParam1;

    errCode = store->RekeyEx(cryptoParam1);
    ASSERT_EQ(errCode, E_NOT_SUPPORT);

    int ret = RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: Rdb_Rekey_038
* @tc.desc: replica rekey test
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_038, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetBundleName("com.example.test_rekey");
    RekeyTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam cryptoParam1;

    errCode = store->RekeyEx(cryptoParam1);
    ASSERT_EQ(errCode, E_NOT_SUPPORT);

    int ret = RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: Rdb_Rekey_039
* @tc.desc: open non-enctypted database with encryptAlgo is PLAIN_TEXT
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_039, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    int errCode = RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(errCode, E_OK);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptAlgo = EncryptAlgo::PLAIN_TEXT;
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.test_rekey");
    config.SetName("test_plain_test.db");
    config.SetCryptoParam(cryptoParam);
    RekeyTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    auto ret = config.IsEncrypt();
    ASSERT_EQ(ret, false);
}

/**
* @tc.name: Rdb_Rekey_040
* @tc.desc: open non-enctypted database with encryptAlgo is PLAIN_TEXT then rekeyex success and query success
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_040, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    int errCode = RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(errCode, E_OK);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptAlgo = EncryptAlgo::PLAIN_TEXT;
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.test_rekey");
    config.SetCryptoParam(cryptoParam);
    RekeyTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    store->ExecuteSql("CREATE TABLE IF NOT EXISTS test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "name TEXT NOT NULL, age INTEGER)");
    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);

    int ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptAlgo = EncryptAlgo::AES_256_CBC;
    newCryptoParam.iterNum = 500;
    newCryptoParam.hmacAlgo = HmacAlgo::SHA512;
    newCryptoParam.kdfAlgo = KdfAlgo::KDF_SHA512;
    newCryptoParam.cryptoPageSize = 2048;
    errCode = store->RekeyEx(newCryptoParam);
    ASSERT_EQ(errCode, E_OK);

    values.Clear();
    store = nullptr;
    config.SetCryptoParam(newCryptoParam);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
}

/**
* @tc.name: Rdb_Rekey_041
* @tc.desc: test cryptoParam is custom then rekey and query success
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_041, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    int errCode = RdbHelper::DeleteRdbStore(config);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetEncryptStatus(true);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    cryptoParam.encryptAlgo = EncryptAlgo::AES_256_CBC;
    cryptoParam.iterNum = 500;
    cryptoParam.hmacAlgo = HmacAlgo::SHA512;
    cryptoParam.kdfAlgo = KdfAlgo::KDF_SHA512;
    cryptoParam.cryptoPageSize = 2048;
    config.SetCryptoParam(cryptoParam);
    config.SetBundleName("com.example.test_rekey");
    RekeyTestOpenCallback helper;
    errCode = E_OK;

    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    store->ExecuteSql("CREATE TABLE IF NOT EXISTS test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "name TEXT NOT NULL, age INTEGER)");

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    int ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    RdbStoreConfig::CryptoParam newCryptoParam = cryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 6, 2, 3, 4, 5, 1 };
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_OK);

    store = nullptr;
    config.SetCryptoParam(newCryptoParam);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
}

/**
* @tc.name: Rdb_Rekey_042
* @tc.desc: test cryptoParam is custom then rekey and query success
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_042, TestSize.Level1)
{
    RdbStoreConfig config(RdbRekeyTest::encryptedDatabasePath);
    int errCode = RdbHelper::DeleteRdbStore(config);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetEncryptStatus(true);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6, 7, 8 };
    cryptoParam.encryptAlgo = EncryptAlgo::AES_256_GCM;
    cryptoParam.iterNum = 2000;
    cryptoParam.hmacAlgo = HmacAlgo::SHA1;
    cryptoParam.kdfAlgo = KdfAlgo::KDF_SHA256;
    cryptoParam.cryptoPageSize = 4096;
    config.SetCryptoParam(cryptoParam);
    config.SetBundleName("com.example.test_rekey");
    RekeyTestOpenCallback helper;
    errCode = E_OK;

    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    store->ExecuteSql("CREATE TABLE IF NOT EXISTS test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "name TEXT NOT NULL, age INTEGER)");

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    int ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    RdbStoreConfig::CryptoParam newCryptoParam = cryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 8, 7, 6, 2, 3, 4, 5, 1 };
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_OK);

    store = nullptr;
    config.SetCryptoParam(newCryptoParam);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
}