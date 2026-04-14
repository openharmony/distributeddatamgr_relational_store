/*
* Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define LOG_TAG "RdbRekeyVectorTest"
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include "block_data.h"
#include "common.h"
#include "file_ex.h"
#include "grd_api_manager.h"
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

class RdbRekeyVectorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static RdbStoreConfig GetVectorConfig(const std::string &name);
    static RdbStoreConfig GetVectorEncryptConfig(const std::string &name);
    static void InsertData(std::shared_ptr<RdbStore> &store);
    static void CheckQueryData(std::shared_ptr<RdbStore> &store);

    static const std::string vectorDatabaseName;
    static const std::string vectorDatabasePath;
};

const std::string RdbRekeyVectorTest::vectorDatabaseName = "vector_rekey.db";
const std::string RdbRekeyVectorTest::vectorDatabasePath = RDB_TEST_PATH + vectorDatabaseName;

class VectorRekeyOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string createTableTest;
};

std::string const VectorRekeyOpenCallback::createTableTest = "CREATE TABLE IF NOT EXISTS test "
                                                             "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                             "name TEXT NOT NULL, age INTEGER, "
                                                             "salary REAL);";

int VectorRekeyOpenCallback::OnCreate(RdbStore &store)
{
    auto res = store.Execute(createTableTest);
    return res.first;
}

int VectorRekeyOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbRekeyVectorTest::SetUpTestCase()
{
}

void RdbRekeyVectorTest::TearDownTestCase()
{
}

void RdbRekeyVectorTest::SetUp()
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbRekeyVectorTest::vectorDatabasePath);
}

void RdbRekeyVectorTest::TearDown()
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbRekeyVectorTest::vectorDatabasePath);
}

RdbStoreConfig RdbRekeyVectorTest::GetVectorConfig(const std::string &name)
{
    RdbStoreConfig config(name);
    config.SetIsVector(true);
    config.SetBundleName("com.example.test_vector_rekey");
    return config;
}

RdbStoreConfig RdbRekeyVectorTest::GetVectorEncryptConfig(const std::string &name)
{
    RdbStoreConfig config(name);
    config.SetIsVector(true);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.test_vector_rekey");
    return config;
}

void RdbRekeyVectorTest::InsertData(std::shared_ptr<RdbStore> &store)
{
    std::string sqlInsert = "INSERT INTO test VALUES(1, 'zhangsan', 18, 100.5);";
    auto res = store->Execute(sqlInsert.c_str(), {});
    EXPECT_EQ(res.first, E_OK);
}

void RdbRekeyVectorTest::CheckQueryData(std::shared_ptr<RdbStore> &store)
{
    auto resultSet = store->QueryByStep("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    EXPECT_NE(resultSet, nullptr);
    int result = resultSet->GoToFirstRow();
    EXPECT_EQ(result, E_OK);
    int columnIndex;
    std::string strVal;
    result = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(result, E_OK);
    result = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ("zhangsan", strVal);
    resultSet->Close();
}

/**
* @tc.name: Vector_Rekey_001
* @tc.desc: test rekey function is normal
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_001, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 6, 5, 4, 3, 2, 1 };
    newCryptoParam.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_OK);
    CheckQueryData(store);
}

/**
* @tc.name: Vector_Rekey_002
* @tc.desc: test rekey with empty crypto param
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_002, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.isVectorRekey = true;
    errCode = store->Rekey(cryptoParam);
    ASSERT_EQ(errCode, E_OK);
    CheckQueryData(store);
}

/**
* @tc.name: Vector_Rekey_003
* @tc.desc: test rekey on non-encrypted vector database
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_003, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorConfig(vectorDatabasePath);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    cryptoParam.isVectorRekey = true;
    errCode = store->Rekey(cryptoParam);
    ASSERT_EQ(errCode, E_NOT_SUPPORT);
}

/**
* @tc.name: Vector_Rekey_004
* @tc.desc: test rekey on readonly database
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_004, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    config.SetReadOnly(true);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.isVectorRekey = true;
    errCode = store->Rekey(cryptoParam);
    ASSERT_EQ(errCode, E_NOT_SUPPORT);
}

/**
* @tc.name: Vector_Rekey_005
* @tc.desc: test multpile consecutive rekey operations
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_005, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    RdbStoreConfig::CryptoParam newCryptoParam1;
    newCryptoParam1.encryptKey_ = std::vector<uint8_t>{ 2, 3, 4, 5, 6, 7 };
    newCryptoParam1.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam1);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam newCryptoParam2;
    newCryptoParam2.encryptKey_ = std::vector<uint8_t>{ 3, 4, 5, 6, 7, 8 };
    newCryptoParam2.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam2);
    ASSERT_EQ(errCode, E_OK);
    CheckQueryData(store);
}

/**
* @tc.name: Vector_Rekey_006
* @tc.desc: test reopen database with new key after rekey
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_006, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 6, 5, 4, 3, 2, 1 };
    newCryptoParam.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_OK);

    store = nullptr;
    RdbHelper::ClearCache();
    config.SetCryptoParam(newCryptoParam);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    CheckQueryData(store);
}

/**
* @tc.name: Vector_Rekey_007
* @tc.desc: test rekey with invalid crypto parameters
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_007, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam invalidParam;
    invalidParam.iterNum = -1;
    invalidParam.isVectorRekey = true;
    errCode = store->Rekey(invalidParam);
    ASSERT_EQ(errCode, E_INVALID_ARGS_NEW);
}

/**
* @tc.name: Vector_Rekey_008
* @tc.desc: test concurrent rekey operations
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_008, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    auto blockResult = std::make_shared<OHOS::BlockData<bool>>(3, false);
    std::atomic<int> successCount{ 0 };
    std::thread rekeyThread([store, blockResult, &successCount]() {
        RdbStoreConfig::CryptoParam param;
        param.encryptKey_ = std::vector<uint8_t>{ 6, 5, 4, 3, 2, 1 };
        param.isVectorRekey = true;
        int ret = store->Rekey(param);
        if (ret == E_OK) {
            successCount++;
        }
        LOG_INFO("Vector_Rekey_008 thread Rekey finish, code:%{public}d", ret);
        blockResult->SetValue(true);
    });
    rekeyThread.detach();

    RdbStoreConfig::CryptoParam mainParam;
    mainParam.encryptKey_ = std::vector<uint8_t>{ 6, 5, 3, 4, 2, 1 };
    mainParam.isVectorRekey = true;
    int ret = store->Rekey(mainParam);
    if (ret == E_OK) {
        successCount++;
    }
    LOG_INFO("Vector_Rekey_008 main Rekey finish, code:%{public}d", ret);
    EXPECT_TRUE(blockResult->GetValue());
    EXPECT_EQ(successCount.load(), 1);
}

/**
* @tc.name: Vector_Rekey_009
* @tc.desc: test concurrent open and rekey operations
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_009, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    auto blockResult = std::make_shared<OHOS::BlockData<bool>>(3, false);
    std::thread openThread([&config, &helper, blockResult]() {
        int err = E_OK;
        auto s = RdbHelper::GetRdbStore(config, 1, helper, err);
        LOG_INFO("Vector_Rekey_009 thread open finish, code:%{public}d", err);
        blockResult->SetValue(true);
    });
    openThread.detach();

    RdbStoreConfig::CryptoParam newParam;
    newParam.encryptKey_ = std::vector<uint8_t>{ 6, 5, 4, 3, 2, 1 };
    newParam.isVectorRekey = true;
    errCode = store->Rekey(newParam);
    LOG_INFO("Vector_Rekey_009 main Rekey finish, code:%{public}d", errCode);
    EXPECT_TRUE(blockResult->GetValue());
}

/**
* @tc.name: Vector_Rekey_010
* @tc.desc: test rekey with different key length
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_010, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6, 7, 8 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 8, 7, 6, 5, 4, 3, 2, 1 };
    newCryptoParam.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_OK);
    CheckQueryData(store);
}

/**
* @tc.name: Vector_Rekey_011
* @tc.desc: test rekey with same encryption key
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_011, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    newCryptoParam.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_OK);
    CheckQueryData(store);
}

/**
* @tc.name: Vector_Rekey_012
* @tc.desc: test rekey on vector database with isVector=false should return E_NOT_SUPPORT
*           Covers branch: (!isVector && config_.GetDBType() == DB_VECTOR) in rdb_store_impl.cpp
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_012, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 6, 5, 4, 3, 2, 1 };
    newCryptoParam.isVectorRekey = false;
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_NOT_SUPPORT);
}

/**
* @tc.name: Vector_Rekey_013
* @tc.desc: test rekey on memory vector database should return E_NOT_SUPPORT
*           Covers branch: isMemoryRdb_ in rdb_store_impl.cpp
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_013, TestSize.Level1)
{
    RdbStoreConfig config("");
    config.SetIsVector(true);
    config.SetEncryptStatus(true);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    config.SetBundleName("com.example.test_vector_rekey");
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr) {
        return;
    }
    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    newCryptoParam.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_NOT_SUPPORT);
}

/**
* @tc.name: Vector_Rekey_014
* @tc.desc: test rekey on vector database with empty key and non-custom-encrypted config
*           Covers branch: (config_.IsCustomEncryptParam() == cryptoParam.encryptKey_.empty())
*           in rdb_store_impl.cpp
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_014, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam emptyKeyParam;
    emptyKeyParam.isVectorRekey = true;
    errCode = store->Rekey(emptyKeyParam);
    ASSERT_EQ(errCode, E_NOT_SUPPORT);
}

/**
* @tc.name: Vector_Rekey_015
* @tc.desc: test rekey on non-custom-encrypted vector DB with explicit key should return E_NOT_SUPPORT
*           Covers branch: (config_.IsCustomEncryptParam() == cryptoParam.encryptKey_.empty()) == false
*           when store was NOT created with custom key but rekey provides a key
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_015, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    newCryptoParam.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_NOT_SUPPORT);
}

/**
* @tc.name: Vector_Rekey_016
* @tc.desc: test rekey on custom-encrypted vector DB with empty key (auto-generated)
*           Covers branch in GetRekeyNewKey: cryptoParam.encryptKey_.empty() == true,
*           triggers RdbSecurityManager path
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_016, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    RdbStoreConfig::CryptoParam emptyCryptoParam;
    emptyCryptoParam.isVectorRekey = true;
    errCode = store->Rekey(emptyCryptoParam);
    ASSERT_EQ(errCode, E_OK);
    CheckQueryData(store);
}

/**
* @tc.name: Vector_Rekey_017
* @tc.desc: test rekey with different key lengths (longer keys)
*           Covers key vector assignment in GetRekeyNewKey and RdDbRekey
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_017, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    InsertData(store);

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    newCryptoParam.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_OK);
    CheckQueryData(store);
}

/**
* @tc.name: Vector_Rekey_018
* @tc.desc: test rekey then insert/update/delete to verify store is fully functional after rekey
*           Covers post-rekey config_.ResetEncryptKey(key) and reopened connection usage
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyVectorTest, Vector_Rekey_018, TestSize.Level1)
{
    RdbStoreConfig config = GetVectorEncryptConfig(vectorDatabasePath);
    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6 };
    config.SetCryptoParam(cryptoParam);
    VectorRekeyOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = std::vector<uint8_t>{ 6, 5, 4, 3, 2, 1 };
    newCryptoParam.isVectorRekey = true;
    errCode = store->Rekey(newCryptoParam);
    ASSERT_EQ(errCode, E_OK);

    InsertData(store);
    CheckQueryData(store);

    auto updateRes = store->Execute("UPDATE test SET age = 20 WHERE name = 'zhangsan';");
    EXPECT_EQ(updateRes.first, E_OK);

    auto deleteRes = store->Execute("DELETE FROM test WHERE name = 'zhangsan';");
    EXPECT_EQ(deleteRes.first, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test", std::vector<std::string>{});
    EXPECT_NE(resultSet, nullptr);
    int count = 0;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 0);
    resultSet->Close();
}
