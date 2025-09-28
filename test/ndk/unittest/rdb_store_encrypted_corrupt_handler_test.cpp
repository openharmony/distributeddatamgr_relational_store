/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <fstream>
#include <string>

#include "accesstoken_kit.h"
#include "common.h"
#include "grd_api_manager.h"
#include "handle_manager.h"
#include "oh_data_define.h"
#include "oh_data_utils.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_ndk_utils.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "relational_store_inner_types.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

class RdbStoreEncryptedCorruptHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static OH_Rdb_ConfigV2 *InitRdbConfig()
    {
        OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
        EXPECT_NE(config, nullptr);
        OH_Rdb_SetDatabaseDir(config, RDB_TEST_PATH);
        OH_Rdb_SetStoreName(config, "encrypted_store_test.db");
        OH_Rdb_SetBundleName(config, "com.ohos.example.distributedndk");
        OH_Rdb_SetEncrypted(config, true);
        OH_Rdb_SetSecurityLevel(config, OH_Rdb_SecurityLevel::S1);
        OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL1);

        EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetDbType(config, RDB_SQLITE));
        return config;
    }
    static void TestEncryptedCorruptedHandler(OH_Rdb_ConfigV2 *config, void *context, OH_Rdb_Store *store);
    static void TestEncryptedCorruptedHandler1(OH_Rdb_ConfigV2 *config, void *context, OH_Rdb_Store *store);
    static void DestroyDb(const std::string &filePath);
};

void RdbStoreEncryptedCorruptHandlerTest::TestEncryptedCorruptedHandler(
    OH_Rdb_ConfigV2 *config, void *context, OH_Rdb_Store *store)
{
    std::string restorePath1 =
        "/data/storage/el2/database/com.ohos.example.distributedndk/entry/rdb/encrypted_back_test.db";
    if (store == nullptr) {
        int ret = OH_Rdb_DeleteStoreV2(config);
        EXPECT_EQ(ret, RDB_OK);
    } else {
        int errCode = OH_Rdb_Restore(store, restorePath1.c_str());
        EXPECT_EQ(errCode, RDB_OK);
    }
}

void RdbStoreEncryptedCorruptHandlerTest::TestEncryptedCorruptedHandler1(
    OH_Rdb_ConfigV2 *config, void *context, OH_Rdb_Store *store)
{
    std::string restorePath1 =
        "/data/storage/el2/database/com.ohos.example.distributedndk/entry/rdb/encrypted_back_test.db";
    if (store == nullptr) {
        return;
    } else {
        return;
    }
}

const char CREATE_TABLE[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
const std::string RDB_TEST_PATH2 =
    "/data/storage/el2/database/com.ohos.example.distributedndk/entry/rdb/encrypted_store_test.db";

void RdbStoreEncryptedCorruptHandlerTest::DestroyDb(const std::string &filePath)
{
    const char *message = "hello";
    const size_t messageLength = 5;
    const size_t seekPosition = 64;
    std::ofstream fsDb(filePath, std::ios_base::binary | std::ios_base::out);
    fsDb.seekp(seekPosition);
    fsDb.write(message, messageLength);
    fsDb.close();
}

void RdbStoreEncryptedCorruptHandlerTest::SetUpTestCase(void)
{
}

void RdbStoreEncryptedCorruptHandlerTest::TearDownTestCase(void)
{
}

void RdbStoreEncryptedCorruptHandlerTest::SetUp(void)
{
}

void RdbStoreEncryptedCorruptHandlerTest::TearDown(void)
{
}

/**
 * @tc.name: RDB_Native_store_test_001
 * @tc.desc: test database header corruption
 * first register corruptedhandler and then open encrypted database;
 * close store and corrupt database header;
 * trigger the callback to delete, and then open encrypted database successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_001, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();
    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, CREATE_TABLE));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH2);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, CREATE_TABLE));
    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_002
 * @tc.desc: test database header corruption
 * first register corruptedhandler and then open custom encrypted database;
 * close store and corrupt database header;
 * trigger the callback to delete, and then open encrypted database successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_002, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();
    EXPECT_EQ(errCode, RDB_OK);
    OH_Rdb_CryptoParam *obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    const uint8_t key[] = "12345678";
    auto ret = OH_Crypto_SetEncryptionKey(obj, key, sizeof(key) - 1);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.encryptKey_.size(), sizeof(key) - 1);
    ret = OH_Rdb_SetCryptoParam(config1, obj);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, CREATE_TABLE));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH2);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, CREATE_TABLE));
    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_003
 * @tc.desc: test database header corruption
 * first open encrypted database and then register corruptedhandler;
 * close store and corrupt database header;
 * trigger the callback to delete, and then open encrypted database successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_003, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);

    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, CREATE_TABLE));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH2);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, CREATE_TABLE));
    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_004
 * @tc.desc: test database header corruption
 * first open custom encrypted database and then register corruptedhandler;
 * close store and corrupt database header;
 * trigger the callback to delete, and then open encrypted database successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_004, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;

    auto config1 = InitRdbConfig();
    EXPECT_EQ(errCode, RDB_OK);
    OH_Rdb_CryptoParam *obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    const uint8_t key[] = "12345678";
    auto ret = OH_Crypto_SetEncryptionKey(obj, key, sizeof(key) - 1);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.encryptKey_.size(), sizeof(key) - 1);
    ret = OH_Rdb_SetCryptoParam(config1, obj);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);

    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, CREATE_TABLE));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH2);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, CREATE_TABLE));
    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_005
 * @tc.desc: test database header corruption
 * first register corruptedhandler and then open custom encrypted database;
 * close store and modify encryption parameters;
 * trigger the callback to delete, and then open encrypted database successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_005, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;

    auto config1 = InitRdbConfig();
    EXPECT_EQ(errCode, RDB_OK);
    OH_Rdb_CryptoParam *obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    const uint8_t key[] = "12345678";
    auto ret = OH_Crypto_SetEncryptionKey(obj, key, sizeof(key) - 1);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Rdb_SetCryptoParam(config1, obj);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, CREATE_TABLE));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    ret = OH_Crypto_SetIteration(obj, 5000);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Crypto_SetKdfAlgo(obj, RDB_KDF_SHA512);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.encryptKey_.size(), sizeof(key) - 1);
    EXPECT_EQ(obj->cryptoParam.kdfAlgo, RDB_KDF_SHA512);
    ret = OH_Rdb_SetCryptoParam(config1, obj);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, CREATE_TABLE));
    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_006
 * @tc.desc: test database header corruption
 * first register corruptedhandler and then open encrypted database;
 * close store and corrupt database header;
 * repeat registration returnerror, the original registration is still valid.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_006, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, CREATE_TABLE));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH2);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, CREATE_TABLE));
    Rdb_CorruptedHandler handler1 = TestEncryptedCorruptedHandler1;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler1);

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    DestroyDb(RDB_TEST_PATH2);

    int errCode3 = OH_Rdb_ErrCode::RDB_OK;
    auto store3 = OH_Rdb_CreateOrOpen(config1, &errCode3);
    EXPECT_EQ(store3, NULL);
    errCode3 = OH_Rdb_ErrCode::RDB_OK;

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store3 = OH_Rdb_CreateOrOpen(config1, &errCode3);
    EXPECT_NE(store3, NULL);

    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store3));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_007
 * @tc.desc: test unregiste corruptedHandler
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_007, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, CREATE_TABLE));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));

    DestroyDb(RDB_TEST_PATH2);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, CREATE_TABLE));
    OH_Rdb_UnregisterCorruptedHandler(config1, handler);

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    DestroyDb(RDB_TEST_PATH2);

    int errCode3 = OH_Rdb_ErrCode::RDB_OK;
    auto store3 = OH_Rdb_CreateOrOpen(config1, &errCode3);
    EXPECT_EQ(store3, NULL);
    errCode3 = OH_Rdb_ErrCode::RDB_OK;
    store3 = OH_Rdb_CreateOrOpen(config1, &errCode3);
    EXPECT_EQ(store3, NULL);

    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_008
 * @tc.desc: test cancel and re-register after open database.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_008, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, CREATE_TABLE));
    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH2);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, CREATE_TABLE));

    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_009
 * @tc.desc: first registe, then open database, close database, and reopen database.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_009, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, CREATE_TABLE));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH2);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, CREATE_TABLE));

    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_010
 * @tc.desc: test invaild args
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_010, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    OH_Rdb_ConfigV2 *config = nullptr;
    void *context = nullptr;
    Rdb_CorruptedHandler handler = nullptr;
    Rdb_CorruptedHandler handler1 = TestEncryptedCorruptedHandler;
    errCode = OH_Rdb_RegisterCorruptedHandler(config, context, handler1);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    auto config1 = InitRdbConfig();
    errCode = OH_Rdb_RegisterCorruptedHandler(config1, context, handler);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    config1->magicNum = 0xFF;
    errCode = OH_Rdb_RegisterCorruptedHandler(config1, context, handler1);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_011
 * @tc.desc: test unregisters
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreEncryptedCorruptHandlerTest, RDB_Native_store_test_011, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestEncryptedCorruptedHandler;
    Rdb_CorruptedHandler handler1 = TestEncryptedCorruptedHandler1;

    auto config1 = InitRdbConfig();
    errCode = OH_Rdb_RegisterCorruptedHandler(config1, context, handler);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    errCode = OH_Rdb_RegisterCorruptedHandler(config1, context, handler1);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    OH_Rdb_UnregisterCorruptedHandler(config1, handler);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    OH_Rdb_UnregisterCorruptedHandler(config1, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    OH_Rdb_DestroyConfig(config1);
}