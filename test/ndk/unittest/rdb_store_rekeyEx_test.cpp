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

#include <string>

#include "accesstoken_kit.h"
#include "common.h"
#include "oh_data_define.h"
#include "oh_data_value.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

class RdbStoreRekeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    OH_VBucket *CreateAndSetValueBucket()
    {
        OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
        valueBucket->putInt64(valueBucket, "id", 1);
        valueBucket->putText(valueBucket, "data1", "zhangSan");
        valueBucket->putInt64(valueBucket, "data2", 13800);
        valueBucket->putReal(valueBucket, "data3", 200.1);
        valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
        return valueBucket;
    }

    OH_Rdb_ConfigV2 *CreateEncryptedConfig()
    {
        OH_Rdb_ConfigV2 *encryptedConfig = OH_Rdb_CreateConfig();
        if (encryptedConfig != nullptr) {
            OH_Rdb_SetDatabaseDir(encryptedConfig, RDB_TEST_PATH);
            OH_Rdb_SetStoreName(encryptedConfig, "rdb_store_rekey_test.db");
            OH_Rdb_SetBundleName(encryptedConfig, "com.ohos.example.distributedndk");
            OH_Rdb_SetEncrypted(encryptedConfig, true);
            OH_Rdb_SetSecurityLevel(encryptedConfig, OH_Rdb_SecurityLevel::S1);
            OH_Rdb_SetArea(encryptedConfig, RDB_SECURITY_AREA_EL1);
        }
        return encryptedConfig;
    }

    int Delete(OH_Rdb_Store *store)
    {
        OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
        OH_VObject *valueObject = OH_Rdb_CreateValueObject();
        const char *dataValue = "zhangSan";
        valueObject->putText(valueObject, dataValue);
        predicates->equalTo(predicates, "data1", valueObject);
        int errCode = OH_Rdb_Delete(store, predicates);
        return errCode;
    }
};
const char *createTableSql =
    "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
    "data3 FLOAT, data4 BLOB, data5 TEXT);";
const char *querySql = "SELECT * FROM store_test";

void RdbStoreRekeyTest::SetUpTestCase(void)
{
}

void RdbStoreRekeyTest::TearDownTestCase(void)
{
}

void RdbStoreRekeyTest::SetUp(void)
{
}

void RdbStoreRekeyTest::TearDown(void)
{
}

/**
 * @tc.name: RDB_Rekey_test_001
 * @tc.desc: test non-encrypted database rekey
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreRekeyTest, RDB_Rekey_test_001, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    ASSERT_NE(config, nullptr);
    OH_Rdb_SetDatabaseDir(config, RDB_TEST_PATH);
    OH_Rdb_SetStoreName(config, "rdb_store_test.db");
    OH_Rdb_SetBundleName(config, "com.ohos.example.distributedndk");
    OH_Rdb_SetEncrypted(config, false);
    OH_Rdb_SetSecurityLevel(config, OH_Rdb_SecurityLevel::S1);
    OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL1);
    int errCode = 0;
    OH_Rdb_Store *store = OH_Rdb_CreateOrOpen(config, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    errCode = OH_Rdb_Execute(store, createTableSql);
    EXPECT_EQ(errCode, 0);
    ASSERT_NE(store, nullptr);
    OH_VBucket *valueBucket = CreateAndSetValueBucket();
    errCode = OH_Rdb_Insert(store, "store_test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_Rdb_CryptoParam *crypto1 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto1, NULL);
    OH_Crypto_SetEncryptionAlgo(crypto1, RDB_PLAIN_TEXT);
    errCode = OH_Rdb_RekeyEx(store, crypto1);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Rdb_CloseStore(store);
    EXPECT_EQ(errCode, 0);

    OH_Rdb_SetCryptoParam(config, crypto1);
    store = OH_Rdb_CreateOrOpen(config, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(store, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
    errCode = OH_Rdb_DeleteStoreV2(config);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DestroyConfig(config);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Rdb_DestroyCryptoParam(crypto1);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_Rekey_test_002
 * @tc.desc: 自定义->自定义
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreRekeyTest, RDB_Rekey_test_002, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *rekeyTestConfig = CreateEncryptedConfig();
    ASSERT_NE(rekeyTestConfig, nullptr);

    OH_Rdb_CryptoParam *crypto1 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto1, NULL);
    const uint8_t key[] = "12345678";
    int errCode = OH_Crypto_SetEncryptionKey(crypto1, key, sizeof(key) - 1);
    errCode = OH_Rdb_SetCryptoParam(rekeyTestConfig, crypto1);
    EXPECT_EQ(errCode, RDB_OK);

    OH_Rdb_Store *store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    errCode = OH_Rdb_Execute(store, createTableSql);
    EXPECT_EQ(errCode, 0);

    OH_VBucket *valueBucket = CreateAndSetValueBucket();
    errCode = OH_Rdb_Insert(store, "store_test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_Rdb_CryptoParam *crypto2 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto2, NULL);
    const uint8_t newKey[] = "87654321";
    errCode = OH_Crypto_SetEncryptionKey(crypto2, newKey, sizeof(newKey) - 1);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Crypto_SetEncryptionAlgo(crypto2, RDB_AES_256_CBC);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Crypto_SetIteration(crypto2, 3000);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Rdb_RekeyEx(store, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(store, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->destroy(cursor);

    errCode = Delete(store);
    EXPECT_EQ(errCode, 1);

    errCode = OH_Rdb_CloseStore(store);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_SetCryptoParam(rekeyTestConfig, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor1 = OH_Rdb_ExecuteQuery(store, querySql);

    rowCount = 0;
    cursor1->getRowCount(cursor1, &rowCount);
    EXPECT_EQ(rowCount, 0);
    cursor1->destroy(cursor1);
    valueBucket->destroy(valueBucket);
    errCode = OH_Rdb_DeleteStoreV2(rekeyTestConfig);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DestroyConfig(rekeyTestConfig);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_037
 * @tc.desc: 改变其他参数
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreRekeyTest, RDB_Rekey_test_003, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *rekeyTestConfig = CreateEncryptedConfig();
    ASSERT_NE(rekeyTestConfig, nullptr);
    int errCode = RDB_OK;

    OH_Rdb_Store *store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    errCode = OH_Rdb_Execute(store, createTableSql);
    EXPECT_EQ(errCode, 0);

    OH_VBucket *valueBucket = CreateAndSetValueBucket();
    errCode = OH_Rdb_Insert(store, "store_test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_Rdb_CryptoParam *crypto2 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto2, NULL);
    errCode = OH_Crypto_SetKdfAlgo(crypto2, RDB_KDF_SHA512);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Rdb_RekeyEx(store, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    errCode = OH_Rdb_CloseStore(store);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_SetEncrypted(rekeyTestConfig, true);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Rdb_SetCryptoParam(rekeyTestConfig, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor1 = OH_Rdb_ExecuteQuery(store, querySql);

    int rowCount = 0;
    cursor1->getRowCount(cursor1, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor1->destroy(cursor1);
    valueBucket->destroy(valueBucket);
    errCode = OH_Rdb_DeleteStoreV2(rekeyTestConfig);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DestroyConfig(rekeyTestConfig);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_Rekey_test_002
 * @tc.desc: 自定义->自动
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreRekeyTest, RDB_Rekey_test_004, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *rekeyTestConfig = CreateEncryptedConfig();
    ASSERT_NE(rekeyTestConfig, nullptr);

    OH_Rdb_CryptoParam *crypto1 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto1, NULL);
    const uint8_t key[] = "12345678";
    int errCode = OH_Crypto_SetEncryptionKey(crypto1, key, sizeof(key) - 1);
    errCode = OH_Rdb_SetCryptoParam(rekeyTestConfig, crypto1);
    EXPECT_EQ(errCode, RDB_OK);

    OH_Rdb_Store *store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    errCode = OH_Rdb_Execute(store, createTableSql);
    EXPECT_EQ(errCode, 0);

    OH_VBucket *valueBucket = CreateAndSetValueBucket();
    errCode = OH_Rdb_Insert(store, "store_test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_Rdb_CryptoParam *crypto2 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto2, NULL);
    errCode = OH_Crypto_SetHmacAlgo(crypto2, RDB_HMAC_SHA512);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Rdb_RekeyEx(store, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    errCode = OH_Rdb_CloseStore(store);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_SetCryptoParam(rekeyTestConfig, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor1 = OH_Rdb_ExecuteQuery(store, querySql);

    int rowCount = 0;
    cursor1->getRowCount(cursor1, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor1->destroy(cursor1);
    valueBucket->destroy(valueBucket);
    errCode = OH_Rdb_DeleteStoreV2(rekeyTestConfig);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DestroyConfig(rekeyTestConfig);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_Rekey_test_002
 * @tc.desc: 自动->自动
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreRekeyTest, RDB_Rekey_test_005, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *rekeyTestConfig = CreateEncryptedConfig();
    ASSERT_NE(rekeyTestConfig, nullptr);

    OH_Rdb_CryptoParam *crypto1 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto1, NULL);
    int errCode = OH_Rdb_SetCryptoParam(rekeyTestConfig, crypto1);
    EXPECT_EQ(errCode, RDB_OK);

    OH_Rdb_Store *store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    errCode = OH_Rdb_Execute(store, createTableSql);
    EXPECT_EQ(errCode, 0);

    OH_VBucket *valueBucket = CreateAndSetValueBucket();
    errCode = OH_Rdb_Insert(store, "store_test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_Rdb_CryptoParam *crypto2 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto2, NULL);
    errCode = OH_Crypto_SetKdfAlgo(crypto2, RDB_KDF_SHA512);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Rdb_RekeyEx(store, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(store, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->destroy(cursor);

    errCode = Delete(store);
    EXPECT_EQ(errCode, 1);

    errCode = OH_Rdb_CloseStore(store);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_SetCryptoParam(rekeyTestConfig, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor1 = OH_Rdb_ExecuteQuery(store, querySql);

    rowCount = 0;
    cursor1->getRowCount(cursor1, &rowCount);
    EXPECT_EQ(rowCount, 0);
    cursor1->destroy(cursor1);
    valueBucket->destroy(valueBucket);
    errCode = OH_Rdb_DeleteStoreV2(rekeyTestConfig);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DestroyConfig(rekeyTestConfig);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_Rekey_test_002
 * @tc.desc: 自动->自定义
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreRekeyTest, RDB_Rekey_test_006, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *rekeyTestConfig = CreateEncryptedConfig();
    ASSERT_NE(rekeyTestConfig, nullptr);

    OH_Rdb_CryptoParam *crypto1 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto1, NULL);
    int errCode = OH_Rdb_SetCryptoParam(rekeyTestConfig, crypto1);
    EXPECT_EQ(errCode, RDB_OK);

    OH_Rdb_Store *store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    errCode = OH_Rdb_Execute(store, createTableSql);
    EXPECT_EQ(errCode, 0);

    OH_VBucket *valueBucket = CreateAndSetValueBucket();
    errCode = OH_Rdb_Insert(store, "store_test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_Rdb_CryptoParam *crypto2 = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto2, NULL);
    const uint8_t newKey[] = "87654321";
    errCode = OH_Crypto_SetEncryptionKey(crypto2, newKey, sizeof(newKey) - 1);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Crypto_SetCryptoPageSize(crypto2, 2048);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Rdb_RekeyEx(store, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(store, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->destroy(cursor);

    errCode = Delete(store);
    EXPECT_EQ(errCode, 1);

    errCode = OH_Rdb_CloseStore(store);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_SetCryptoParam(rekeyTestConfig, crypto2);
    EXPECT_EQ(errCode, RDB_OK);

    store = OH_Rdb_CreateOrOpen(rekeyTestConfig, &errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor1 = OH_Rdb_ExecuteQuery(store, querySql);

    rowCount = 0;
    cursor1->getRowCount(cursor1, &rowCount);
    EXPECT_EQ(rowCount, 0);
    cursor1->destroy(cursor1);
    valueBucket->destroy(valueBucket);
    errCode = OH_Rdb_DeleteStoreV2(rekeyTestConfig);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DestroyConfig(rekeyTestConfig);
    EXPECT_EQ(errCode, RDB_OK);
}