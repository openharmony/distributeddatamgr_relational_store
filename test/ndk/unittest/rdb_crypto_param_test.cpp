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
#include "relational_store_error_code.h"
#include "common.h"
#include "oh_rdb_crypto_param.h"
#include "oh_data_define.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbCryptoParamTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
    }
};

void RdbCryptoParamTest::SetUpTestCase(void)
{
}

void RdbCryptoParamTest::TearDownTestCase(void)
{
}

void RdbCryptoParamTest::SetUp(void)
{
}

void RdbCryptoParamTest::TearDown(void)
{
}

/**
 * @tc.name: RDB_Crypto_Param_test_001
 * @tc.desc: Normal testCase of OH_Rdb_CreateCryptoParam and OH_Rdb_DestroyCryptoParam.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCryptoParamTest, RDB_Crypto_Param_test_001, TestSize.Level1)
{
    auto obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    auto ret = OH_Rdb_DestroyCryptoParam(nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    OH_Rdb_CryptoParam wrong;
    wrong.id = 1;
    ret = OH_Rdb_DestroyCryptoParam(&wrong);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Crypto_Param_test_002
 * @tc.desc: Normal testCase of OH_Crypto_SetEncryptionKey.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCryptoParamTest, RDB_Crypto_Param_test_002, TestSize.Level1)
{
    OH_Rdb_CryptoParam *obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    const uint8_t key[] = "12345678";
    auto ret = OH_Crypto_SetEncryptionKey(nullptr, key, sizeof(key) - 1);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Crypto_SetEncryptionKey(obj, key, sizeof(key) - 1);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.encryptKey_.size(), sizeof(key) - 1);
    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Crypto_Param_test_003
 * @tc.desc: Normal testCase of OH_Crypto_SetIteration.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCryptoParamTest, RDB_Crypto_Param_test_003, TestSize.Level1)
{
    OH_Rdb_CryptoParam *obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    // -1 is iteration times
    auto ret = OH_Crypto_SetIteration(obj, -1);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    // 1000 is iteration times
    ret = OH_Crypto_SetIteration(obj, 1000);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.iterNum, 1000);
    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Crypto_Param_test_004
 * @tc.desc: Normal testCase of OH_Crypto_SetEncryptionAlgo.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCryptoParamTest, RDB_Crypto_Param_test_004, TestSize.Level1)
{
    OH_Rdb_CryptoParam *obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    // 3 is invalid encryption
    auto ret = OH_Crypto_SetEncryptionAlgo(obj, 3);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Crypto_SetEncryptionAlgo(obj, RDB_AES_256_CBC);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.encryptAlgo, RDB_AES_256_CBC);
    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Crypto_Param_test_005
 * @tc.desc: Normal testCase of OH_Crypto_SetHmacAlgo.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCryptoParamTest, RDB_Crypto_Param_test_005, TestSize.Level1)
{
    OH_Rdb_CryptoParam *obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    // 3 is invalid hdc
    auto ret = OH_Crypto_SetHmacAlgo(obj, 3);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Crypto_SetHmacAlgo(obj, RDB_HMAC_SHA512);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.hmacAlgo, RDB_HMAC_SHA512);

    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Crypto_Param_test_006
 * @tc.desc: Normal testCase of OH_Crypto_SetKdfAlgo.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCryptoParamTest, RDB_Crypto_Param_test_006, TestSize.Level1)
{
    OH_Rdb_CryptoParam *obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    // 3 is invalid kdf
    auto ret = OH_Crypto_SetKdfAlgo(obj, 3);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Crypto_SetKdfAlgo(obj, RDB_KDF_SHA512);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.kdfAlgo, RDB_KDF_SHA512);
    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Crypto_Param_test_007
 * @tc.desc: Normal testCase of OH_Crypto_SetCryptoPageSize.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCryptoParamTest, RDB_Crypto_Param_test_007, TestSize.Level1)
{
    OH_Rdb_CryptoParam *obj = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(obj, NULL);

    int64_t pageSize = -1;
    auto ret = OH_Crypto_SetCryptoPageSize(obj, pageSize);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    pageSize = 1023;
    ret = OH_Crypto_SetCryptoPageSize(obj, pageSize);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    pageSize = 0;
    ret = OH_Crypto_SetCryptoPageSize(obj, pageSize);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    EXPECT_EQ(OH_Crypto_SetCryptoPageSize(obj, 512), RDB_E_INVALID_ARGS);
    EXPECT_EQ(OH_Crypto_SetCryptoPageSize(obj, 131072), RDB_E_INVALID_ARGS);
    
    pageSize = 1024;
    ret = OH_Crypto_SetCryptoPageSize(obj, pageSize);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.cryptoPageSize, pageSize);

    pageSize = 4096;
    ret = OH_Crypto_SetCryptoPageSize(obj, pageSize);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.cryptoPageSize, pageSize);

    pageSize = 65536;
    ret = OH_Crypto_SetCryptoPageSize(obj, pageSize);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(obj->cryptoParam.cryptoPageSize, pageSize);
    ret = OH_Rdb_DestroyCryptoParam(obj);
    EXPECT_EQ(ret, RDB_OK);
}