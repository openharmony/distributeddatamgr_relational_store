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

#define LOG_TAG "RdbRekeyExTest"
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include "common.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

namespace OHOS::RdbStoreRekeyExTest {
constexpr int64_t ITER_NUM = 500;
constexpr int64_t NEW_ITER_NUM = 5000;
constexpr int CRYPTO_PAGE_SIZE = 2048;
constexpr int NEW_CRYPTO_PAGE_SIZE = 1024;
constexpr int AGE_VALUE = 18;
struct RekeyExTestParam {
    RdbStoreConfig::CryptoParam srcCryptoParam;
    RdbStoreConfig::CryptoParam dstCryptoParam;
};

std::vector<RekeyExTestParam> GenerateAllRekeyExParams()
{
    std::vector<RdbStoreConfig::CryptoParam> allCryptoParams;
    for (int encrypt = 0; encrypt <= static_cast<int>(EncryptAlgo::PLAIN_TEXT); encrypt++) {
        for (int hmac = 0; hmac < static_cast<int>(HmacAlgo::HMAC_BUTT); hmac++) {
            for (int kdf = 0; kdf < static_cast<int>(KdfAlgo::KDF_BUTT); kdf++) {
                RdbStoreConfig::CryptoParam param;
                param.encryptAlgo = static_cast<EncryptAlgo>(encrypt);
                param.hmacAlgo = static_cast<HmacAlgo>(hmac);
                param.kdfAlgo = static_cast<KdfAlgo>(kdf);
                param.iterNum = ITER_NUM;
                param.cryptoPageSize = CRYPTO_PAGE_SIZE;
                allCryptoParams.push_back(param);
            }
        }
    }
    std::vector<RekeyExTestParam> allTestParams;
    for (const auto &srcParam : allCryptoParams) {
        for (const auto &dstParam : allCryptoParams) {
            allTestParams.push_back({ srcParam, dstParam });
        }
    }
    return allTestParams;
}

class RekeyTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};
constexpr const char *CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test1 ("
                                          "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "name TEXT NOT NULL, "
                                          "age INTEGER)";

int RekeyTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RekeyTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

class RdbRekeyExTest : public testing::TestWithParam<RekeyExTestParam> {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    void VerifyResultSet(std::shared_ptr<ResultSet> resultSet);
    const std::string BUNDLE_NAME = "com.example.test_rekey";

protected:
    RekeyExTestParam currentParam_;
    std::string encryptedDatabaseName_;
    std::string encryptedDatabasePath_;
    std::shared_ptr<RdbStore> store_;
};

void RdbRekeyExTest::SetUpTestCase(void)
{
}

void RdbRekeyExTest::TearDownTestCase(void)
{
}

void RdbRekeyExTest::SetUp(void)
{
    currentParam_ = GetParam();
    encryptedDatabaseName_ = "RekeyEx_test.db";
    encryptedDatabasePath_ = RDB_TEST_PATH + encryptedDatabaseName_;
}

void RdbRekeyExTest::TearDown(void)
{
}

void RdbRekeyExTest::VerifyResultSet(std::shared_ptr<ResultSet> resultSet)
{
    ASSERT_NE(resultSet, nullptr);

    int32_t rowCount = 0;
    int ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);

    ret = resultSet->GoToFirstRow();
    ASSERT_EQ(ret, E_OK);

    int columnIndex = -1;

    ret = resultSet->GetColumnIndex("id", columnIndex);
    ASSERT_EQ(ret, E_OK);
    int idVal = -1;
    ret = resultSet->GetInt(columnIndex, idVal);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(idVal, 1);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    ASSERT_EQ(ret, E_OK);
    std::string nameVal;
    ret = resultSet->GetString(columnIndex, nameVal);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(nameVal, "zhangsan");

    ret = resultSet->GetColumnIndex("age", columnIndex);
    ASSERT_EQ(ret, E_OK);
    int ageVal = -1;
    ret = resultSet->GetInt(columnIndex, ageVal);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(ageVal, AGE_VALUE);
}

/**
* @tc.name: RdbStore_RekeyEx_001
* @tc.desc: test rekeyex all crypto params
* @tc.type: FUNC
*/
HWTEST_P(RdbRekeyExTest, RdbStore_RekeyEx_001, TestSize.Level1)
{
    int errCode = E_OK;
    auto &srcParam = currentParam_.srcCryptoParam;
    auto &dstParam = currentParam_.dstCryptoParam;
    dstParam.iterNum = NEW_ITER_NUM;
    dstParam.cryptoPageSize = NEW_CRYPTO_PAGE_SIZE;

    RdbStoreConfig config(encryptedDatabasePath_);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetBundleName(BUNDLE_NAME);
    config.SetName(encryptedDatabaseName_);
    config.SetCryptoParam(srcParam);
    config.SetEncryptStatus(true);
    RekeyTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store_, nullptr);
    ASSERT_EQ(errCode, E_OK);

    int64_t insertId = -1;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", "zhangsan");
    values.PutInt("age", AGE_VALUE);
    int ret = store_->Insert(insertId, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(insertId, 1);

    errCode = store_->RekeyEx(dstParam);
    ASSERT_EQ(errCode, E_OK);

    store_ = nullptr;
    config.SetCryptoParam(dstParam);
    config.SetEncryptStatus(dstParam.encryptAlgo != EncryptAlgo::PLAIN_TEXT);
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store_, nullptr);
    ASSERT_EQ(errCode, E_OK);

    auto resultSet = store_->QueryByStep("SELECT * FROM test1");
    VerifyResultSet(resultSet);
    resultSet->Close();
    RdbHelper::DeleteRdbStore(config);
}

INSTANTIATE_TEST_SUITE_P(RdbRekeyExTestSuite, RdbRekeyExTest, testing::ValuesIn(GenerateAllRekeyExParams()));

} // namespace OHOS::RdbStoreRekeyExTest
