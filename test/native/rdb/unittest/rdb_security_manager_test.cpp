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
#define LOG_TAG "RdbSecurityManagerTest"
#include "rdb_security_manager.h"

#include <block_data.h>
#include <gtest/gtest.h>

#include <thread>

#include "common.h"
#include "file_ex.h"
#include "rdb_errno.h"
#include "rdb_helper.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace Test {
using KeyType = RdbSecurityManager::KeyFileType;
class RdbSecurityManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    static constexpr const char *BUNDLE_NAME = "rdb.security.manager.test";
    static constexpr const char *DB_FILE = "security_manager_test.db";
    const std::string dbFile_ = RDB_TEST_PATH + DB_FILE;
};

void RdbSecurityManagerTest::SetUpTestCase(void)
{
    RdbSecurityManager::GetInstance().Init(BUNDLE_NAME);
}

void RdbSecurityManagerTest::TearDownTestCase(void)
{
}

void RdbSecurityManagerTest::SetUp(void)
{
}

void RdbSecurityManagerTest::TearDown(void)
{
}

class RdbStoreSecurityManagerTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return E_OK;
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

/**
 * @tc.name: Insert_BigInt_INT64
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbSecurityManagerTest, RestoreKeyFile, TestSize.Level1)
{
    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    auto errCode = RdbSecurityManager::GetInstance().RestoreKeyFile(dbFile_, key);
    ASSERT_EQ(errCode, E_OK);
    auto password = RdbSecurityManager::GetInstance().GetRdbPassword(dbFile_, KeyType::PUB_KEY_FILE);
    ASSERT_EQ(password.GetSize(), key.size());
    auto ret = memcmp(password.GetData(), key.data(), password.GetSize());
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: Insert_BigInt_INT64
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbSecurityManagerTest, LockUnlock, TestSize.Level1)
{
    auto blockResult = std::make_shared<OHOS::BlockData<bool>>(1, false);
    RdbSecurityManager::KeyFiles keyFiles(dbFile_);
    keyFiles.Lock();
    std::thread thread([dbFile = dbFile_, blockResult]() {
        RdbSecurityManager::KeyFiles keyFiles(dbFile);
        keyFiles.Lock();
        keyFiles.Unlock();
        blockResult->SetValue(true);
    });
    auto beforeUnlock = blockResult->GetValue();
    blockResult->Clear(false);
    keyFiles.Unlock();
    auto afterUnlock = blockResult->GetValue();
    ASSERT_FALSE(beforeUnlock);
    ASSERT_TRUE(afterUnlock);
    thread.join();
}

/**
 * @tc.name: LoadSecretKeyFromDiskTest
 * @tc.desc: test load secret key from disk test
 * @tc.type: FUNC
 */
HWTEST_F(RdbSecurityManagerTest, LoadSecretKeyFromDiskTest, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbPath = RDB_TEST_PATH + "secret_key_load_test.db";
    RdbStoreConfig config(dbPath);
    config.SetEncryptStatus(true);
    config.SetBundleName(BUNDLE_NAME);
    RdbStoreSecurityManagerTestOpenCallback helper;

    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);
    store = nullptr;

    RdbSecurityManager::KeyFiles keyFile(dbPath);
    const std::string file = keyFile.GetKeyFile(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
    std::vector<char> keyfile1;
    ASSERT_TRUE(OHOS::LoadBufferFromFile(file, keyfile1));

    std::vector<char> content = { 'a' };
    bool ret = OHOS::SaveBufferToFile(file, content);
    ASSERT_TRUE(ret);

    std::vector<char> keyfile2;
    ASSERT_TRUE(OHOS::LoadBufferFromFile(file, keyfile2));
    ASSERT_NE(keyfile1.size(), keyfile2.size());

    RdbStoreConfig config1(dbPath);
    config1.SetEncryptStatus(true);
    config1.SetBundleName(BUNDLE_NAME);
    RdbStoreSecurityManagerTestOpenCallback helper1;
    auto store1 = RdbHelper::GetRdbStore(config1, 1, helper1, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store1, nullptr);

    RdbHelper::DeleteRdbStore(config);
}

/**
 * @tc.name: LockNoBlockTest001
 * @tc.desc: Abnormal test for LockNB
 * @tc.type: FUNC
 */
HWTEST_F(RdbSecurityManagerTest, LockNBTest001, TestSize.Level1)
{
    std::string lockPath = dbFile_ + "-LockNBTest001";
    RdbSecurityManager::KeyFiles keyFiles(lockPath);
    EXPECT_EQ(keyFiles.DestroyLock(), E_OK);
    EXPECT_NE(keyFiles.Lock(false), E_OK);
}

/**
 * @tc.name: LockNBTest002
 * @tc.desc: test LockNB return E_ERROR when called from another fd
 * @tc.type: FUNC
 */
HWTEST_F(RdbSecurityManagerTest, LockNBTest002, TestSize.Level1)
{
    RdbSecurityManager::KeyFiles keyFiles(dbFile_);
    EXPECT_EQ(keyFiles.Lock(false), E_OK);
    std::thread thread([dbFile = dbFile_]() {
        RdbSecurityManager::KeyFiles keyFiles(dbFile);
        EXPECT_EQ(keyFiles.Lock(false), E_ERROR);
        keyFiles.Unlock();
    });
    sleep(1);
    thread.join();
    keyFiles.Unlock();
}

/**
 * @tc.name: InitPathTest
 * @tc.desc: test init path test
 * @tc.type: FUNC
 */
HWTEST_F(RdbSecurityManagerTest, InitPathTest, TestSize.Level1)
{
    std::string filePath("system/test");
    bool ret = RdbSecurityManager::InitPath(filePath);
    EXPECT_FALSE(ret);
}
} // namespace Test