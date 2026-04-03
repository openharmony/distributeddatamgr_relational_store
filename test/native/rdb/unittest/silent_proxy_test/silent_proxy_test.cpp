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

#include "silent_proxy.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <atomic>
#include <vector>
#include <fstream>
#include <thread>

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_manager_mock.h"
#include "rdb_open_callback.h"
#include "rdb_service_mock.h"
#include "rdb_store_config.h"
#include "rdb_types.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;

namespace {
const std::string TEST_CONFIG_DIR = "/data/test/silent_conf/";
const std::string TEST_CONFIG_PATH = TEST_CONFIG_DIR + "silentproxy_config.json";
}

class SilentProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    static void CreateConfigFile(const std::string &content);
    static void RemoveConfigFile();

    // Mock helpers
    void SetupMock();
    void ClearMock();

    static inline std::shared_ptr<MockRdbManager> mockRdbManager_ = nullptr;
    static inline std::shared_ptr<MockRdbService> mockRdbService_ = nullptr;
};

void SilentProxyTest::SetUpTestCase(void)
{
    ::testing::FLAGS_gmock_verbose = "error";
    system(("mkdir -p " + TEST_CONFIG_DIR).c_str());
}

void SilentProxyTest::TearDownTestCase(void)
{
    system(("rm -rf " + TEST_CONFIG_DIR).c_str());
}

void SilentProxyTest::SetUp(void)
{
    RemoveConfigFile();
}

void SilentProxyTest::TearDown(void)
{
    RemoveConfigFile();
    ClearMock();
}

void SilentProxyTest::CreateConfigFile(const std::string &content)
{
    std::ofstream fout(TEST_CONFIG_PATH);
    ASSERT_TRUE(fout.is_open()) << "Failed to create config file";
    fout << content;
    fout.close();
}

void SilentProxyTest::RemoveConfigFile()
{
    (void)remove(TEST_CONFIG_PATH.c_str());
}

void SilentProxyTest::SetupMock()
{
    mockRdbManager_ = std::make_shared<MockRdbManager>();
    mockRdbService_ = std::make_shared<MockRdbService>();
    BRdbManager::rdbManager = mockRdbManager_;
}

void SilentProxyTest::ClearMock()
{
    BRdbManager::rdbManager = nullptr;
    mockRdbManager_ = nullptr;
    mockRdbService_ = nullptr;
}

// ==================== SilentProxy Serialization Tests ====================

/**
 * @tc.name: SilentProxy_Marshal_001
 * @tc.desc: Test SilentProxy Marshal with valid data
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, SilentProxy_Marshal_001, TestSize.Level1)
{
    SilentProxy proxy;
    proxy.bundleName = "com.example.test";
    proxy.storeNames = { "test.db", "test2.db" };

    SilentProxy::json node;
    EXPECT_TRUE(proxy.Marshal(node));
    EXPECT_EQ(node["bundleName"], "com.example.test");
    EXPECT_EQ(node["storeNames"].size(), 2);
}

/**
 * @tc.name: SilentProxy_Unmarshal_001
 * @tc.desc: Test SilentProxy Unmarshal with valid JSON data
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, SilentProxy_Unmarshal_001, TestSize.Level1)
{
    SilentProxy::json node;
    node["bundleName"] = "com.example.test";
    node["storeNames"] = { "test.db", "test2.db" };

    SilentProxy proxy;
    EXPECT_TRUE(proxy.Unmarshal(node));
    EXPECT_EQ(proxy.bundleName, "com.example.test");
    EXPECT_EQ(proxy.storeNames.size(), 2);
}

/**
 * @tc.name: SilentProxy_Unmarshal_Empty_002
 * @tc.desc: Test SilentProxy Unmarshal with empty data
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, SilentProxy_Unmarshal_Empty_002, TestSize.Level1)
{
    SilentProxy::json node;
    node["bundleName"] = "";
    node["storeNames"] = SilentProxy::json::array();

    SilentProxy proxy;
    EXPECT_TRUE(proxy.Unmarshal(node));
    EXPECT_EQ(proxy.bundleName, "");
    EXPECT_EQ(proxy.storeNames.size(), 0);
}

// ==================== SilentProxys Serialization Tests ====================

/**
 * @tc.name: SilentProxys_Marshal_001
 * @tc.desc: Test SilentProxys Marshal with multiple SilentProxy objects
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, SilentProxys_Marshal_001, TestSize.Level1)
{
    SilentProxys proxys;
    SilentProxy proxy1;
    proxy1.bundleName = "com.example.test1";
    proxy1.storeNames = { "test1.db" };
    SilentProxy proxy2;
    proxy2.bundleName = "com.example.test2";
    proxy2.storeNames = { "test2.db" };
    proxys.silentProxys = { proxy1, proxy2 };

    SilentProxys::json node;
    EXPECT_TRUE(proxys.Marshal(node));
    EXPECT_EQ(node["silentProxys"].size(), 2);
}

/**
 * @tc.name: SilentProxys_Unmarshal_001
 * @tc.desc: Test SilentProxys Unmarshal with valid JSON data
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, SilentProxys_Unmarshal_001, TestSize.Level1)
{
    SilentProxys::json node;
    node["silentProxys"] = SilentProxys::json::array();
    SilentProxys::json proxy1;
    proxy1["bundleName"] = "com.example.test1";
    proxy1["storeNames"] = { "test1.db" };
    SilentProxys::json proxy2;
    proxy2["bundleName"] = "com.example.test2";
    proxy2["storeNames"] = { "test2.db" };
    node["silentProxys"].push_back(proxy1);
    node["silentProxys"].push_back(proxy2);

    SilentProxys proxys;
    EXPECT_TRUE(proxys.Unmarshal(node));
    EXPECT_EQ(proxys.silentProxys.size(), 2);
}

/**
 * @tc.name: SilentProxys_Unmarshal_Empty_002
 * @tc.desc: Test SilentProxys Unmarshal with empty array
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, SilentProxys_Unmarshal_Empty_002, TestSize.Level1)
{
    SilentProxys::json node;
    node["silentProxys"] = SilentProxys::json::array();

    SilentProxys proxys;
    EXPECT_TRUE(proxys.Unmarshal(node));
    EXPECT_EQ(proxys.silentProxys.size(), 0);
}

// ==================== SilentProxyManager Constructor Tests ====================

/**
 * @tc.name: SilentProxyManager_Constructor_001
 * @tc.desc: Test SilentProxyManager constructor initializes correctly
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, SilentProxyManager_Constructor_001, TestSize.Level1)
{
    SilentProxyManager manager(TEST_CONFIG_PATH);
    EXPECT_NE(&manager, nullptr);
}

// ==================== IsSupportSilentFromProxy Branch Tests ====================

/**
 * @tc.name: IsSupportSilent_ProxyNotExist_ServiceFailed_001
 * @tc.desc: Test IsSupportSilent when proxy config not exist and service failed
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_ProxyNotExist_ServiceFailed_001, TestSize.Level1)
{
    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: IsSupportSilent_ProxyMatch_StoreInList_002
 * @tc.desc: Test IsSupportSilent when bundleName matches and storeName in list
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_ProxyMatch_StoreInList_002, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.test",
                "storeNames": ["test", "test2"]
            }
        ]
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_OK);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: IsSupportSilent_ProxyMatch_StoreNotInList_003
 * @tc.desc: Test IsSupportSilent when bundleName matches but storeName not in list
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_ProxyMatch_StoreNotInList_003, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.test",
                "storeNames": ["other"]
            }
        ]
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: IsSupportSilent_ProxyNotMatch_004
 * @tc.desc: Test IsSupportSilent when bundleName does not match any entry
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_ProxyNotMatch_004, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.other",
                "storeNames": ["test"]
            }
        ]
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: IsSupportSilent_ProxyCacheHit_005
 * @tc.desc: Test IsSupportSilent cache mechanism - second call should hit cache
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_ProxyCacheHit_005, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.test",
                "storeNames": ["test"]
            }
        ]
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err1, flag1] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err1, E_OK);
    EXPECT_TRUE(flag1);

    RemoveConfigFile();

    auto [err2, flag2] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err2, E_OK);
    EXPECT_TRUE(flag2);
}

/**
 * @tc.name: IsSupportSilent_StoreNameSuffix_006
 * @tc.desc: Test IsSupportSilent with store name suffix handling (.db)
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_StoreNameSuffix_006, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.test",
                "storeNames": ["test"]
            }
        ]
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_OK);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: IsSupportSilent_EmptyConfig_007
 * @tc.desc: Test IsSupportSilent with empty silentProxys array
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_EmptyConfig_007, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": []
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: IsSupportSilent_InvalidJson_008
 * @tc.desc: Test IsSupportSilent with invalid JSON content - Unmarshall fails
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_InvalidJson_008, TestSize.Level1)
{
    std::string config = "invalid json content";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_ERROR);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: IsSupportSilent_MalformedJson_008A
 * @tc.desc: Test IsSupportSilent with malformed JSON structure - Unmarshall fails
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_MalformedJson_008A, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.test"
                "storeNames": ["test"]
            }
        ]
    })";  // Missing comma between bundleName and storeNames
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_ERROR);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: IsSupportSilent_MultipleBundles_009
 * @tc.desc: Test IsSupportSilent with multiple bundle entries in config
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_MultipleBundles_009, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.test1",
                "storeNames": ["db1"]
            },
            {
                "bundleName": "com.example.test2",
                "storeNames": ["db2"]
            }
        ]
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);

    auto [err1, flag1] = manager.IsSupportSilent("com.example.test1", "db1.db");
    EXPECT_EQ(err1, E_OK);
    EXPECT_TRUE(flag1);

    auto [err2, flag2] = manager.IsSupportSilent("com.example.test2", "db2.db");
    EXPECT_EQ(err2, E_OK);
    EXPECT_TRUE(flag2);
}

/**
 * @tc.name: IsSupportSilent_ProxyReturnTrue_NoServiceCall_010
 * @tc.desc: Test IsSupportSilent returns immediately when proxy returns true
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, IsSupportSilent_ProxyReturnTrue_NoServiceCall_010, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.test",
                "storeNames": ["test"]
            }
        ]
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_OK);
    EXPECT_TRUE(flag);
}

// ==================== Service Mock Tests ====================

/**
 * @tc.name: Service_GetRdbService_NotSupport_011
 * @tc.desc: Test when GetRdbService returns E_NOT_SUPPORT
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Service_GetRdbService_NotSupport_011, TestSize.Level1)
{
    SetupMock();
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillOnce(Return(std::make_pair(E_NOT_SUPPORT, nullptr)));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_NOT_SUPPORT);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: Service_GetRdbService_Error_012
 * @tc.desc: Test when GetRdbService returns error
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Service_GetRdbService_Error_012, TestSize.Level1)
{
    SetupMock();
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillOnce(Return(std::make_pair(E_ERROR, nullptr)));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_ERROR);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: Service_GetRdbService_NullService_013
 * @tc.desc: Test when GetRdbService returns nullptr service
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Service_GetRdbService_NullService_013, TestSize.Level1)
{
    SetupMock();
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillOnce(Return(std::make_pair(E_OK, nullptr)));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_OK);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: Service_ReturnError_021
 * @tc.desc: Test when service->GetSilentAccessStores returns error
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Service_ReturnError_021, TestSize.Level1)
{
    SetupMock();
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillOnce(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_))
        .WillOnce(Return(std::make_pair(-1, std::vector<std::string>())));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_ERROR);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: Service_PermissionDenied_022
 * @tc.desc: Test when service->GetSilentAccessStores returns RDB_PERMISSION_DENIED
 *           and verify cache is set correctly
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Service_PermissionDenied_022, TestSize.Level1)
{
    SetupMock();
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillOnce(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_))
        .WillOnce(Return(std::make_pair(RDB_PERMISSION_DENIED, std::vector<std::string>())));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err1, flag1] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err1, E_ERROR);
    EXPECT_FALSE(flag1);

    auto [err2, flag2] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err2, E_OK);
    EXPECT_FALSE(flag2);
}

/**
 * @tc.name: Service_ReturnTrue_023
 * @tc.desc: Test when GetSilentAccessStores returns true
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Service_ReturnTrue_023, TestSize.Level1)
{
    SetupMock();
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillOnce(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_))
        .WillOnce(Return(std::make_pair(RDB_OK, std::vector<std::string>{ "test" })));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_OK);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: Service_ReturnFalse_024
 * @tc.desc: Test when GetSilentAccessStores returns false
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Service_ReturnFalse_024, TestSize.Level1)
{
    SetupMock();
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillOnce(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_))
        .WillOnce(Return(std::make_pair(RDB_OK, std::vector<std::string>{ "other" })));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    auto [err, flag] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err, E_OK);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: Service_CacheHit_025
 * @tc.desc: Test Service cache hit scenario
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Service_CacheHit_025, TestSize.Level1)
{
    SetupMock();
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillOnce(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_))
        .WillOnce(Return(std::make_pair(RDB_OK, std::vector<std::string>{ "test" })));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    // First call - should call service
    auto [err1, flag1] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err1, E_OK);
    EXPECT_TRUE(flag1);

    // Second call - should hit cache, no service call
    auto [err2, flag2] = manager.IsSupportSilent("com.example.test", "test.db");
    EXPECT_EQ(err2, E_OK);
    EXPECT_TRUE(flag2);
}

// ==================== Double-Check Concurrent Tests ====================

/**
 * @tc.name: Proxy_DoubleCheck_Concurrent_018
 * @tc.desc: Test Proxy double-check logic with concurrent calls
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Proxy_DoubleCheck_Concurrent_018, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.concurrent",
                "storeNames": ["test"]
            }
        ]
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    const int threadCount = 10;
    std::vector<std::thread> threads;
    std::vector<std::pair<int32_t, bool>> results(threadCount);

    auto task = [&manager, &results](int index) {
        results[index] = manager.IsSupportSilent("com.example.concurrent", "test.db");
    };

    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back(task, i);
    }

    for (auto &thread : threads) {
        thread.join();
    }

    // All threads should get the same result
    for (int i = 0; i < threadCount; i++) {
        EXPECT_EQ(results[i].first, E_OK);
        EXPECT_TRUE(results[i].second);
    }
}

/**
 * @tc.name: Proxy_DoubleCheck_Concurrent_Miss_019
 * @tc.desc: Test Proxy double-check when store not in list
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Proxy_DoubleCheck_Concurrent_Miss_019, TestSize.Level1)
{
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.concurrent",
                "storeNames": ["other"]
            }
        ]
    })";
    CreateConfigFile(config);

    SilentProxyManager manager(TEST_CONFIG_PATH);
    const int threadCount = 10;
    std::vector<std::thread> threads;
    std::vector<std::pair<int32_t, bool>> results(threadCount);

    auto task = [&manager, &results](int index) {
        results[index] = manager.IsSupportSilent("com.example.concurrent", "test.db");
    };

    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back(task, i);
    }

    for (auto &thread : threads) {
        thread.join();
    }

    // All threads should get false (store not in list, service will fail)
    for (int i = 0; i < threadCount; i++) {
        EXPECT_FALSE(results[i].second);
    }
}

/**
 * @tc.name: Service_Concurrent_030
 * @tc.desc: Test Service with concurrent calls
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Service_Concurrent_030, TestSize.Level1)
{
    SetupMock();
    // Only expect one service call due to double-check and caching
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillOnce(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_))
        .WillOnce(Return(std::make_pair(RDB_OK, std::vector<std::string>{ "test" })));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    const int threadCount = 10;
    std::vector<std::thread> threads;
    std::vector<std::pair<int32_t, bool>> results(threadCount);

    auto task = [&manager, &results](int index) {
        results[index] = manager.IsSupportSilent("com.example.concurrent", "test.db");
    };

    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back(task, i);
    }

    for (auto &thread : threads) {
        thread.join();
    }

    // All threads should get the same result
    for (int i = 0; i < threadCount; i++) {
        EXPECT_EQ(results[i].first, E_OK);
        EXPECT_TRUE(results[i].second);
    }
}

/**
 * @tc.name: Mixed_Concurrent_031
 * @tc.desc: Test concurrent access with mixed Proxy and Service paths
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, Mixed_Concurrent_031, TestSize.Level1)
{
    SetupMock();
    // For bundle not in proxy config, will call service
    EXPECT_CALL(*mockRdbManager_, GetRdbService(_))
        .WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_))
        .WillRepeatedly(Return(std::make_pair(RDB_OK, std::vector<std::string>{ "test" })));

    SilentProxyManager manager(TEST_CONFIG_PATH);
    const int threadCount = 20;
    std::vector<std::thread> threads;
    std::vector<std::pair<int32_t, bool>> results(threadCount);
    std::atomic<int> successCount{0};

    auto task = [&manager, &results, &successCount](int index) {
        // Alternate between two different bundles
        std::string bundle = (index % 2 == 0) ? "com.example.test1" : "com.example.test2";
        results[index] = manager.IsSupportSilent(bundle, "test.db");
        if (results[index].first == E_OK) {
            successCount++;
        }
    };

    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back(task, i);
    }

    for (auto &thread : threads) {
        thread.join();
    }

    // All threads should succeed
    EXPECT_EQ(successCount.load(), threadCount);
    for (int i = 0; i < threadCount; i++) {
        EXPECT_EQ(results[i].first, E_OK);
    }
}

// ==================== RoleType Skip IsSupportSilent Tests ====================

namespace {
const std::string RDB_VISITOR_TEST_PATH = "/data/test/rdb_visitor_test/";
}

class VisitorTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return store.ExecuteSql("CREATE TABLE IF NOT EXISTS test "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER)");
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

class VisitorTestVisitorOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override { return E_OK; }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override { return E_OK; }
};

/**
 * @tc.name: RoleType_Visitor_032
 * @tc.desc: Test VISITOR role skips IsSupportSilent call
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, RoleType_Visitor_032, TestSize.Level1)
{
    SetupMock();
    ON_CALL(*mockRdbManager_, GetRdbService(_))
        .WillByDefault(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_)).Times(1);

    system(("mkdir -p " + RDB_VISITOR_TEST_PATH).c_str());
    const std::string dbPath = RDB_VISITOR_TEST_PATH + "visitor_test.db";

    RdbStoreConfig ownerConfig(dbPath);
    ownerConfig.SetBundleName("com.test.visitor");
    ownerConfig.SetName("visitor_test.db");
    VisitorTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> ownerStore = RdbHelper::GetRdbStore(ownerConfig, 1, helper, errCode);
    ASSERT_NE(ownerStore, nullptr);

    RdbStoreConfig config("", StorageMode::MODE_DISK, true);
    config.SetRoleType(OHOS::NativeRdb::VISITOR);
    config.SetVisitorDir(dbPath);
    config.SetBundleName("com.test.visitor");
    config.SetName("visitor_test.db");

    VisitorTestVisitorOpenCallback visitorHelper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, visitorHelper, errCode);
    ASSERT_NE(store, nullptr);

    ownerStore = nullptr;
    store = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(dbPath);
    system(("rm -rf " + RDB_VISITOR_TEST_PATH).c_str());
}

/**
 * @tc.name: RoleType_VisitorWrite_033
 * @tc.desc: Test VISITOR_WRITE role skips IsSupportSilent call
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, RoleType_VisitorWrite_033, TestSize.Level1)
{
    SetupMock();
    ON_CALL(*mockRdbManager_, GetRdbService(_))
        .WillByDefault(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_)).Times(1);

    system(("mkdir -p " + RDB_VISITOR_TEST_PATH).c_str());
    const std::string dbPath = RDB_VISITOR_TEST_PATH + "visitor_write_test.db";

    RdbStoreConfig ownerConfig(dbPath);
    ownerConfig.SetBundleName("com.test.visitorwrite");
    ownerConfig.SetName("visitor_write_test.db");
    VisitorTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> ownerStore = RdbHelper::GetRdbStore(ownerConfig, 1, helper, errCode);
    ASSERT_NE(ownerStore, nullptr);

    RdbStoreConfig config("");
    config.SetRoleType(OHOS::NativeRdb::VISITOR_WRITE);
    config.SetVisitorDir(dbPath);
    config.SetBundleName("com.test.visitorwrite");
    config.SetName("visitor_write_test.db");

    VisitorTestVisitorOpenCallback visitorHelper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, visitorHelper, errCode);
    ASSERT_NE(store, nullptr);

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("test"));
    values.PutInt("age", 20);
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);

    ownerStore = nullptr;
    store = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(dbPath);
    system(("rm -rf " + RDB_VISITOR_TEST_PATH).c_str());
}

/**
 * @tc.name: RoleType_Owner_034
 * @tc.desc: Test OWNER role triggers IsSupportSilent call
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, RoleType_Owner_034, TestSize.Level1)
{
    SetupMock();
    ON_CALL(*mockRdbManager_, GetRdbService(_))
        .WillByDefault(Return(std::make_pair(E_OK, mockRdbService_)));
    EXPECT_CALL(*mockRdbService_, GetSilentAccessStores(_))
        .WillOnce(Return(std::make_pair(RDB_OK, std::vector<std::string>{ "other" })));

    system(("mkdir -p " + RDB_VISITOR_TEST_PATH).c_str());
    const std::string dbPath = RDB_VISITOR_TEST_PATH + "owner_test.db";

    RdbStoreConfig ownerConfig(dbPath);
    ownerConfig.SetBundleName("com.test.owner");
    ownerConfig.SetName("owner_test.db");

    VisitorTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(ownerConfig, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    store = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(dbPath);
    system(("rm -rf " + RDB_VISITOR_TEST_PATH).c_str());
}

/**
 * @tc.name: ClearCache_035
 * @tc.desc: Test SilentProxyManager::ClearCache functionality
 * @tc.type: FUNC
 */
HWTEST_F(SilentProxyTest, ClearCache_035, TestSize.Level1)
{
    SilentProxyManager manager(TEST_CONFIG_PATH);
    std::string config = R"({
        "silentProxys": [
            {
                "bundleName": "com.example.cache",
                "storeNames": ["store1", "store2"]
            }
        ]
    })";
    CreateConfigFile(config);
    auto [err1, flag1] = manager.IsSupportSilent("com.example.cache", "store1.db");
    EXPECT_EQ(err1, E_OK);
    EXPECT_TRUE(flag1);
    EXPECT_EQ(manager.silentCache_.Size(), 1);

    manager.ClearCache();
    EXPECT_EQ(manager.silentCache_.Size(), 0);

    auto [err2, flag2] = manager.IsSupportSilent("com.example.cache", "store1.db");
    EXPECT_EQ(err2, E_OK);
    EXPECT_TRUE(flag2);
    EXPECT_EQ(manager.silentCache_.Size(), 1);
    auto [err3, flag3] = manager.IsSupportSilent("com.example.cache", "store2.db");
    EXPECT_EQ(err3, E_OK);
    EXPECT_TRUE(flag3);
}
