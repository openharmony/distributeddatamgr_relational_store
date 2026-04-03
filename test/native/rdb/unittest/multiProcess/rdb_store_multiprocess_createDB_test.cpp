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
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <system_error>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include "common.h"
#include "grd_type_export.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_security_manager.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"

using namespace testing::ext;
using namespace testing::mt;
using namespace OHOS::NativeRdb;

// Constants for testing
static constexpr int32_t TEST_AGE = 18;
static constexpr double TEST_SALARY = 100.5;
static const std::vector<uint8_t> TEST_BLOB_DATA = { 1, 2, 3 };
static constexpr int32_t PROCESS_CLEANUP_DELAY_MS = 100;

/**
 * @brief Database callback for table creation
 */
class DatabaseCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override
    {
        return rdbStore.ExecuteSql(
            "CREATE TABLE IF NOT EXISTS test "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)");
    }

    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        // Upgrade logic can be implemented here if needed
        return E_OK;
    }
};

/**
 * @brief Helper class for multi-process testing
 */
struct TestDataConfig {
    std::string dataName;
    int age;
    double salary;
};

/**
 * @brief Database configuration
 */
struct DatabaseConfig {
    std::string dbName;
    std::string bundleName;
    std::string areaName;
};

/**
 * @brief Configuration data for database test
 */
struct TestConfig {
    std::string dbName;
    bool encryptStatus;
    std::string dataName;
    int age;
    double salary;
    std::string bundleName;
    std::string areaName;
    bool isVector;
    OHOS::NativeRdb::StorageMode storageMode;
    OHOS::NativeRdb::SecurityLevel securityLevel;
};

/**
 * @brief Helper class for database operations
 */
class DatabaseHelper {
public:
    static OHOS::NativeRdb::ValuesBucket CreateTestValues(const std::string& name, int age, double salary,
                                                          const std::vector<uint8_t>& blobData)
    {
        OHOS::NativeRdb::ValuesBucket values;
        values.Put("name", name);
        values.Put("age", age);
        values.Put("salary", salary);
        values.Put("blobType", blobData);
        return values;
    }

    static bool VerifyData(const std::shared_ptr<OHOS::NativeRdb::RdbStore>& store, const std::string& expectedName)
    {
        auto resultSet = store->QuerySql("SELECT * FROM test WHERE name = ?",
                                         std::vector<std::string>{expectedName});
        if (!resultSet) {
            return false;
        }

        if (resultSet->GoToFirstRow() != E_OK) {
            return false;
        }

        int columnIndex;
        std::string strVal;

        if (resultSet->GetColumnIndex("name", columnIndex) != E_OK) {
            return false;
        }
        if (resultSet->GetString(columnIndex, strVal) != E_OK) {
            return false;
        }

        return strVal == expectedName;
    }

    static void InsertTestData(const std::shared_ptr<OHOS::NativeRdb::RdbStore>& store,
                               const OHOS::NativeRdb::ValuesBucket& values, const std::string& tableName = "test")
    {
        int64_t id;
        int ret = store->Insert(id, tableName, values);
        EXPECT_EQ(ret, E_OK);
        EXPECT_GT(id, 0);
    }

    static void CleanupDatabase(const std::string& dbName)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(PROCESS_CLEANUP_DELAY_MS));
        RdbHelper::DeleteRdbStore(RDB_TEST_PATH + dbName);
    }
};

/**
 * @brief Process test configuration and execution
 */
class ProcessTest {
private:
    TestConfig config;

public:
    // Constructor with 3 parameters (G.FUN.01-CPP compliant)
    ProcessTest(const DatabaseConfig& dbConfig, const TestDataConfig& dataConfig, bool encryptStatus = true)
        : config{dbConfig.dbName, encryptStatus, dataConfig.dataName, dataConfig.age, dataConfig.salary,
                 dbConfig.bundleName, dbConfig.areaName, false, OHOS::NativeRdb::StorageMode::MODE_DISK,
                 OHOS::NativeRdb::SecurityLevel::S1} {}

    // Constructor with 1 parameter (G.FUN.01-CPP compliant)
    explicit ProcessTest(const TestConfig& testConfig) : config(testConfig) {}

    void RunProcess() const
    {
        auto store = CreateStore();
        EXPECT_NE(store, nullptr) << "Failed to create store";
        if (!store) {
            return;
        }
        // Insert and verify test data
        OHOS::NativeRdb::ValuesBucket values = DatabaseHelper::CreateTestValues(config.dataName, config.age,
                                                                                config.salary, TEST_BLOB_DATA);
        DatabaseHelper::InsertTestData(store, values);
        EXPECT_TRUE(DatabaseHelper::VerifyData(store, config.dataName));

        // Clean up
        DatabaseHelper::CleanupDatabase(config.dbName);
    }

    void RunProcessWithVectorConfig()
    {
        config.isVector = true;
        config.securityLevel = OHOS::NativeRdb::SecurityLevel::S4;
        auto store = CreateStore();
        EXPECT_NE(store, nullptr) << "Failed to create vector store";
        if (!store) {
            return;
        }
        OHOS::NativeRdb::ValuesBucket values = DatabaseHelper::CreateTestValues(config.dataName, config.age,
                                                                                config.salary, TEST_BLOB_DATA);
        DatabaseHelper::InsertTestData(store, values);
        EXPECT_TRUE(DatabaseHelper::VerifyData(store, config.dataName));

        DatabaseHelper::CleanupDatabase(config.dbName);
    }

    void RunProcessWithMemoryConfig()
    {
        config.storageMode = OHOS::NativeRdb::StorageMode::MODE_MEMORY;
        auto store = CreateStore();
        EXPECT_NE(store, nullptr) << "Failed to create memory store";
        if (!store) {
            return;
        }
        OHOS::NativeRdb::ValuesBucket values = DatabaseHelper::CreateTestValues(config.dataName, config.age,
                                                                                config.salary, TEST_BLOB_DATA);
        DatabaseHelper::InsertTestData(store, values);
        EXPECT_TRUE(DatabaseHelper::VerifyData(store, config.dataName));

        // Memory databases don't need file deletion
        std::this_thread::sleep_for(std::chrono::milliseconds(PROCESS_CLEANUP_DELAY_MS));
    }

private:
    std::shared_ptr<OHOS::NativeRdb::RdbStore> CreateStore() const
    {
        int errCode = E_OK;
        OHOS::NativeRdb::RdbStoreConfig storeConfig(RDB_TEST_PATH + config.dbName);
        storeConfig.SetEncryptStatus(config.encryptStatus);
        storeConfig.SetBundleName(config.bundleName);
        storeConfig.SetStorageMode(config.storageMode);
        storeConfig.SetSecurityLevel(config.securityLevel);
        storeConfig.SetIsVector(config.isVector);

        if (!config.areaName.empty()) {
            storeConfig.SetArea(std::stoi(config.areaName));
        }

        DatabaseCallback helper;
        auto store = RdbHelper::GetRdbStore(storeConfig, 1, helper, errCode);

        if (errCode != E_OK && errCode != E_SQLITE_BUSY) {
            return nullptr;
        }
        if (store == nullptr) {
            return nullptr;
        }

        return store;
    }
};

class RdbMultiProcessCreateDBTest : public testing::Test {
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    void SetUp(){};
    void TearDown(){};
    static const std::string databaseName;
    static const std::string vectorDbName;
    static const std::string memoryDbName;
    static const std::string encryptedDbName;
    static const std::string notEncryptedDbName;
    static const std::string areaDbName;
    static const std::string sharedEncryptedLibName;
    static const std::string encryptedLib1Name;
    static const std::string encryptedLib2Name;
    static const std::string bundleTestDbName;
};

const std::string RdbMultiProcessCreateDBTest::databaseName = "multi_process_create_test.db";
const std::string RdbMultiProcessCreateDBTest::vectorDbName = "vector_test.db";
const std::string RdbMultiProcessCreateDBTest::memoryDbName = "shared_memory_test";
const std::string RdbMultiProcessCreateDBTest::encryptedDbName = "encrypted_test.db";
const std::string RdbMultiProcessCreateDBTest::notEncryptedDbName = "not_encrypted_test.db";
const std::string RdbMultiProcessCreateDBTest::areaDbName = "area_test.db";
const std::string RdbMultiProcessCreateDBTest::sharedEncryptedLibName = "shared_encrypted_lib.db";
const std::string RdbMultiProcessCreateDBTest::encryptedLib1Name = "encrypted_lib1.db";
const std::string RdbMultiProcessCreateDBTest::encryptedLib2Name = "encrypted_lib2.db";
const std::string RdbMultiProcessCreateDBTest::bundleTestDbName = "bundle_shared.db";

/**
 * @tc.name: Rdb_ConcurrentCreate_001
 * @tc.desc: Test two processes creating the same database concurrently using fork()
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_001, TestSize.Level1)
{
    int32_t initRet = RdbSecurityManager::GetInstance().Init("com.example.parent");
    EXPECT_EQ(initRet, E_OK);
    pid_t childPid = fork();

    if (childPid == 0) {
        // Child process
        DatabaseConfig childDbConfig{RdbMultiProcessCreateDBTest::databaseName, "com.example.child", ""};
        TestDataConfig childDataConfig{"child_process", TEST_AGE + 1, TEST_SALARY + 10.0};
        ProcessTest childTest(childDbConfig, childDataConfig, true);
        childTest.RunProcess();
        exit(0);
    } else if (childPid > 0) {
        // Parent process
        DatabaseConfig parentDbConfig{RdbMultiProcessCreateDBTest::databaseName, "com.example.parent", ""};
        TestDataConfig parentDataConfig{"parent_process", TEST_AGE, TEST_SALARY};
        ProcessTest parentTest(parentDbConfig, parentDataConfig, true);
        parentTest.RunProcess();
        int status;
        pid_t ret = waitpid(childPid, &status, 0);
        EXPECT_GT(ret, 0);
    } else {
        FAIL() << "Failed to create child process";
    }
}

/**
 * @tc.name: Rdb_ConcurrentCreate_Encrypted_002
 * @tc.desc: two processes create encrypted database at the same time
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_Encrypted_002, TestSize.Level1)
{
    int32_t initRet = RdbSecurityManager::GetInstance().Init("com.example.parent.encrypt");
    EXPECT_EQ(initRet, E_OK);
    pid_t childPid = fork();

    if (childPid == 0) {
        DatabaseConfig childDbConfig{encryptedDbName, "com.example.child.encrypt", ""};
        TestDataConfig childDataConfig{"encrypted_child", TEST_AGE + 2, TEST_SALARY + 20.0};
        ProcessTest childTest(childDbConfig, childDataConfig, true);
        childTest.RunProcess();
        exit(0);
    } else if (childPid > 0) {
        DatabaseConfig parentDbConfig{encryptedDbName, "com.example.parent.encrypt", ""};
        TestDataConfig parentDataConfig{"encrypted_parent", TEST_AGE, TEST_SALARY};
        ProcessTest parentTest(parentDbConfig, parentDataConfig, true);
        parentTest.RunProcess();
        int status;
        pid_t ret = waitpid(childPid, &status, 0);
        EXPECT_GT(ret, 0);
    } else {
        FAIL() << "Failed to create child process";
    }
}

/**
 * @tc.name: Rdb_ConcurrentCreate_NotEncrypted_003
 * @tc.desc: two processes create not encrypted database at the same time
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_NotEncrypted_003, TestSize.Level1)
{
    pid_t childPid = fork();

    if (childPid == 0) {
        DatabaseConfig childDbConfig{notEncryptedDbName, "com.example.child.notencrypt", ""};
        TestDataConfig childDataConfig{"not_encrypted_child", TEST_AGE + 3, TEST_SALARY + 30.0};
        ProcessTest childTest(childDbConfig, childDataConfig, false);
        childTest.RunProcess();
        exit(0);
    } else if (childPid > 0) {
        DatabaseConfig parentDbConfig{notEncryptedDbName, "com.example.parent.notencrypt", ""};
        TestDataConfig parentDataConfig{"not_encrypted_parent", TEST_AGE, TEST_SALARY};
        ProcessTest parentTest(parentDbConfig, parentDataConfig, false);
        parentTest.RunProcess();
        int status;
        pid_t ret = waitpid(childPid, &status, 0);
        EXPECT_GT(ret, 0);
    } else {
        FAIL() << "Failed to create child process";
    }
}

/**
 * @tc.name: Rdb_ConcurrentCreate_DifferentArea_004
 * @tc.desc: two processes with different areas create same database at the same time
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_DifferentArea_004, TestSize.Level1)
{
    int32_t initRet = RdbSecurityManager::GetInstance().Init("com.example.parent.area");
    EXPECT_EQ(initRet, E_OK);
    pid_t childPid = fork();

    if (childPid == 0) {
        DatabaseConfig childDbConfig{areaDbName, "com.example.child.area", "2"};
        TestDataConfig childDataConfig{"area_child", TEST_AGE + 4, TEST_SALARY + 40.0};
        ProcessTest childTest(childDbConfig, childDataConfig, true);
        childTest.RunProcess();
        exit(0);
    } else if (childPid > 0) {
        DatabaseConfig parentDbConfig{areaDbName, "com.example.parent.area", "1"};
        TestDataConfig parentDataConfig{"area_parent", TEST_AGE, TEST_SALARY};
        ProcessTest parentTest(parentDbConfig, parentDataConfig, true);
        parentTest.RunProcess();
        int status;
        pid_t ret = waitpid(childPid, &status, 0);
        EXPECT_GT(ret, 0);
    } else {
        FAIL() << "Failed to create child process";
    }
}

/**
 * @tc.name: Rdb_ConcurrentCreate_VectorDB_005
 * @tc.desc: two processes create vector database at the same time
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_VectorDB_005, TestSize.Level1)
{
    if (!RdbHelper::IsSupportArkDataDb()) {
        GTEST_SKIP() << "VectorDb is not supported, skipping test.";
    }

    int32_t initRet = RdbSecurityManager::GetInstance().Init("com.example.parent.vector");
    EXPECT_EQ(initRet, E_OK);
    pid_t childPid = fork();

    if (childPid == 0) {
        DatabaseConfig childDbConfig{vectorDbName, "com.example.child.vector", ""};
        TestDataConfig childDataConfig{"vector_child", TEST_AGE + 5, TEST_SALARY + 50.0};
        ProcessTest childTest(childDbConfig, childDataConfig, true);
        childTest.RunProcessWithVectorConfig();
        exit(0);
    } else if (childPid > 0) {
        DatabaseConfig parentDbConfig{vectorDbName, "com.example.parent.vector", ""};
        TestDataConfig parentDataConfig{"vector_parent", TEST_AGE, TEST_SALARY};
        ProcessTest parentTest(parentDbConfig, parentDataConfig, true);
        parentTest.RunProcessWithVectorConfig();
        int status;
        pid_t ret = waitpid(childPid, &status, 0);
        EXPECT_GT(ret, 0);
    } else {
        FAIL() << "Failed to create child process";
    }
}

/**
 * @tc.name: Rdb_ConcurrentCreate_MemoryDB_006
 * @tc.desc: Two processes create memory database at the same time
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_MemoryDB_006, TestSize.Level1)
{
    pid_t childPid = fork();

    if (childPid == 0) {
        DatabaseConfig childDbConfig{memoryDbName, "com.example.child.memory", ""};
        TestDataConfig childDataConfig{"memory_child", TEST_AGE + 6, TEST_SALARY + 60.0};
        ProcessTest childTest(childDbConfig, childDataConfig, false);
        childTest.RunProcessWithMemoryConfig();
        exit(0);
    } else if (childPid > 0) {
        DatabaseConfig parentDbConfig{memoryDbName, "com.example.parent.memory", ""};
        TestDataConfig parentDataConfig{"memory_parent", TEST_AGE, TEST_SALARY};
        ProcessTest parentTest(parentDbConfig, parentDataConfig, false);
        parentTest.RunProcessWithMemoryConfig();
        int status;
        pid_t ret = waitpid(childPid, &status, 0);
        EXPECT_GT(ret, 0);
    } else {
        FAIL() << "Failed to create child process";
    }
}

/**
 * @tc.name: Rdb_ConcurrentCreate_Encrypted_NotEncrypted_007
 * @tc.desc: parent process creates encrypted db, child process creates not encrypted db (same file)
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_Encrypted_NotEncrypted_007, TestSize.Level1)
{
    int32_t initRet = RdbSecurityManager::GetInstance().Init("com.example.parent.encdec");
    EXPECT_EQ(initRet, E_OK);
    pid_t childPid = fork();

    if (childPid == 0) {
        DatabaseConfig childDbConfig{sharedEncryptedLibName, "com.example.child.encdec", ""};
        TestDataConfig childDataConfig{"child_not_encrypted", TEST_AGE + 7, TEST_SALARY + 70.0};
        ProcessTest childTest(childDbConfig, childDataConfig, false);
        childTest.RunProcess();
        exit(0);
    } else if (childPid > 0) {
        DatabaseConfig parentDbConfig{sharedEncryptedLibName, "com.example.parent.encdec", ""};
        TestDataConfig parentDataConfig{"parent_encrypted", TEST_AGE, TEST_SALARY};
        ProcessTest parentTest(parentDbConfig, parentDataConfig, true);
        parentTest.RunProcess();
        int status;
        pid_t ret = waitpid(childPid, &status, 0);
        EXPECT_GT(ret, 0);
    } else {
        FAIL() << "Failed to create child process";
    }
}

/**
 * @tc.name: Rdb_ConcurrentCreate_Encrypted_Encrypted_008
 * @tc.desc: parent process creates encrypted db1, child process creates encrypted db2
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_Encrypted_Encrypted_008, TestSize.Level1)
{
    int32_t initRet = RdbSecurityManager::GetInstance().Init("com.example.parent.encrypt1");
    EXPECT_EQ(initRet, E_OK);
    pid_t childPid = fork();

    if (childPid == 0) {
        DatabaseConfig childDbConfig{encryptedLib2Name, "com.example.child.encrypt2", ""};
        TestDataConfig childDataConfig{"child_encrypted2", TEST_AGE + 8, TEST_SALARY + 80.0};
        ProcessTest childTest(childDbConfig, childDataConfig, true);
        childTest.RunProcess();
        exit(0);
    } else if (childPid > 0) {
        DatabaseConfig parentDbConfig{encryptedLib1Name, "com.example.parent.encrypt1", ""};
        TestDataConfig parentDataConfig{"parent_encrypted1", TEST_AGE, TEST_SALARY};
        ProcessTest parentTest(parentDbConfig, parentDataConfig, true);
        parentTest.RunProcess();
        int status;
        pid_t ret = waitpid(childPid, &status, 0);
        EXPECT_GT(ret, 0);
    } else {
        FAIL() << "Failed to create child process";
    }
}

/**
 * @tc.name: Rdb_ConcurrentCreate_BundleName_009
 * @tc.desc: two processes with different bundle names open same encrypted database
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_BundleName_009, TestSize.Level1)
{
    int32_t initRet = RdbSecurityManager::GetInstance().Init("com.example.parent.bundle");
    EXPECT_EQ(initRet, E_OK);
    pid_t childPid = fork();

    if (childPid == 0) {
        DatabaseConfig childDbConfig{bundleTestDbName, "com.example.child.bundle", ""};
        TestDataConfig childDataConfig{"child_bundle", TEST_AGE + 9, TEST_SALARY + 90.0};
        ProcessTest childTest(childDbConfig, childDataConfig, true);
        childTest.RunProcess();
        exit(0);
    } else if (childPid > 0) {
        DatabaseConfig parentDbConfig{bundleTestDbName, "com.example.parent.bundle", ""};
        TestDataConfig parentDataConfig{"parent_bundle", TEST_AGE, TEST_SALARY};
        ProcessTest parentTest(parentDbConfig, parentDataConfig, true);
        parentTest.RunProcess();
        int status;
        pid_t ret = waitpid(childPid, &status, 0);
        EXPECT_GT(ret, 0);
    } else {
        FAIL() << "Failed to create child process";
    }
}