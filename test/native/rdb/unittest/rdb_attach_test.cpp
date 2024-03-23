/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbAttachTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void QueryCheck1(std::shared_ptr<RdbStore> &store) const;
    void QueryCheck2(std::shared_ptr<RdbStore> &store) const;
    void DeleteCheck(std::shared_ptr<RdbStore> &store) const;
    void UpdateCheck(std::shared_ptr<RdbStore> &store) const;
    void InsertCheck(std::shared_ptr<RdbStore> &store) const;

    static constexpr const char *MAIN_DATABASE_NAME = "/data/test/main.db";
    static constexpr const char *ATTACHED_DATABASE_NAME = "/data/test/attached.db";
    static constexpr const char *ENCRYPT_ATTACHED_DATABASE_NAME = "/data/test/encrypt_attached.db";
    static constexpr int BUSY_TIMEOUT = 2;
};

class MainOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const MainOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test1(id INTEGER PRIMARY KEY "
                                                        "AUTOINCREMENT, name TEXT NOT NULL)";

int MainOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int MainOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

class AttachedOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const AttachedOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test2(id INTEGER PRIMARY KEY "
                                                            "AUTOINCREMENT, name TEXT NOT NULL)";

int AttachedOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int AttachedOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbAttachTest::SetUpTestCase(void)
{
    RdbStoreConfig attachedConfig(RdbAttachTest::ATTACHED_DATABASE_NAME);
    AttachedOpenCallback attachedHelper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> attachedStore = RdbHelper::GetRdbStore(attachedConfig, 1, attachedHelper, errCode);
    EXPECT_NE(attachedStore, nullptr);
}

void RdbAttachTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
    RdbHelper::DeleteRdbStore(ATTACHED_DATABASE_NAME);
}

void RdbAttachTest::SetUp(void)
{
}

void RdbAttachTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

/**
 * @tc.name: RdbStore_Attach_001
 * @tc.desc: test attach, attach is not supported in wal mode
 * @tc.type: FUNC
 */
HWTEST_F(RdbAttachTest, RdbStore_Attach_001, TestSize.Level1)
{
    RdbStoreConfig config(RdbAttachTest::MAIN_DATABASE_NAME);
    MainOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int ret = store->ExecuteSql("ATTACH '" + std::string(ATTACHED_DATABASE_NAME) + "' as attached");
    EXPECT_EQ(ret, E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE);
}

/**
 * @tc.name: RdbStore_Attach_002
 * @tc.desc: test RdbStore attach
 * @tc.type: FUNC
 */
HWTEST_F(RdbAttachTest, RdbStore_Attach_002, TestSize.Level1)
{
    RdbStoreConfig config(RdbAttachTest::MAIN_DATABASE_NAME);
    config.SetJournalMode(JournalMode::MODE_TRUNCATE);
    MainOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int ret = store->ExecuteSql("ATTACH DATABASE '" + std::string(ATTACHED_DATABASE_NAME) + "' as 'attached'");
    EXPECT_EQ(ret, E_OK);

    InsertCheck(store);

    QueryCheck1(store);

    ret = store->ExecuteSql("DETACH DATABASE 'attached'");
    EXPECT_EQ(ret, E_OK);

    QueryCheck2(store);

    ret = store->ExecuteSql("attach database '" + std::string(ATTACHED_DATABASE_NAME) + "' as 'attached'");
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteSql("detach database 'attached'");
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Attach_003
 * @tc.desc: Abnormal testCase for Attach
 * @tc.type: FUNC
 */
HWTEST_F(RdbAttachTest, RdbStore_Attach_003, TestSize.Level2)
{
    const std::string attachedName = "attached";
    RdbStoreConfig config(RdbAttachTest::MAIN_DATABASE_NAME);
    MainOpenCallback helper;
    int errCode = E_OK;

    // journal mode is wal
    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store1);
    EXPECT_EQ(E_OK, errCode);
    RdbStoreConfig attachedConfig(RdbAttachTest::ATTACHED_DATABASE_NAME);
    auto ret = store1->Attach(attachedConfig, attachedName, BUSY_TIMEOUT);
    EXPECT_EQ(E_OK, ret.first);
    EXPECT_EQ(1, ret.second);
    QueryCheck1(store1);
    // use the same attachedName to attach again
    ret = store1->Attach(attachedConfig, attachedName, BUSY_TIMEOUT);
    EXPECT_EQ(E_ATTACHED_DATABASE_EXIST, ret.first);

    ret = store1->Detach(attachedName);
    EXPECT_EQ(E_OK, ret.first);
    EXPECT_EQ(0, ret.second);
    QueryCheck2(store1);
}

/**
 * @tc.name: RdbStore_Attach_004
 * @tc.desc: Abnormal testCase for Attach with wrong path
 * @tc.type: FUNC
 */
HWTEST_F(RdbAttachTest, RdbStore_Attach_004, TestSize.Level2)
{
    const std::string attachedName = "attached";
    RdbStoreConfig config(RdbAttachTest::MAIN_DATABASE_NAME);
    MainOpenCallback helper;
    int errCode = E_OK;

    // journal mode is wal
    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store1);
    EXPECT_EQ(E_OK, errCode);
    RdbStoreConfig attachedConfig("/wrong/path");
    auto ret = store1->Attach(attachedConfig, attachedName, BUSY_TIMEOUT);
    EXPECT_EQ(E_INVALID_FILE_PATH, ret.first);
}

/**
 * @tc.name: RdbStore_Attach_005
 * @tc.desc: Abnormal testCase for Attach encrypted database
 * @tc.type: FUNC
 */
HWTEST_F(RdbAttachTest, RdbStore_Attach_005, TestSize.Level2)
{
    int errCode = E_OK;
    AttachedOpenCallback attachedHelper;
    RdbStoreConfig encryptAttachedConfig(RdbAttachTest::ENCRYPT_ATTACHED_DATABASE_NAME);
    encryptAttachedConfig.SetEncryptStatus(true);
    std::shared_ptr<RdbStore> encryptAttachedStore =
        RdbHelper::GetRdbStore(encryptAttachedConfig, 1, attachedHelper, errCode);
    EXPECT_NE(encryptAttachedStore, nullptr);

    encryptAttachedStore = nullptr;
    const std::string attachedName = "attached";
    RdbStoreConfig config(RdbAttachTest::MAIN_DATABASE_NAME);
    MainOpenCallback helper;

    // journal mode is wal
    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store1);
    EXPECT_EQ(E_OK, errCode);
    auto ret = store1->Attach(encryptAttachedConfig, attachedName, BUSY_TIMEOUT);
    EXPECT_EQ(E_OK, ret.first);
    EXPECT_EQ(1, ret.second);

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("lisi"));
    int res = store1->Insert(id, "test2", values);
    EXPECT_EQ(res, E_OK);
    EXPECT_EQ(id, 1);
    QueryCheck1(store1);

    ret = store1->Detach(attachedName);
    EXPECT_EQ(E_OK, ret.first);
    EXPECT_EQ(0, ret.second);
    QueryCheck2(store1);
    RdbHelper::DeleteRdbStore(RdbAttachTest::ENCRYPT_ATTACHED_DATABASE_NAME);
}

/**
 * @tc.name: RdbStore_Attach_006
 * @tc.desc: Abnormal testCase for Attach
 * @tc.type: FUNC
 */
HWTEST_F(RdbAttachTest, RdbStore_Attach_006, TestSize.Level2)
{
    const std::string attachedName = "attached";
    RdbStoreConfig config(RdbAttachTest::MAIN_DATABASE_NAME);
    MainOpenCallback helper;
    int errCode = E_OK;

    // journal mode is wal
    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store1);
    EXPECT_EQ(E_OK, errCode);
    RdbStoreConfig attachedConfig(RdbAttachTest::ATTACHED_DATABASE_NAME);
    auto ret = store1->Attach(attachedConfig, attachedName, BUSY_TIMEOUT);
    EXPECT_EQ(E_OK, ret.first);
    EXPECT_EQ(1, ret.second);

    UpdateCheck(store1);
    DeleteCheck(store1);

    ret = store1->Detach(attachedName);
    EXPECT_EQ(E_OK, ret.first);
    EXPECT_EQ(0, ret.second);
}

void RdbAttachTest::QueryCheck1(std::shared_ptr<RdbStore> &store) const
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test1");
    EXPECT_NE(resultSet, nullptr);
    int ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    int columnIndex;
    int intVal;
    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(intVal, 1);
    std::string strVal;
    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(strVal, "zhangsan");

    resultSet = store->QuerySql("SELECT * FROM test2");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(intVal, 1);
    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(strVal, "lisi");
}

void RdbAttachTest::QueryCheck2(std::shared_ptr<RdbStore> &store) const
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test1");
    EXPECT_NE(resultSet, nullptr);
    int ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    int columnIndex;
    int intVal;
    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(intVal, 1);
    std::string strVal;
    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(strVal, "zhangsan");

    // detached, no table test2
    resultSet = store->QuerySql("SELECT * FROM test2");
    EXPECT_NE(resultSet, nullptr);
}

void RdbAttachTest::DeleteCheck(std::shared_ptr<RdbStore> &store) const
{
    int changedRows = 0;
    AbsRdbPredicates predicates("test1");
    predicates.EqualTo("id", 1);
    int ret = store->Delete(changedRows, predicates);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(changedRows, 1);

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test1 where name = 'lisi_update1'");
    EXPECT_NE(resultSet, nullptr);
    int count = 0;
    resultSet->GetRowCount(count);
    EXPECT_EQ(0, count);

    int changedRows2 = 0;
    AbsRdbPredicates predicates2("test2");
    predicates2.EqualTo("id", 1);
    ret = store->Delete(changedRows2, predicates2);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(changedRows2, 1);

    std::shared_ptr<ResultSet> resultSet2 =
        store->QuerySql("SELECT * FROM test2 where name = 'lisi_update2'");
    EXPECT_NE(resultSet2, nullptr);
    int count2 = 0;
    resultSet2->GetRowCount(count2);
    EXPECT_EQ(0, count2);
}

void RdbAttachTest::UpdateCheck(std::shared_ptr<RdbStore> &store) const
{
    int changedRows = 0;
    ValuesBucket values;
    values.PutString("name", std::string("lisi_update1"));
    AbsRdbPredicates predicates("test1");
    predicates.EqualTo("id", 1);
    int ret = store->Update(changedRows, values, predicates);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(changedRows, 1);

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test1 where name = 'lisi_update1'");
    EXPECT_NE(resultSet, nullptr);
    int count = 0;
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);

    values.Clear();
    values.PutString("name", std::string("lisi_update2"));
    AbsRdbPredicates predicates2("test2");
    predicates2.EqualTo("id", 1);
    int changedRows2 = 0;
    ret = store->Update(changedRows2, values, predicates2);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(changedRows2, 1);

    std::shared_ptr<ResultSet> resultSet2 =
        store->QuerySql("SELECT * FROM test2 where name = 'lisi_update2'");
    EXPECT_NE(resultSet2, nullptr);
    int count2 = 0;
    resultSet2->GetRowCount(count2);
    EXPECT_EQ(1, count2);
}

void RdbAttachTest::InsertCheck(std::shared_ptr<RdbStore> &store) const
{
    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    int ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("lisi"));
    ret = store->Insert(id, "test2", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);
}
