/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <ctime>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "abs_predicates.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

constexpr int CYCLENUM = 13;

class RdbStorePredicateJoinBTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void GenerateAllTables();
    void InsertDeptDates();
    void InsertJobDates();
    void InsertEmpDates();
    void InsertSalarygradeDates();
    int ResultSize(std::shared_ptr<ResultSet> &resultSet);

    static const std::string DATABASE_NAME;

protected:
    std::shared_ptr<RdbStore> store_;
};

const std::string RdbStorePredicateJoinBTest::DATABASE_NAME = RDB_TEST_PATH + "predicates_join_b_test.db";

const std::string CREATE_TABLE_DEPT_SQL = std::string("CREATE TABLE IF NOT EXISTS dept ") +
      std::string("(id INTEGER PRIMARY KEY , dName TEXT , loc TEXT)");
const std::string CREATE_TABLE_JOB_SQL = std::string("CREATE TABLE IF NOT EXISTS job ") +
      std::string("(id INTEGER PRIMARY KEY , jName TEXT , description TEXT)");
const std::string CREATE_TABLE_EMP_SQL = std::string("CREATE TABLE IF NOT EXISTS emp ") +
      std::string("(id INTEGER PRIMARY KEY ,eName TEXT, jobId INTEGER , ") +
      std::string("mgr INTEGER, joinDate TEXT, salary REAL, bonus REAL, deptId INTEGER,") +
      std::string("FOREIGN KEY (jobId) REFERENCES job (id) ON UPDATE NO ACTION ON DELETE CASCADE,") +
      std::string("FOREIGN KEY (deptId) REFERENCES dept (id) ON UPDATE NO ACTION ON DELETE CASCADE)");
const std::string CREATE_TABLE_SALARYGRADE_SQL = std::string("CREATE TABLE IF NOT EXISTS salarygrade") +
      std::string("(grade INTEGER PRIMARY KEY,loSalary INTEGER, hiSalary INTEGER)");


class PredicateJoinBTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};


int PredicateJoinBTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int PredicateJoinBTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStorePredicateJoinBTest::SetUpTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbStorePredicateJoinBTest::DATABASE_NAME);
}

void RdbStorePredicateJoinBTest::TearDownTestCase(void) {}

void RdbStorePredicateJoinBTest::SetUp(void)
{
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(RdbStorePredicateJoinBTest::DATABASE_NAME);
    int errCode = E_OK;
    RdbStoreConfig config(RdbStorePredicateJoinBTest::DATABASE_NAME);
    PredicateJoinBTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store_, nullptr);
    RdbStorePredicateJoinBTest::GenerateAllTables();
}

void RdbStorePredicateJoinBTest::TearDown(void)
{
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(RdbStorePredicateJoinBTest::DATABASE_NAME);
}

void RdbStorePredicateJoinBTest::GenerateAllTables()
{
    store_->ExecuteSql(CREATE_TABLE_DEPT_SQL);
    RdbStorePredicateJoinBTest::InsertDeptDates();

    store_->ExecuteSql(CREATE_TABLE_JOB_SQL);
    RdbStorePredicateJoinBTest::InsertJobDates();

    store_->ExecuteSql(CREATE_TABLE_EMP_SQL);
    RdbStorePredicateJoinBTest::InsertEmpDates();

    store_->ExecuteSql(CREATE_TABLE_SALARYGRADE_SQL);
    RdbStorePredicateJoinBTest::InsertSalarygradeDates();
}

void RdbStorePredicateJoinBTest::InsertDeptDates()
{
    int64_t  id;
    ValuesBucket values;

    values.PutInt("id", 10);
    values.PutString("dName", std::string("JiaoYanBU"));
    values.PutString("loc", std::string("BeiJing"));
    store_->Insert(id, "dept", values);

    values.Clear();
    values.PutInt("id", 20);
    values.PutString("dName", std::string("XueGongBu"));
    values.PutString("loc", std::string("ShangHai"));
    store_->Insert(id, "dept", values);

    values.Clear();
    values.PutInt("id", 30);
    values.PutString("dName", std::string("XiaoShouBu"));
    values.PutString("loc", std::string("GuangZhou"));
    store_->Insert(id, "dept", values);

    values.Clear();
    values.PutInt("id", 40);
    values.PutString("dName", std::string("CaiWuBu"));
    values.PutString("loc", std::string("ShenZhen"));
    store_->Insert(id, "dept", values);
}

void RdbStorePredicateJoinBTest::InsertJobDates()
{
    int64_t  id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("jName", std::string("Chairman"));
    values.PutString("description", std::string("ManageTheEntireCompany"));
    store_->Insert(id, "job", values);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("jName", std::string("Manager"));
    values.PutString("description", std::string("ManageEmployeesOfTheDepartment"));
    store_->Insert(id, "job", values);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("jName", std::string("Salesperson"));
    values.PutString("description", std::string("SellingProductsToCustomers"));
    store_->Insert(id, "job", values);

    values.Clear();
    values.PutInt("id", 4);
    values.PutString("jName", std::string("Clerk"));
    values.PutString("description", std::string("UseOfficeSoftware"));
    store_->Insert(id, "job", values);
}

void RdbStorePredicateJoinBTest::InsertEmpDates()
{
    int64_t id;

    int ret = 0;
    for (int i = 0; i <= CYCLENUM; i++) {
        ret = store_->Insert(id, "emp", UTUtils::SetRowDatas(UTUtils::gRowDatas[i]));
    }
    EXPECT_EQ(ret, E_OK);
}

void RdbStorePredicateJoinBTest::InsertSalarygradeDates()
{
    int64_t  id;
    ValuesBucket values;

    values.PutInt("grade", 1);
    values.PutInt("loSalary", 7000);
    values.PutInt("hiSalary", 12000);
    store_->Insert(id, "salarygrade", values);

    values.Clear();
    values.PutInt("grade", 2);
    values.PutInt("loSalary", 12010);
    values.PutInt("hiSalary", 14000);
    store_->Insert(id, "salarygrade", values);

    values.Clear();
    values.PutInt("grade", 3);
    values.PutInt("loSalary", 14010);
    values.PutInt("hiSalary", 20000);
    store_->Insert(id, "salarygrade", values);

    values.Clear();
    values.PutInt("grade", 4);
    values.PutInt("loSalary", 20010);
    values.PutInt("hiSalary", 30000);
    store_->Insert(id, "salarygrade", values);

    values.Clear();
    values.PutInt("grade", 5);
    values.PutInt("loSalary", 30010);
    values.PutInt("hiSalary", 99990);
    store_->Insert(id, "salarygrade", values);
}

int RdbStorePredicateJoinBTest::ResultSize(std::shared_ptr<ResultSet> &resultSet)
{
    if (resultSet->GoToFirstRow() != E_OK) {
        return 0;
    }
    int count;
    resultSet->GetRowCount(count);
    return count;
}

/* *
 * @tc.name: RdbStore_InnerJoinB_001
 * @tc.desc: Normal testCase of RdbPredicates for CrossJoin
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateJoinBTest, RdbStore_CrossJoinB_001, TestSize.Level1)
{
    RdbPredicates predicates("emp");

    std::vector<std::string> clauses;
    clauses.push_back("emp.deptId = dept.id");
    predicates.CrossJoin("dept")->On(clauses);

    std::vector<std::string> joinTypes;
    joinTypes.push_back("CROSS JOIN");

    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());
    EXPECT_EQ("dept", predicates.GetJoinTableNames()[0]);
    EXPECT_EQ("ON(emp.deptId = dept.id)", predicates.GetJoinConditions()[0]);
    EXPECT_EQ("CROSS JOIN dept ON(emp.deptId = dept.id)", predicates.GetJoinClause());

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = store_->Query(predicates, columns);
    EXPECT_EQ(14, ResultSize(allDataTypes));

    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());

    int id;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(0, id));
    EXPECT_EQ(1001, id);

    std::string eName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(1, eName));
    EXPECT_EQ("SunWuKong", eName);

    int jobId;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(2, jobId));
    EXPECT_EQ(4, jobId);

    int mgr;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(3, mgr));
    EXPECT_EQ(1004, mgr);

    std::string joinDate;
    EXPECT_EQ(E_OK, allDataTypes->GetString(4, joinDate));
    EXPECT_EQ("2000-12-17", joinDate);

    double salary;
    EXPECT_EQ(E_OK, allDataTypes->GetDouble(5, salary));
    EXPECT_EQ(8000.00, salary);

    bool bonus;
    EXPECT_EQ(E_OK, allDataTypes->IsColumnNull(6, bonus));
    EXPECT_EQ(true, bonus);

    int deptId;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(7, deptId));
    EXPECT_EQ(20, deptId);

    int id_1;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(8, id_1));
    EXPECT_EQ(20, id_1);

    std::string dName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(9, dName));
    EXPECT_EQ("XueGongBu", dName);

    std::string loc;
    EXPECT_EQ(E_OK, allDataTypes->GetString(10, loc));
    EXPECT_EQ("ShangHai", loc);
}

/* *
 * @tc.name: RdbStore_InnerJoinB_002
 * @tc.desc: Normal testCase of RdbPredicates for InnerJoin
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateJoinBTest, RdbStore_InnerJoinB_002, TestSize.Level1)
{
    RdbPredicates predicates("emp t1");

    std::vector<std::string> clauses;
    clauses.push_back("t1.jobId = t2.id");
    predicates.InnerJoin("job t2")->On(clauses)->EqualTo("t1.eName", "SunWuKong");

    std::vector<std::string> joinTypes;
    joinTypes.push_back("INNER JOIN");
    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());
    EXPECT_EQ("ON(t1.jobId = t2.id)", predicates.GetJoinConditions()[0]);

    std::vector<std::string> columns;
    columns.push_back("t1.id");
    columns.push_back("t1.eName");
    columns.push_back("t1.salary");
    columns.push_back("t2.jName");
    columns.push_back("t2.description");
    std::shared_ptr<ResultSet> allDataTypes = store_->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());

    int id;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(0, id));
    EXPECT_EQ(1001, id);

    std::string eName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(1, eName));
    EXPECT_EQ("SunWuKong", eName);

    double salary;
    EXPECT_EQ(E_OK, allDataTypes->GetDouble(2, salary));
    EXPECT_EQ(8000.00, salary);

    std::string jName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(3, jName));
    EXPECT_EQ("Clerk", jName);

    std::string description;
    EXPECT_EQ(E_OK, allDataTypes->GetString(4, description));
    EXPECT_EQ("UseOfficeSoftware", description);
}

/* *
 * @tc.name: RdbStore_InnerJoinB_003
 * @tc.desc: Normal testCase of RdbPredicates for InnerJoin
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateJoinBTest, RdbStore_InnerJoinB_003, TestSize.Level1)
{
    RdbPredicates predicates("emp t1");

    std::vector<std::string> clauses;
    clauses.push_back("t1.salary BETWEEN t2.losalary AND t2.hisalary");
    predicates.InnerJoin("salarygrade t2")->On(clauses);

    std::vector<std::string> joinTypes;
    joinTypes.push_back("INNER JOIN");
    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());

    std::vector<std::string> columns;
    columns.push_back("t1.eName");
    columns.push_back("t1.salary");
    columns.push_back("t2.*");
    std::shared_ptr<ResultSet> allDataTypes = store_->Query(predicates, columns);
    EXPECT_EQ(14, ResultSize(allDataTypes));
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());

    std::string eName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(0, eName));
    EXPECT_EQ("SunWuKong", eName);

    double salary;
    EXPECT_EQ(E_OK, allDataTypes->GetDouble(1, salary));
    EXPECT_EQ(8000.00, salary);

    int grade;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(2, grade));
    EXPECT_EQ(1, grade);

    int loSalary;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(3, loSalary));
    EXPECT_EQ(7000, loSalary);

    int hiSalary;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(4, hiSalary));
    EXPECT_EQ(12000, hiSalary);
}


/* *
 * @tc.name: RdbStore_InnerJoinB_004
 * @tc.desc: Normal testCase of RdbPredicates for InnerJoin
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateJoinBTest, RdbStore_InnerJoinB_004, TestSize.Level1)
{
    RdbPredicates predicates("emp t1");

    std::vector<std::string> clauses;
    clauses.push_back("t1.jobId = t2.id");
    clauses.push_back("t1.deptId = t3.id");
    clauses.push_back("t1.salary BETWEEN t4.losalary AND t4.hisalary");
    predicates.InnerJoin("job t2")->InnerJoin("dept t3")->InnerJoin("salarygrade t4")->On(clauses);

    std::vector<std::string> joinTypes;
    joinTypes.push_back("INNER JOIN");
    joinTypes.push_back("INNER JOIN");
    joinTypes.push_back("INNER JOIN");
    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());
    EXPECT_EQ("", predicates.GetJoinConditions()[0]);
    EXPECT_EQ("", predicates.GetJoinConditions()[1]);
    EXPECT_EQ("ON(t1.jobId = t2.id AND t1.deptId = t3.id AND t1.salary BETWEEN "
              "t4.losalary AND t4.hisalary)",
              predicates.GetJoinConditions()[2]);

    std::vector<std::string> columns;
    columns.push_back("t1.eName");
    columns.push_back("t1.salary");
    columns.push_back("t2.jName");
    columns.push_back("t2.description");
    columns.push_back("t3.dName");
    columns.push_back("t3.loc");
    columns.push_back("t4.grade");
    std::shared_ptr<ResultSet> allDataTypes = store_->Query(predicates, columns);
    EXPECT_EQ(14, ResultSize(allDataTypes));
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());

    std::string eName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(0, eName));
    EXPECT_EQ("SunWuKong", eName);

    double salary;
    EXPECT_EQ(E_OK, allDataTypes->GetDouble(1, salary));
    EXPECT_EQ(8000.00, salary);

    std::string jName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(2, jName));
    EXPECT_EQ("Clerk", jName);

    std::string description;
    EXPECT_EQ(E_OK, allDataTypes->GetString(3, description));
    EXPECT_EQ("UseOfficeSoftware", description);

    std::string dName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(4, dName));
    EXPECT_EQ("XueGongBu", dName);

    std::string loc;
    EXPECT_EQ(E_OK, allDataTypes->GetString(5, loc));
    EXPECT_EQ("ShangHai", loc);

    int grade;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(6, grade));
    EXPECT_EQ(1, grade);
}


/* *
 * @tc.name: RdbStore_LeftOuterJoinB_005
 * @tc.desc: Normal testCase of RdbPredicates for LeftOuterJoin
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateJoinBTest, RdbStore_LeftOuterJoinB_005, TestSize.Level1)
{
    RdbPredicates predicates("emp t1");

    std::vector<std::string> clauses;
    clauses.push_back("t1.mgr = t2.id");
    std::vector<std::string> joinTypes;
    joinTypes.push_back("LEFT OUTER JOIN");

    predicates.LeftOuterJoin("emp t2")->On(clauses);
    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());
    EXPECT_EQ("ON(t1.mgr = t2.id)", predicates.GetJoinConditions()[0]);

    std::vector<std::string> columns;
    columns.push_back("t1.eName");
    columns.push_back("t1.mgr");
    columns.push_back("t2.id");
    columns.push_back("t2.eName");
    std::shared_ptr<ResultSet> allDataTypes = store_->Query(predicates, columns);
    EXPECT_EQ(14, ResultSize(allDataTypes));
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());

    std::string eName;
    EXPECT_EQ(E_OK, allDataTypes->GetString(0, eName));
    EXPECT_EQ("SunWuKong", eName);

    int mgr;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(1, mgr));
    EXPECT_EQ(1004, mgr);

    int id;
    EXPECT_EQ(E_OK, allDataTypes->GetInt(2, id));
    EXPECT_EQ(1004, id);

    std::string eName_1;
    EXPECT_EQ(E_OK, allDataTypes->GetString(3, eName_1));
    EXPECT_EQ("TangCeng", eName_1);
}
