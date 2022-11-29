/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import dataRdb from '@ohos.data.rdb';

const DEPT_TABLE = "CREATE TABLE IF NOT EXISTS dept"
    + "(id INTEGER PRIMARY KEY , dName TEXT , loc TEXT)";

const JOB_TABLE = "CREATE TABLE IF NOT EXISTS job"
    + "(id INTEGER PRIMARY KEY , jName TEXT , description TEXT)";

const EMP_TABLE = "CREATE TABLE IF NOT EXISTS emp"
    + "(id INTEGER PRIMARY KEY ,eName TEXT, jobId INTEGER , "
    + "mgr INTEGER, joinDate TEXT, salary REAL, bonus REAL, deptId INTEGER,"
    + "FOREIGN KEY (jobId) REFERENCES job (id) ON UPDATE NO ACTION ON DELETE CASCADE,"
    + "FOREIGN KEY (deptId) REFERENCES dept (id) ON UPDATE NO ACTION ON DELETE CASCADE)";

const SALARYGRADE_TABLE = "CREATE TABLE IF NOT EXISTS salarygrade"
    + "(grade INTEGER PRIMARY KEY,loSalary INTEGER, hiSalary INTEGER)";

const STORE_CONFIG = { name: "RdbJoinBTest.db" }

const CURRENT_STORE_VERSION = 1;

const TAG = 'RDB_TEST';

var rdbStore = undefined;

describe('rdbStorePredicatesJoinBTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll');
        console.info(TAG + 'beforeAll end');
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach');
        rdbStore = await dataRdb.getRdbStore(STORE_CONFIG, CURRENT_STORE_VERSION);
        await generateJobTable();
        await generateSalarygradeTable();
        await generateDeptTable();
        await generateEmpTable();
        console.info(TAG + 'beforeEach end');
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach');
        await dataRdb.deleteRdbStore("RdbJoinBTest.db");
        rdbStore = null;
        console.info(TAG + 'afterEach end');
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll');
        console.info(TAG + 'afterAll end');
    })

    async function generateDeptTable() {
        console.info(TAG + 'generateDeptTable');
        await rdbStore.executeSql(DEPT_TABLE);

        const depts = [
            {id:10, dName:"JiaoYanBU", loc:"BeiJing"},
            {id:20, dName:"XueGongBu", loc:"ShangHai"},
            {id:30, dName:"XiaoShouBu", loc:"GuangZhou"},
            {id:40, dName:"CaiWuBu", loc:"ShenZhen"},
        ];

        rdbStore.batchInsert("dept", depts);
        console.info(TAG + 'generateDeptTable end');
    }

    async function generateJobTable() {
        console.info(TAG + 'generateJobTable')
        await rdbStore.executeSql(JOB_TABLE);

        var jobs = [
            {id:1, jName:"Chairman", description:"ManageTheEntireCompany"},
            {id:2, jName:"Manager", description:"ManageEmployeesOfTheDepartment"},
            {id:3, jName:"Salesperson", description:"SellingProductsToCustomers"},
            {id:4, jName:"Clerk", description:"UseOfficeSoftware"},
        ]

        rdbStore.batchInsert("job", jobs);
        console.info(TAG + 'generateJobTable end')
    }

    async function generateEmpTable() {
        console.info(TAG + 'generateEmpTable')
        await rdbStore.executeSql(EMP_TABLE);

        var emps = [
            {id:1001, eName:"SunWuKong", jobId:4, mgr:1004, joinDate:"2000-12-17", salary:8000.00, bonus:null, deptId:20},
            {id:1002, eName:"LuJunYi", jobId:3, mgr:1006, joinDate:"2001-02-20", salary:16000.00, bonus:3000.00, deptId:30},
            {id:1003, eName:"LinChong", jobId:3, mgr:1006, joinDate:"2001-02-22", salary:12500.00, bonus:5000.00, deptId:30},
            {id:1004, eName:"TangCeng", jobId:2, mgr:1009, joinDate:"2001-04-02", salary:29750.00, bonus:null, deptId:20},
            {id:1005, eName:"LiKui", jobId:4, mgr:1006, joinDate:"2001-09-28", salary:12500.00, bonus:14000.00, deptId:30},
            {id:1006, eName:"SongJiang", jobId:2, mgr:1009, joinDate:"2001-05-01", salary:28500.00, bonus:null, deptId:30},
            {id:1007, eName:"LiuBei", jobId:2, mgr:1009, joinDate:"2001-09-01", salary:24500.00, bonus:null, deptId:10},
            {id:1008, eName:"ZhuBaJie", jobId:4, mgr:1004, joinDate:"2007-04-19", salary:30000.00, bonus:null, deptId:20},
            {id:1009, eName:"LuoGuanZhong", jobId:1, mgr:null, joinDate:"2001-11-17", salary:50000.00, bonus:null, deptId:10},
            {id:1010, eName:"WuYong", jobId:3, mgr:1006, joinDate:"2001-09-08", salary:15000.00, bonus:0.00, deptId:30},
            {id:1011, eName:"ShaCeng", jobId:4, mgr:1004, joinDate:"2007-05-23", salary:11000.00, bonus:null, deptId:20},
            {id:1012, eName:"LiKui", jobId:4, mgr:1006, joinDate:"2001-12-03", salary:9500.00, bonus:null, deptId:30},
            {id:1013, eName:"XiaoBaiLong", jobId:4, mgr:1004, joinDate:"2001-12-03", salary:30000.00, bonus:null, deptId:20},
            {id:1014, eName:"GuanYu", jobId:4, mgr:1007, joinDate:"2002-01-23", salary:13000.00, bonus:null, deptId:10},
        ];

        rdbStore.batchInsert("emp", emps);
        console.info(TAG + 'generateEmpTable end');
    }


    async function generateSalarygradeTable() {
        console.info(TAG + 'generateSalarygradeTable')
        await rdbStore.executeSql(SALARYGRADE_TABLE);

        var salarygrades = [
            {grade:1, loSalary:7000, hiSalary:12000},
            {grade:2, loSalary:12010, hiSalary:14000},
            {grade:3, loSalary:14010, hiSalary:20000},
            {grade:4, loSalary:20010, hiSalary:30000},
            {grade:5, loSalary:30010, hiSalary:99990},
        ];

        rdbStore.batchInsert("salarygrade", salarygrades);
        console.info(TAG + 'generateSalarygradeTable end')
    }

    console.log(TAG + "*************Unit Test Begin*************");
    /**
     * @tc.name: testRdbJoinB001
     * @tc.desc: normal testcase of Rdb_Cross_Join
     * @tc.type: FUNC
     * @tc.require: I4NZP6
     */
    it('testRdbJoinB001', 0, async function (done) {
        console.log(TAG + "testRdbJoinB001 begin.");
        let resultSet = await rdbStore.querySql(
            "SELECT * FROM emp CROSS JOIN dept ON emp.deptId = dept.id");

        expect(14).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect(1001).assertEqual(resultSet.getInt(0));
        expect("SunWuKong").assertEqual(resultSet.getString(1));
        expect(4).assertEqual(resultSet.getInt(2));
        expect(1004).assertEqual(resultSet.getInt(3));
        expect("2000-12-17").assertEqual(resultSet.getString(4));
        expect(8000.00).assertEqual(resultSet.getDouble(5));
        expect(true).assertEqual(resultSet.isColumnNull(6));
        expect(20).assertEqual(resultSet.getInt(7));
        expect(20).assertEqual(resultSet.getInt(8));
        expect("XueGongBu").assertEqual(resultSet.getString(9));
        expect("ShangHai").assertEqual(resultSet.getString(10));
        done();
    })

    /**
     * @tc.name: testRdbJoinB002
     * @tc.desc: normal testcase of Rdb_Inner_Join
     * @tc.type: FUNC
     * @tc.require: I4NZP6
     */
    it('testRdbJoinB002', 0, async function (done) {
        console.log(TAG + "testRdbJoinB002 begin.");
        let resultSet = await rdbStore.querySql(
            "SELECT  t1.id, t1.eName, t1.salary, t2.jName, t2.description FROM emp t1 INNER JOIN  job t2 ON t1.`jobId` = t2.`id` WHERE t1.eName = 'SunWuKong'")

        expect(1).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect(1001).assertEqual(resultSet.getInt(0));
        expect("SunWuKong").assertEqual(resultSet.getString(1));
        expect(8000.00).assertEqual(resultSet.getDouble(2));
        expect("Clerk").assertEqual(resultSet.getString(3));
        expect("UseOfficeSoftware").assertEqual(resultSet.getString(4));
        done();
    })


    /**
     * @tc.name: testRdbJoinB003
     * @tc.desc: normal testcase of Rdb_Inner_Join
     * @tc.type: FUNC
     * @tc.require: I4NZP6
     */
    it('testRdbJoinB003', 0, async function (done) {
        console.log(TAG + "testRdbJoinB003 begin.");
        let resultSet = await rdbStore.querySql(
            "SELECT  t1.eName, t1.salary, t2.* FROM emp t1 INNER JOIN salarygrade t2 WHERE t1.salary BETWEEN t2.losalary AND t2.hisalary")

        expect(14).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect("SunWuKong").assertEqual(resultSet.getString(0));
        expect(8000.00).assertEqual(resultSet.getDouble(1));
        expect(1).assertEqual(resultSet.getInt(2));
        expect(7000).assertEqual(resultSet.getInt(3));
        expect(12000).assertEqual(resultSet.getInt(4));
        done();
    })

    /**
     * @tc.name: testRdbJoinB004
     * @tc.desc: normal testcase of Rdb_Inner_Join
     * @tc.type: FUNC
     * @tc.require: I4NZP6
     */
    it('testRdbJoinB004', 0, async function (done) {
        console.log(TAG + "testRdbJoinB004 begin.");
        let resultSet = await rdbStore.querySql(
            "SELECT t1.eName, t1.salary, t2.jName, t2.description, t3.dName, t3.loc, t4.grade FROM emp t1 INNER JOIN job t2 INNER JOIN dept t3 "
            + "INNER JOIN salarygrade t4 ON t1.jobId = t2.id AND t1.deptId = t3.id AND t1.salary BETWEEN t4.loSalary AND t4.hiSalary");

        expect(14).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect("SunWuKong").assertEqual(resultSet.getString(0));
        expect(8000.00).assertEqual(resultSet.getDouble(1));
        expect("Clerk").assertEqual(resultSet.getString(2));
        expect("UseOfficeSoftware").assertEqual(resultSet.getString(3));
        expect("XueGongBu").assertEqual(resultSet.getString(4));
        expect("ShangHai").assertEqual(resultSet.getString(5));
        expect(1).assertEqual(resultSet.getInt(6));
        done();
    })

    /**
     * @tc.name: testRdbJoinB005
     * @tc.desc: normal testcase of Rdb_Left_Outer_Join
     * @tc.type: FUNC
     * @tc.require: I4NZP6
     */
    it('testRdbJoinB005', 0, async function (done) {
        console.log(TAG + "testRdbJoinB005 begin.");
        let resultSet = await rdbStore.querySql(
            "SELECT t1.eName, t1.mgr, t2.id, t2.eName FROM emp t1 LEFT OUTER JOIN emp t2 ON t1.mgr = t2.id");

        expect(14).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect("SunWuKong").assertEqual(resultSet.getString(0));
        expect(1004).assertEqual(resultSet.getInt(1));
        expect(1004).assertEqual(resultSet.getInt(2));
        expect("TangCeng").assertEqual(resultSet.getString(3));
        done();
    })

    console.log(TAG + "*************Unit Test End*************");
})