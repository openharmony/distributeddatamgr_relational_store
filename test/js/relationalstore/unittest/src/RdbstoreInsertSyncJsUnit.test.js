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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import data_relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "InsertTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}

var rdbStore = undefined
var context = ability_featureAbility.getContext()

describe('rdbStoreInsertSyncTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        await rdbStore.executeSql("DELETE FROM test");
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "InsertTest.db");
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0001
     * @tc.name Normal test case of insert
     * @tc.desc 1.Insert data
     *          2.Query data
     */
    it('testSyncRdbStoreInsert0001', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreInsert0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 20,
                "salary": 100.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket)
        }

        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("name", "zhangsan")
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "resultSet query done");
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            const age = resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
            console.log(TAG + "id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
            expect(1).assertEqual(id);
            expect("zhangsan").assertEqual(name)
            expect(18).assertEqual(age)
            expect(100.5).assertEqual(salary)
            expect(1).assertEqual(blobType[0])
            expect(2).assertEqual(blobType[1])
            expect(3).assertEqual(blobType[2])
            expect(false).assertEqual(resultSet.goToNextRow())
        } catch (e) {
            console.log("insert1 error " + e);
        }
        resultSet.close()
        resultSet = null
        done()
        console.log(TAG + "************* testSyncRdbStoreInsert0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0002
     * @tc.name Abnormal test case of insert, if TABLE name is wrong
     * @tc.desc 1.Create value
     *          2.Execute insert (with wrong table)
     */
    it('testSyncRdbStoreInsert0002', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreInsert0002 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = rdbStore.insertSync("wrong", valueBucket);
            expect(null).assertFail()
        } catch (e) {
            console.log(TAG + `insert with wrong table ${e.code}, ${e.message}`);
            expect(14800021).assertEqual(e.code)
        }
        done()
        console.log(TAG + "************* testSyncRdbStoreInsert0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0003
     * @tc.name Abnormal test case of insert, if TABLE name is null
     * @tc.desc 1.Create value
     *          2.Execute insert (with null table)
     */
    it('testSyncRdbStoreInsert0003', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreInsert0003 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            try {
                let ret = rdbStore.insertSync(null, valueBucket);
                expect(null).assertFail()
            } catch (err) {
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
                expect("401").assertEqual(err.code)
                done()
            }
        }
        done()
        console.log(TAG + "************* testSyncRdbStoreInsert0003 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0004
     * @tc.name Normal test case of insert (long string and special characters)
     * @tc.desc 1.Insert data
     *          2.Configure predicates
     *          3.Query data
     */
    it('testSyncRdbStoreInsert0004', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreInsert0004 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var nameStr = "abcd" + "e".repeat(2000) + "./&*$!@()"
        const valueBucket = {
            "name": nameStr,
            "age": 19,
            "salary": 100.5,
            "blobType": u8,
        }
        rdbStore.insertSync("test", valueBucket);

        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("age", 19)
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "resultSet query done");
            expect(true).assertEqual(resultSet.goToFirstRow())
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            console.log(TAG + "id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
            expect(nameStr).assertEqual(name)
        } catch (e) {
            console.log("insert error " + e);
        }
        resultSet.close()
        resultSet = null
        done()
        console.log(TAG + "************* testSyncRdbStoreInsert0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0005
     * @tc.name Normal test case of insert (Chinese and long string)
     * @tc.desc 1.Insert data
     *          2.Configure predicates
     *          3.Query data
     */
    it('testSyncRdbStoreInsert0005', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreInsert0005 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var nameStr = "苹果是水果" + "e".repeat(2000)
        const valueBucket = {
            "name": nameStr,
            "age": 20,
            "salary": 100.5,
            "blobType": u8,
        }
        rdbStore.insertSync("test", valueBucket
        )

        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("age", 20)
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "resultSet query done");
            expect(true).assertEqual(resultSet.goToFirstRow())
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            console.log(TAG + "id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
            expect(nameStr).assertEqual(name)
        } catch (e) {
            console.log("insert error " + e);
        }
        resultSet.close()
        resultSet = null
        done()
        console.log(TAG + "************* testSyncRdbStoreInsert0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0006
     * @tc.name Normal test case of insert (Chinese and long string)
     * @tc.desc 1.Insert data
     *          2.Configure predicates
     *          3.Query data
     */
    it('testSyncRdbStoreInsert0006', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreInsert0006 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var nameStr = "西瓜是水果" + "e".repeat(2000) + "好吃又好看"
        const valueBucket = {
            "name": nameStr,
            "age": 21,
            "salary": 100.5,
            "blobType": u8,
        }
        rdbStore.insertSync("test", valueBucket)
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("age", 21)
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "resultSet query done");
            expect(true).assertEqual(resultSet.goToFirstRow())
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            console.log(TAG + "id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
            expect(nameStr).assertEqual(name)
        } catch (e) {
            console.log("insert error " + e);
        }
        resultSet.close()
        resultSet = null
        done()
        console.log(TAG + "************* testSyncRdbStoreInsert0006 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0007
     * @tc.name Normal test case of insert boundary value
     * @tc.desc 1.Insert data
     *          2.Configure predicates
     *          3.Query data
     */
    it('testSyncRdbStoreInsert0007', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreInsert0007 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": Number.MIN_SAFE_INTEGER,
                "salary": Number.MIN_VALUE,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket)
        }

        {
            const valueBucket = {
                "name": "lisi",
                "age": Number.MAX_SAFE_INTEGER,
                "salary": Number.MAX_VALUE,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket)
        }

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "resultSet query done");
            expect(true).assertEqual(resultSet.goToFirstRow())
            const age = resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
            expect(Number.MIN_SAFE_INTEGER).assertEqual(age)
            expect(Number.MIN_VALUE).assertEqual(salary)

            expect(true).assertEqual(resultSet.goToNextRow())
            const age_1 = resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary_1 = resultSet.getDouble(resultSet.getColumnIndex("salary"))
            expect(Number.MAX_SAFE_INTEGER).assertEqual(age_1)
            expect(Number.MAX_VALUE).assertEqual(salary_1)
            resultSet.close()
            done()
        } catch (e) {
            expect(null).assertFail()
            console.log("insert error " + e);
        }
        resultSet = null
        console.log(TAG + "************* testSyncRdbStoreInsert0007 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0008
     * @tc.name Normal test case of insert null value
     * @tc.desc 1.Insert data
     *          2.Query data
     *          3.Create value
     *          4.Execute update
     *          5.Query data
     */
    it('testSyncRdbStoreInsert0008', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreInsert0008 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": null,
                "salary": undefined,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket)
        }

        {
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket);
        }

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        try {
            done()
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect(true).assertEqual(resultSet.isColumnNull(resultSet.getColumnIndex("age")));
            expect(true).assertEqual(resultSet.isColumnNull(resultSet.getColumnIndex("salary")));
        } catch (err) {
            console.log("query error" + err);
        }

        {
            const valueBucket = {
                "age": null,
                "salary": undefined,
            }
            predicates.equalTo("name", "lisi")
            await rdbStore.update(valueBucket, predicates)
        }

        predicates.clear();
        resultSet = await rdbStore.query(predicates);
        try {
            done();
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect(true).assertEqual(resultSet.goToNextRow());
            expect(true).assertEqual(resultSet.isColumnNull(resultSet.getColumnIndex("age")));
            expect(200.5).assertEqual(resultSet.getDouble(resultSet.getColumnIndex("salary")));
        } catch (err) {
            console.log("query error" + err);
        }

        resultSet.close()
        resultSet = null
        console.log(TAG + "************* testSyncRdbStoreInsert0008 end  *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0009
     * @tc.name Abnormal test case of insert, if value invalid
     * @tc.desc 1.Create value ("age": new Date())
     *          2.Execute insert
     */
    it('testSyncRdbStoreInsert0009', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreInsert0009 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": new Date(),
                "salary": 100.5,
                "blobType": u8,
            }
            try {
                rdbStore.insertSync("test", valueBucket)
            } catch (err) {
                done();
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
                expect("401").assertEqual(err.code)
            }
        }
        console.log(TAG + "************* testSyncRdbStoreInsert0009 end  *************");
    })


    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolutionSync_0001
     * @tc.name Abnormal test case of insert, if primary key conflict
     * @tc.desc 1.Insert data
     *          2.Insert data (conflict "id")
     */
    it('InsertWithConflictResolutionSync0001', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolutionSync0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket);
        }

        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 200.5,
                "blobType": u8,
            }
            try {
                rdbStore.insertSync("test", valueBucket);
                expect(null).assertFail()
            } catch (err) {
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
                expect(14800032).assertEqual(err.code)
                done();
            }
        }

        console.log(TAG + "************* InsertWithConflictResolutionSync_0001 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolutionSync_0002
     * @tc.name Abnormal test case of insert with ON_CONFLICT_ROLLBACK, if primary key conflict
     * @tc.desc 1.Insert data with ON_CONFLICT_ROLLBACK
     *          2.Create value (conflict "id")
     *          3.Begin Transaction
     *          4.Insert data
     *          5.Insert data with ON_CONFLICT_ROLLBACK (conflict "id")
     *          6.Query data
     */
    it('InsertWithConflictResolutionSync0002', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolutionSync0002 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
        }

        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 200.5,
                "blobType": u8,
            }

            rdbStore.beginTransaction()
            const valueBucketInsert = {
                "name": "wangwu",
                "age": 30,
                "salary": 400.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucketInsert)
            try {
                rdbStore.insertSync("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
                expect(null).assertFail();
            } catch (err) {
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message);
                expect(14800032).assertEqual(err.code);
                rdbStore.rollBack();
            }
        }

        {
            let predicates = await new data_relationalStore.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);

            expect(1).assertEqual(resultSet.rowCount);
            resultSet.close();
            done();
        }

        console.log(TAG + "************* InsertWithConflictResolutionSync_0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolutionSync_0003
     * @tc.name Normal test case of insert with ON_CONFLICT_IGNORE, if primary key conflict
     * @tc.desc 1.Insert data with ON_CONFLICT_IGNORE
     *          2.Insert data with ON_CONFLICT_IGNORE (conflict "id")
     *          3.Configure predicates ("name" is "zhangsan")
     *          4.Query data
     */
    it('InsertWithConflictResolutionSync0003', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolutionSync0003 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE);
        }

        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 200.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE);
        }
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("name", "zhangsan")
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "resultSet query done");
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            expect(1).assertEqual(id);
            expect(false).assertEqual(resultSet.goToNextRow())
        } catch (err) {
            console.log("insert error" + err);
        }

        resultSet.close()
        resultSet = null
        done()
        console.log(TAG + "************* InsertWithConflictResolutionSync_0003 end  *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolutionSync_0004
     * @tc.name Normal test case of insert with ON_CONFLICT_REPLACE, if primary key conflict
     * @tc.desc 1.Insert data with ON_CONFLICT_REPLACE
     *          2.Query data ("name" is "zhangsan")
     *          3.Insert data with ON_CONFLICT_REPLACE (conflict "id")
     *          4.Query data 
     */
    it('InsertWithConflictResolutionSync0004', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolutionSync0004 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        }
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("name", "zhangsan")
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "resultSet query done");
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            expect(1).assertEqual(id);
            expect(false).assertEqual(resultSet.goToNextRow())
        } catch (err) {
            console.log("insert error" + err);
        }
        resultSet.close()

        {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 200.5,
                "blobType": u8,
            }
            rdbStore.insertSync("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        }
        resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "resultSet query done");
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            const age = resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
            console.log(TAG + "id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
            expect(1).assertEqual(id);
            expect("zhangsan").assertEqual(name)
            expect(18).assertEqual(age)
            expect(200.5).assertEqual(salary)
            expect(4).assertEqual(blobType[0])
            expect(5).assertEqual(blobType[1])
            expect(6).assertEqual(blobType[2])
            expect(false).assertEqual(resultSet.goToNextRow())
        } catch (err) {
            console.log("resultSet query error " + err);
        }

        resultSet.close()
        resultSet = null
        done()
        console.log(TAG + "************* InsertWithConflictResolutionSync_0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolutionSync_0005
     * @tc.name Abnormal test case of insert, if param conflict is invalid
     * @tc.desc 1.Create value
     *          2.Execute insert (param conflict is 6)
     */
    it('InsertWithConflictResolutionSync0005', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolutionSync0005 start *************");
        {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 200.5,
                "blobType": u8,
            }

            try {
                rdbStore.insertSync("test", valueBucket, 6);
                expect(null).assertFail()
            } catch (err) {
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
                expect("401").assertEqual(err.code)
                done()
            }
        }

        console.log(TAG + "************* InsertWithConflictResolutionSync_0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_batchInsert_0001
     * @tc.name Normal test case of batchInsert
     * @tc.desc 1.Create valueBucket
     *          2.Execute push
     *          3.BatchInsert data
     *          4.Query data
     */
        it('testRdbStoreSyncbatchInsert001', 0, async function () {
            console.log(TAG + "************* testRdbStoreSyncbatchInsert001 start *************");
    
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let valueBucketArray = new Array();
            for (let i = 0; i < 100; i++) {
                valueBucketArray.push(valueBucket);
            }
            rdbStore.batchInsertSync("test", valueBucketArray);
            let resultSet = await rdbStore.querySql("SELECT * FROM test");
            let count = resultSet.rowCount;
            expect(100).assertEqual(count);
            resultSet.close()
            console.log(TAG + "************* testRdbStoreSyncbatchInsert001 end *************");
        })

    console.log(TAG + "*************Unit Test End*************");
})