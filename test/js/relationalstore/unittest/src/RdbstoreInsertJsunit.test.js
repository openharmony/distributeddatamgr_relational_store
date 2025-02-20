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
var rdbStore1 = undefined
var context = ability_featureAbility.getContext()

describe('rdbStoreInsertTest', function () {
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
    it('testRdbStoreInsert0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 20,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
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
        console.log(TAG + "************* testRdbStoreInsert0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0002
     * @tc.name Abnormal test case of insert, if TABLE name is wrong
     * @tc.desc 1.Create value
     *          2.Execute insert (with wrong table)
     */
    it('testRdbStoreInsert0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0002 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let insertPromise = rdbStore.insert("wrong", valueBucket)
            insertPromise.then(async (ret) => {
                expect(1).assertEqual(ret)
                console.log(TAG + "insert first done: " + ret)
                expect(null).assertFail()
            }).catch((err) => {
                console.log(TAG + "insert with wrong table")
            })
        }
        done()
        console.log(TAG + "************* testRdbStoreInsert0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0003
     * @tc.name Abnormal test case of insert, if TABLE name is null
     * @tc.desc 1.Create value
     *          2.Execute insert (with null table)
     */
    it('testRdbStoreInsert0003', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0003 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            try {
                let insertPromise = rdbStore.insert(null, valueBucket)
                insertPromise.then(async (ret) => {
                    expect(1).assertEqual(ret)
                    console.log(TAG + "insert first done: " + ret)
                    expect(null).assertFail()
                }).catch((err) => {
                    console.log(TAG + "insert with null table")
                    expect(null).assertFail()
                })
            } catch (err) {
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
                expect("401").assertEqual(err.code)
                done()
            }
        }
        done()
        console.log(TAG + "************* testRdbStoreInsert0003 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0004
     * @tc.name Normal test case of insert (long string and special characters)
     * @tc.desc 1.Insert data
     *          2.Configure predicates
     *          3.Query data
     */
    it('testRdbStoreInsert0004', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0004 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var nameStr = "abcd" + "e".repeat(2000) + "./&*$!@()"
        const valueBucket = {
            "name": nameStr,
            "age": 19,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
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
        console.log(TAG + "************* testRdbStoreInsert0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0005
     * @tc.name Normal test case of insert (Chinese and long string)
     * @tc.desc 1.Insert data
     *          2.Configure predicates
     *          3.Query data
     */
    it('testRdbStoreInsert0005', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0005 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var nameStr = "苹果是水果" + "e".repeat(2000)
        const valueBucket = {
            "name": nameStr,
            "age": 20,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
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
        console.log(TAG + "************* testRdbStoreInsert0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0006
     * @tc.name Normal test case of insert (Chinese and long string)
     * @tc.desc 1.Insert data
     *          2.Configure predicates
     *          3.Query data
     */
    it('testRdbStoreInsert0006', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0006 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var nameStr = "西瓜是水果" + "e".repeat(2000) + "好吃又好看"
        const valueBucket = {
            "name": nameStr,
            "age": 21,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
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
        console.log(TAG + "************* testRdbStoreInsert0006 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0007
     * @tc.name Normal test case of insert boundary value
     * @tc.desc 1.Insert data
     *          2.Configure predicates
     *          3.Query data
     */
    it('testRdbStoreInsert0007', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0007 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": Number.MIN_SAFE_INTEGER,
                "salary": Number.MIN_VALUE,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }

        {
            const valueBucket = {
                "name": "lisi",
                "age": Number.MAX_SAFE_INTEGER,
                "salary": Number.MAX_VALUE,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
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
        console.log(TAG + "************* testRdbStoreInsert0007 end *************");
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
    it('testRdbStoreInsert0008', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0008 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": null,
                "salary": undefined,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket);
        }

        {
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket);
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
        console.log(TAG + "************* testRdbStoreInsert0008 end  *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0009
     * @tc.name Abnormal test case of insert, if value invalid
     * @tc.desc 1.Create value ("age": new Date())
     *          2.Execute insert
     */
    it('testRdbStoreInsert0009', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0009 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": new Date(),
                "salary": 100.5,
                "blobType": u8,
            }
            try {
                let insertPromise = rdbStore.insert("test", valueBucket)
                insertPromise.then(async (ret) => {
                    done();
                    expect(null).assertFail()
                }).catch((err) => {
                    done();
                    expect(null).assertFail()
                })
            } catch (err) {
                done();
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
                expect("401").assertEqual(err.code)
            }
        }
        console.log(TAG + "************* testRdbStoreInsert0009 end  *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Insert_0010
     * @tc.name Abnormal test case of insert, if store is closed
     * @tc.desc 1.close store
     *          2.Execute insert
     */
    it('testRdbStoreInsert0010', 0, async function () {
        console.log(TAG + "************* testRdbStoreInsert0010 start *************");
        const STORE_CONFIG1 = {
            name: "InsertTest1.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
        };
        rdbStore1 = await data_relationalStore.getRdbStore(context, STORE_CONFIG1);
        await rdbStore1.executeSql(CREATE_TABLE_TEST, null);
        await rdbStore1.close().then(() => {
            console.info(`close succeeded`);
        }).catch((err) => {
            console.error(`close failed, code is ${err.code},message is ${err.message}`);
        })

        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "zhangsan",
            "age": new Date(),
            "salary": 100.5,
            "blobType": u8,
        }
        try {
            await rdbStore1.insert("test", valueBucket)
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }
        await data_relationalStore.deleteRdbStore(context, "InsertTest1.db");
        console.log(TAG + "************* testRdbStoreInsert0010 end  *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolution_0001
     * @tc.name Abnormal test case of insert, if primary key conflict
     * @tc.desc 1.Insert data
     *          2.Insert data (conflict "id")
     */
    it('InsertWithConflictResolution0001', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolution0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket);
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
                let insertPromise = rdbStore.insert("test", valueBucket)
                insertPromise.then(async (ret) => {
                    expect(1).assertEqual(ret)
                    console.log(TAG + "insert first done: " + ret)
                    expect(null).assertFail()
                }).catch((err) => {
                    console.log(TAG + "insert with wrong valuebucket and ConflictResolution is default")
                    done();
                })
            } catch (err) {
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
                expect("401").assertEqual(err.code)
                expect(null).assertFail()
            }
        }

        console.log(TAG + "************* InsertWithConflictResolution_0001 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolution_0002
     * @tc.name Abnormal test case of insert with ON_CONFLICT_ROLLBACK, if primary key conflict
     * @tc.desc 1.Insert data with ON_CONFLICT_ROLLBACK
     *          2.Create value (conflict "id")
     *          3.Begin Transaction
     *          4.Insert data
     *          5.Insert data with ON_CONFLICT_ROLLBACK (conflict "id")
     *          6.Query data
     */
    it('InsertWithConflictResolution0002', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolution0002 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
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
            await rdbStore.insert("test", valueBucketInsert)
            try {
                await rdbStore.insert("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
                expect(null).assertFail();
            } catch (err) {
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message);
                expect(14800032).assertEqual(err.code);
            }
        }

        {
            let predicates = await new data_relationalStore.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);

            expect(1).assertEqual(resultSet.rowCount);
            resultSet.close();
            done();
        }

        console.log(TAG + "************* InsertWithConflictResolution_0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolution_0003
     * @tc.name Normal test case of insert with ON_CONFLICT_IGNORE, if primary key conflict
     * @tc.desc 1.Insert data with ON_CONFLICT_IGNORE
     *          2.Insert data with ON_CONFLICT_IGNORE (conflict "id")
     *          3.Configure predicates ("name" is "zhangsan")
     *          4.Query data
     */
    it('InsertWithConflictResolution0003', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolution0003 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE);
        }

        {
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE);
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
        console.log(TAG + "************* InsertWithConflictResolution_0003 end  *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolution_0004
     * @tc.name Normal test case of insert with ON_CONFLICT_REPLACE, if primary key conflict
     * @tc.desc 1.Insert data with ON_CONFLICT_REPLACE
     *          2.Query data ("name" is "zhangsan")
     *          3.Insert data with ON_CONFLICT_REPLACE (conflict "id")
     *          4.Query data
     */
    it('InsertWithConflictResolution0004', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolution0004 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
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
            await rdbStore.insert("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
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
        console.log(TAG + "************* InsertWithConflictResolution_0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_InsertWithConflictResolution_0005
     * @tc.name Abnormal test case of insert, if param conflict is invalid
     * @tc.desc 1.Create value
     *          2.Execute insert (param conflict is 6)
     */
    it('InsertWithConflictResolution0005', 0, async function (done) {
        console.log(TAG + "************* InsertWithConflictResolution0005 start *************");
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
                rdbStore.insert("test", valueBucket, 6);
                expect(null).assertFail()
            } catch (err) {
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
                expect("401").assertEqual(err.code)
                done()
            }
        }

        console.log(TAG + "************* InsertWithConflictResolution_0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_batchInsert_0001
     * @tc.name Normal test case of batchInsert
     * @tc.desc 1.Create valueBucket
     *          2.Execute push
     *          3.BatchInsert data
     *          4.Query data
     */
    it('testRdbStorebatchInsert001', 0, async function () {
        console.log(TAG + "************* testRdbStorebatchInsert001 start *************");

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
        await rdbStore.batchInsert("test", valueBucketArray);
        let resultSet = await rdbStore.querySql("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(100).assertEqual(count);
        resultSet.close()
        console.log(TAG + "************* testRdbStorebatchInsert001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_batchInsert_0002
     * @tc.name Normal test case of batchInsert
     * @tc.desc 1.Create valueBucket
     *          2.Execute push
     *          3.BatchInsert data
     *          4.Query data
     */
    it('testRdbStoreBatchInsert002', 0, async function () {
        console.log(TAG + "************* testRdbStoreBatchInsert002 start *************");

        const STORE_NAME = "AfterCloseTest.db";
        const STORE_CONFIG1 = {
            name: STORE_NAME,
            securityLevel: data_relationalStore.SecurityLevel.S1,
        };
        const rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG1);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
        await rdbStore.close().then(() => {
            console.info(`close succeeded`);
        }).catch((err) => {
            console.error(`close failed, code is ${err.code},message is ${err.message}`);
        })

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
        try {
            await rdbStore.batchInsert("test", valueBucketArray);
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await data_relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbStoreBatchInsert002 end *************");
    })

    /**
     * @tc.number testRdbStoreBatchInsertWithConflictResolution001
     * @tc.name batch insert with conflict resolution
     * @tc.desc normal batch insert with conflict resolution
     */
    it('testRdbStoreBatchInsertWithConflictResolution001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let valueBucketArray = new Array();
            for (let i = 0; i < 2; i++) {
                valueBucketArray.push(valueBucket);
            }
            var num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_NONE)
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution001 batch num1 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK)
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution001 batch num2 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_ABORT)
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution001 batch num3 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_FAIL)
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution001 batch num4 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE)
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution001 batch num5 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE)
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution001 batch num6 " + num)
            expect(2).assertEqual(num);

            let resultSet = await rdbStore.querySql("select * from test")
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution001 result count " + resultSet.rowCount)
            expect(12).assertEqual(resultSet.rowCount)
            resultSet.close()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution001 failed");
        }
        done()
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution001 end *************");
    })

    /**
     * @tc.number testRdbStoreBatchInsertWithConflictResolution002
     * @tc.name batch insert with conflict resolution
     * @tc.desc conflict when batch insert with conflict resolution
     */
    it('testRdbStoreBatchInsertWithConflictResolution002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution002 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            const valueBucket = {
                "id" : 2,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket);
            let valueBucketArray = new Array();
            for (let i = 0; i < 5; i++) {
                let val = {
                    "id" : i,
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": u8,
                }
                valueBucketArray.push(val);
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_NONE);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution002 ON_CONFLICT_NONE code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution002 ON_CONFLICT_ROLLBACK code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_ABORT);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution002 ON_CONFLICT_ABORT code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_FAIL);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution002 ON_CONFLICT_FAIL code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                let num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE);
                console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution002 ON_CONFLICT_IGNORE num " + num)
                expect(2).assertEqual(num)
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution002 ON_CONFLICT_IGNORE code: " + e.code);
                expect(null).assertFail();
            }
            try {
                let num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
                console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution002 ON_CONFLICT_REPLACE num " + num)
                expect(5).assertEqual(num)
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution002 ON_CONFLICT_REPLACE code: " + e.code);
                expect(null).assertFail();
            }
            let resultSet = await rdbStore.querySql("select * from test")
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution002 result count " + resultSet.rowCount)
            expect(5).assertEqual(resultSet.rowCount)
            resultSet.close()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution002 failed");
        }
        done()
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution002 end *************");
    })

    /**
     * @tc.number testRdbStoreBatchInsertWithConflictResolution003
     * @tc.name batch insert with conflict resolution
     * @tc.desc conflict when batch insert with conflict resolution
     */
    it('testRdbStoreBatchInsertWithConflictResolution003', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution003 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            let valueBucketArray = new Array();
            for (let i = 0; i < 5; i++) {
                let val = {
                    "id": i,
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": u8,
                }
                if (i == 2) {
                    val.name = null;
                }
                valueBucketArray.push(val);
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_NONE);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution003 ON_CONFLICT_NONE code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution003 ON_CONFLICT_ROLLBACK code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_ABORT);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution003 ON_CONFLICT_ABORT code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_FAIL);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution003 ON_CONFLICT_FAIL code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                let num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE);
                expect(2).assertEqual(num)
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution003 ON_CONFLICT_IGNORE code: " + e.code);
                expect(null).assertFail();
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution003 ON_CONFLICT_REPLACE code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            let resultSet = await rdbStore.querySql("select * from test")
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution003 result count " + resultSet.rowCount)
            expect(4).assertEqual(resultSet.rowCount)
            resultSet.close()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution003 failed");
        }
        done()
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution003 end *************");
    })

    /**
     * @tc.number testRdbStoreBatchInsertWithConflictResolution004
     * @tc.name batch insert with conflict resolution
     * @tc.desc conflict when batch insert with conflict resolution
     */
    it('testRdbStoreBatchInsertWithConflictResolution004', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution004 start *************");
        let valueBucketArray = new Array();
        for (let i = 0; i < 5; i++) {
            let val = {
                "id": i,
                "name": "zhangsan",
            }
            valueBucketArray.push(val);
        }
        try {
            await rdbStore.executeSql("DROP TABLE IF EXISTS test004");
            await rdbStore.executeSql("CREATE TABLE test004 (id INTEGER PRIMARY KEY CHECK (id >= 3 OR id <= 1), name TEXT NOT NULL)", null)
            try {
                await rdbStore.batchInsertWithConflictResolution("test004", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_NONE);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution004 ON_CONFLICT_NONE code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                rdbStore.batchInsertWithConflictResolutionSync("test004", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution004 ON_CONFLICT_ROLLBACK code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test004", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_ABORT);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution004 ON_CONFLICT_ABORT code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                rdbStore.batchInsertWithConflictResolutionSync("test004", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_FAIL);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution004 ON_CONFLICT_FAIL code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                let num = await rdbStore.batchInsertWithConflictResolution("test004", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE);
                console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution004 ON_CONFLICT_IGNORE num " + num)
                expect(2).assertEqual(num)
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution004 ON_CONFLICT_IGNORE code: " + e.code);
                expect(null).assertFail();
            }
            try {
                let num = rdbStore.batchInsertWithConflictResolutionSync("test004", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
                console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution004 ON_CONFLICT_REPLACE num " + num)
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution004 ON_CONFLICT_REPLACE code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            let resultSet = await rdbStore.querySql("select * from test004")
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution004 result count " + resultSet.rowCount)
            expect(4).assertEqual(resultSet.rowCount)
            resultSet.close()
            await rdbStore.executeSql("DROP TABLE IF EXISTS test004");
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution004 failed");
        }
        done()
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution004 end *************");
    })

    /**
     * @tc.number testRdbStoreBatchInsertWithConflictResolution005
     * @tc.name batch insert with conflict resolution
     * @tc.desc batch insert with conflict resolution with invalid args
     */
    it('testRdbStoreBatchInsertWithConflictResolution005', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution005 start *************");
        try {
            try {
                rdbStore.batchInsertWithConflictResolutionSync();
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution005 no args: " + e.code);
                expect(String(e.code)).assertEqual(String(401))
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test");
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution005 with 1 args: " + e.code);
                expect(String(e.code)).assertEqual(String(401))
            }
            try {
                rdbStore.batchInsertWithConflictResolutionSync("test", undefined);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution005 with 2 args: " + e.code);
                expect(String(e.code)).assertEqual(String(401))
            }
            try {
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                }
                let valueBucketArray = new Array();
                for (let i = 0; i < 2; i++) {
                    valueBucketArray.push(valueBucket);
                }
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray, undefined);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testRdbStoreBatchInsertWithConflictResolution005 with 3 args: " + e.code);
                expect(String(e.code)).assertEqual(String(401))
            }
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution005 failed");
        }
        done()
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution005 end *************");
    })

    /**
     * @tc.number testRdbStoreBatchInsertWithConflictResolution006
     * @tc.name batch insert with conflict resolution
     * @tc.desc batch insert with conflict resolution with over limit rows
     */
    it('testRdbStoreBatchInsertWithConflictResolution006', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution006 start *************");

        var u8 = new Uint8Array([1, 2, 3])
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let valueBucketArray = new Array();
            let rows = 32768 / 4 + 1;
            for (let i = 0; i < rows; i++) {
                valueBucketArray.push(valueBucket);
            }
            let num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_NONE);
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution006 failed num " + num);
            expect(null).assertFail();
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(14800000).assertEqual(e.code)
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution006 success");
        }
        done()
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution006 end *************");
    })

    /**
     * @tc.number testRdbStoreBatchInsertWithConflictResolution007
     * @tc.name batch insert with conflict resolution
     * @tc.desc batch insert with conflict resolution with busy
     */
    it('testRdbStoreBatchInsertWithConflictResolution007', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution007 start *************");

        let transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
            }
            let valueBucketArray = new Array();
            for (let i = 0; i < 2; i++) {
                valueBucketArray.push(valueBucket);
            }
            await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_NONE);
            await transaction.rollback();
            expect(null).assertFail();
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(14800024).assertEqual(e.code)
            console.log(TAG + "testRdbStoreBatchInsertWithConflictResolution007 failed");
            try {
                await transaction.rollback();
            }catch (e) {
                console.log(TAG + e + " rollback code: " + e.code);
                expect(null).assertFail();
            }
        }
        done()
        console.log(TAG + "************* testRdbStoreBatchInsertWithConflictResolution007 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})