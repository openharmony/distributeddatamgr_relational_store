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
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'
import dataSharePredicates from '@ohos.data.dataSharePredicates';
var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT UNIQUE, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
const STORE_CONFIG = {
    name: "UpdataTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined;

describe('rdbStoreUpdateSyncTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
    })

    beforeEach(async function () {
        await rdbStore.executeSql("DELETE FROM test");
        console.info(TAG + 'beforeEach')
    })

    afterEach(function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "UpdataTest.db");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0001
     * @tc.name Normal test case of update
     * @tc.desc 1.Insert data
     *          2.Update data
     *          3.Query data
     */
    it('testSyncRdbStoreUpdate0001', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdate0001 start *************");
        var u8 = new Uint8Array([1, 2, 3]);
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(1).assertEqual(ret);
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "name": "lisi",
                "age": 20,
                "salary": 200.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("id", "1")
            let ret = rdbStore.updateSync(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);

            predicates = new data_relationalStore.RdbPredicates("test")
            let resultSet = await rdbStore.query(predicates)
            try {
                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                await expect(1).assertEqual(id);
                await expect("lisi").assertEqual(name);
                await expect(20).assertEqual(age);
                await expect(200.5).assertEqual(salary);
                await expect(4).assertEqual(blobType[0]);
                await expect(5).assertEqual(blobType[1]);
                await expect(6).assertEqual(blobType[2]);
                await expect(false).assertEqual(resultSet.goToNextRow())
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }

        console.log(TAG + "************* testSyncRdbStoreUpdate0001 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0002
     * @tc.name Abnormal test case of update, if TABLE name or Bucket is empty and column invalid
     * @tc.desc 1.Create value
     *          2.Configure predicates (TABLE name: "")
     *          3.Execute update
     *          4.Configure predicates (emptyBucket)
     *          5.Execute update
     *          6.Configure predicates (column: "aaa")
     *          7.Execute update
     */
    it('testSyncRdbStoreUpdate0002', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdate0002 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("")
            rdbStore.updateSync(valueBucket, predicates) // table name should not empty
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect("401").assertEqual(err.code)
        }
        try {
            const emptyBucket = {};
            let predicates = new data_relationalStore.RdbPredicates("test")
            rdbStore.updateSync(emptyBucket, predicates) // emptyBucket should not empty
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `test failed, err: ${JSON.stringify(err)}`)
            expect('401').assertEqual(err.code)
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("aaa", "null") // column aaa not exist
            rdbStore.updateSync(valueBucket, predicates)
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `aaa failed, err: ${JSON.stringify(err)}`)
            expect(14800021).assertEqual(err.code)
        }
        console.log(TAG + "************* testSyncRdbStoreUpdate0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0003
     * @tc.name Abnormal test case of update, if TABLE name or Column is invalid
     * @tc.desc 1.Create value
     *          2.Configure predicates (TABLE name: "wrongTable")
     *          3.Execute update
     *          4.Configure predicates (column: "wrongColumn")
     *          5.Execute update
     */
    it('testSyncRdbStoreUpdate0003', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdate0003 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
            "wrongColumn": 100.5,
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("wrongTable")
            rdbStore.updateSync(valueBucket, predicates) // wrongTable not exist
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `wrongTable failed, err: ${JSON.stringify(err)}`)
            expect(14800021).assertEqual(err.code)
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("test")
            rdbStore.updateSync(valueBucket, predicates) // wrongColumn not exist
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `test failed, err: ${JSON.stringify(err)}`)
            expect(14800021).assertEqual(err.code)
        }
        console.log(TAG + "************* testSyncRdbStoreUpdate0003 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0004
     * @tc.name Abnormal test case of update, if column is invalid
     * @tc.desc 1.Create value
     *          2.Configure predicates (column: "aaa")
     *          3.Execute update
     *          4.Configure predicates (column: "null")
     *          5.Execute update
     */
    it('testSyncRdbStoreUpdate0004', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdate0004 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("aaa", "null")
            rdbStore.updateSync(valueBucket, predicates)
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `test failed, err: ${JSON.stringify(err)}`)
            expect(14800021).assertEqual(err.code)
        }
        try {
            const emptyBucket = {};
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", "zhangsan")
            predicates.equalTo("age", 18)
            predicates.equalTo("null", 100.5)
            rdbStore.updateSync(emptyBucket, predicates)
        } catch (err) {
            console.log(TAG + `emptyBucket failed, err: ${JSON.stringify(err)}`)
            expect('401').assertEqual(err.code)
        }
        console.log(TAG + "************* testSyncRdbStoreUpdate0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0005
     * @tc.name Normal test case of update, value is long string and special characters
     * @tc.desc 1.Insert data
     *          2.Update data
     *          3.Query data
     */
    it('testSyncRdbStoreUpdate0005', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdate0005 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            const valueBucket = {
                "name": "xiaoming",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([4, 5, 6])
            var nameStr = "abcd" + "e".repeat(2000) + "./&*$!@()"
            const valueBucket = {
                "name": nameStr,
                "age": 20,
                "salary": 200.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", "xiaoming")
            let ret = rdbStore.updateSync(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);

            predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", 20)
            let resultSet = await rdbStore.query(predicates)
            try {
                expect(true).assertEqual(resultSet.goToFirstRow())
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                await expect(nameStr).assertEqual(name);
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        console.log(TAG + "************* testSyncRdbStoreUpdate0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0006
     * @tc.name Normal test case of update, value is Chinese and long string
     * @tc.desc 1.Insert data
     *          2.Update data
     *          3.Query data
     */
    it('testSyncRdbStoreUpdate0006', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdate0006 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            const valueBucket = {
                "name": "xiaohua",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([4, 5, 6])
            var nameStr = "橘子是水果" + "e".repeat(2000)
            const valueBucket = {
                "name": nameStr,
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", "xiaohua")
            let ret = rdbStore.updateSync(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);
            predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", 19)
            let resultSet = await rdbStore.query(predicates)
            try {
                expect(true).assertEqual(resultSet.goToFirstRow())
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                await expect(nameStr).assertEqual(name);
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        console.log(TAG + "************* testSyncRdbStoreUpdate0006 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0007
     * @tc.name Normal test case of update, value is Chinese and long string
     * @tc.desc 1.Insert data
     *          2.Update data
     *          3.Query data
     */
    it('testSyncRdbStoreUpdate0007', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdate0007 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            const valueBucket = {
                "name": "xiaocan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([4, 5, 6])
            var nameStr = "菠萝是水果" + "e".repeat(2000) + "好吃又不贵"
            const valueBucket = {
                "name": nameStr,
                "age": 21,
                "salary": 200.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", "xiaocan")
            let ret = rdbStore.updateSync(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);
            predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", 21)
            let resultSet = await rdbStore.query(predicates)
            try {
                expect(true).assertEqual(resultSet.goToFirstRow())
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                await expect(nameStr).assertEqual(name);
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        console.log(TAG + "************* testSyncRdbStoreUpdate0007 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0008
     * @tc.name Abnormal test case of update, if non system application calls
     * @tc.desc 1.Create value (calling system application)
     *          2.Execute update
     */
    it('testSyncRdbStoreUpdate0008', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdate0008 start *************");
        try {
            const valueBucket = {
                "name": "name",
                "age": 21,
                "salary": 200.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            var predicate = new dataSharePredicates.DataSharePredicates();
            rdbStore.updateSync("test", valueBucket, predicate);
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect("202").assertEqual(err.code)
        }
        console.log(TAG + "************* testSyncRdbStoreUpdate0008 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0001
     * @tc.name Normal test case of update
     * @tc.desc 1.Insert data
     *          2.Execute update
     *          3.Query data
     */
    it('testSyncRdbStoreUpdateWithConflictResolution0001', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0001 start *************");
        try {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert2 failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }

        try {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "wangjing",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", "19")
            let ret = rdbStore.updateSync(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);
            predicates = new data_relationalStore.RdbPredicates("test")
            let resultSet = await rdbStore.query(predicates)

            try {
                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                    + salary + ", blobType=" + blobType);

                await expect(1).assertEqual(id);
                await expect("zhangsan").assertEqual(name);
                await expect(18).assertEqual(age);
                await expect(100.5).assertEqual(salary);
                await expect(1).assertEqual(blobType[0]);
                await expect(2).assertEqual(blobType[1]);
                await expect(3).assertEqual(blobType[2]);

                await expect(true).assertEqual(resultSet.goToNextRow())
                const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                    + salary_1 + ", blobType=" + blobType_1);

                await expect(3).assertEqual(id_1);
                await expect("wangjing").assertEqual(name_1);
                await expect(20).assertEqual(age_1);
                await expect(300.5).assertEqual(salary_1);
                await expect(7).assertEqual(blobType_1[0]);
                await expect(8).assertEqual(blobType_1[1]);
                await expect(9).assertEqual(blobType_1[2]);
                await expect(false).assertEqual(resultSet.goToNextRow())
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0001 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0002
     * @tc.name Abnormal test case of update with ON_CONFLICT_NONE, if conflict is none
     * @tc.desc 1.Insert data
     *          2.Create value
     *          3.Execute update with ON_CONFLICT_NONE
     *          4.Query data
     */
    it('testSyncRdbStoreUpdateWithConflictResolution0002', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0002 start *************");
        try {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert2 failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "zhangsan",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", "19")
            rdbStore.updateSync(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_NONE);
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect(14800032).assertEqual(err.code)
        }

        let predicates = new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
            const name = await resultSet.getString(resultSet.getColumnIndex("name"))
            const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
            console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                + salary + ", blobType=" + blobType);

            await expect(1).assertEqual(id);
            await expect("zhangsan").assertEqual(name);
            await expect(18).assertEqual(age);
            await expect(100.5).assertEqual(salary);
            await expect(1).assertEqual(blobType[0]);
            await expect(2).assertEqual(blobType[1]);
            await expect(3).assertEqual(blobType[2]);

            await expect(true).assertEqual(resultSet.goToNextRow())
            const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
            const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
            const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
            console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                + salary_1 + ", blobType=" + blobType_1);

            await expect(2).assertEqual(id_1);
            await expect("lisi").assertEqual(name_1);
            await expect(19).assertEqual(age_1);
            await expect(200.5).assertEqual(salary_1);
            await expect(4).assertEqual(blobType_1[0]);
            await expect(5).assertEqual(blobType_1[1]);
            await expect(6).assertEqual(blobType_1[2]);
            await expect(false).assertEqual(resultSet.goToNextRow())
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        } finally {
            resultSet.close()
            resultSet = null
        }
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0003
     * @tc.name Normal test case of update with ON_CONFLICT_ROLLBACK
     * @tc.desc 1.Insert data
     *          2.Create value
     *          3.Execute update with ON_CONFLICT_ROLLBACK
     *          4.Query data
     */
    it('testSyncRdbStoreUpdateWithConflictResolution0003', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0003 start *************");
        try {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert2 failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "wangjing",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", "19")
            let ret = rdbStore.updateSync(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);

            predicates = new data_relationalStore.RdbPredicates("test")
            let resultSet = await rdbStore.query(predicates)
            try {
                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                    + salary + ", blobType=" + blobType);

                await expect(1).assertEqual(id);
                await expect("zhangsan").assertEqual(name);
                await expect(18).assertEqual(age);
                await expect(100.5).assertEqual(salary);
                await expect(1).assertEqual(blobType[0]);
                await expect(2).assertEqual(blobType[1]);
                await expect(3).assertEqual(blobType[2]);

                await expect(true).assertEqual(resultSet.goToNextRow())
                const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                    + salary_1 + ", blobType=" + blobType_1);

                await expect(3).assertEqual(id_1);
                await expect("wangjing").assertEqual(name_1);
                await expect(20).assertEqual(age_1);
                await expect(300.5).assertEqual(salary_1);
                await expect(7).assertEqual(blobType_1[0]);
                await expect(8).assertEqual(blobType_1[1]);
                await expect(9).assertEqual(blobType_1[2]);
                await expect(false).assertEqual(resultSet.goToNextRow())
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `insert2 failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0003 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0004
     * @tc.name Abnormal test case of update with ON_CONFLICT_ROLLBACK
     * @tc.desc 1.Insert data
     *          2.Create value
     *          3.Begin Transaction
     *          4.Insert data
     *          5.Update data with ON_CONFLICT_ROLLBACK
     *          6.Query data
     */
    it('testSyncRdbStoreUpdateWithConflictResolution0004', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0004 start *************");
        try {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "zhangsan",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", "19")

            rdbStore.beginTransaction()
            const valueBucketInsert = {
                "name": "wangwu",
                "age": 30,
                "salary": 400.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucketInsert)
            try {
                rdbStore.updateSync(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
                expect().assertFail()
            } catch (err) {
                console.log("catch err: failed, err: code=" + err.code + " message=" + err.message);
                expect(14800032).assertEqual(err.code);
            }
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }

        try {
            let predicates = new data_relationalStore.RdbPredicates("test")
            let resultSet = await rdbStore.query(predicates)
            try {
                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                    + salary + ", blobType=" + blobType);

                await expect(1).assertEqual(id);
                await expect("zhangsan").assertEqual(name);
                await expect(18).assertEqual(age);
                await expect(100.5).assertEqual(salary);
                await expect(1).assertEqual(blobType[0]);
                await expect(2).assertEqual(blobType[1]);
                await expect(3).assertEqual(blobType[2]);

                await expect(true).assertEqual(resultSet.goToNextRow())
                const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                    + salary_1 + ", blobType=" + blobType_1);

                await expect(2).assertEqual(id_1);
                await expect("lisi").assertEqual(name_1);
                await expect(19).assertEqual(age_1);
                await expect(200.5).assertEqual(salary_1);
                await expect(4).assertEqual(blobType_1[0]);
                await expect(5).assertEqual(blobType_1[1]);
                await expect(6).assertEqual(blobType_1[2]);
                await expect(false).assertEqual(resultSet.goToNextRow())
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0005
     * @tc.name Normal test case of insert with ON_CONFLICT_REPLACE
     * @tc.desc 1.Insert data
     *          2.Create value
     *          3.Execute update with ON_CONFLICT_REPLACE
     *          4.Query data
     */
    it('testSyncRdbStoreUpdateWithConflictResolution0005', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0005 start *************");
        try {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert1 failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert2 failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "wangjing",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", "19")
            let ret = rdbStore.updateSync(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);
            predicates = new data_relationalStore.RdbPredicates("test")
            let resultSet = await rdbStore.query(predicates)
            try {

                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                    + salary + ", blobType=" + blobType);

                await expect(1).assertEqual(id);
                await expect("zhangsan").assertEqual(name);
                await expect(18).assertEqual(age);
                await expect(100.5).assertEqual(salary);
                await expect(1).assertEqual(blobType[0]);
                await expect(2).assertEqual(blobType[1]);
                await expect(3).assertEqual(blobType[2]);

                await expect(true).assertEqual(resultSet.goToNextRow())
                const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                    + salary_1 + ", blobType=" + blobType_1);

                await expect(3).assertEqual(id_1);
                await expect("wangjing").assertEqual(name_1);
                await expect(20).assertEqual(age_1);
                await expect(300.5).assertEqual(salary_1);
                await expect(7).assertEqual(blobType_1[0]);
                await expect(8).assertEqual(blobType_1[1]);
                await expect(9).assertEqual(blobType_1[2]);
                await expect(false).assertEqual(resultSet.goToNextRow())
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0006
     * @tc.name Normal test case of update partial data with ON_CONFLICT_REPLACE
     * @tc.desc 1.Insert data
     *          2.Create partial value
     *          3.Execute update with ON_CONFLICT_REPLACE
     *          4.Query data
     */
    it('testSyncRdbStoreUpdateWithConflictResolution0006', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0006 start *************");
        try {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }

        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (err) {
            console.log(TAG + `insert2 failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 20,
                "salary": 300.5,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", "19")
            let ret = rdbStore.updateSync(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);
            predicates = new data_relationalStore.RdbPredicates("test")
            let resultSet = await rdbStore.query(predicates)
            try {
                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                    + salary + ", blobType=" + blobType);

                await expect(2).assertEqual(id);
                await expect("zhangsan").assertEqual(name);
                await expect(20).assertEqual(age);
                await expect(300.5).assertEqual(salary);
                await expect(4).assertEqual(blobType[0]);
                await expect(5).assertEqual(blobType[1]);
                await expect(6).assertEqual(blobType[2]);

                await expect(false).assertEqual(resultSet.goToNextRow())
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0006 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0007
     * @tc.name Abnormal test case of update, if value of "age" is invalid
     * @tc.desc 1.Create value
     *          2.Configure predicates
     *          3.Execute update
     */
    it('testSyncRdbStoreUpdateWithConflictResolution0007', 0, async function () {
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0007 start *************");
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 20,
                "salary": 300.5,
            }
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", "19")
            rdbStore.update(valueBucket, predicates, 6);
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect("401").assertEqual(err.code)
        }
        console.log(TAG + "************* testSyncRdbStoreUpdateWithConflictResolution0007 end   *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})
