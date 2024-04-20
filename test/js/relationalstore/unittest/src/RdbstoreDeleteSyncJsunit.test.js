/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
import dataSharePredicates from '@ohos.data.dataSharePredicates';

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "Delete.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined
var context = ability_featureAbility.getContext()

describe('rdbStoreDeleteSyncTest', function () {
    beforeAll(function () {
        console.info(TAG + 'beforeAll')
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "Delete.db");
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");
    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0010
     * @tc.name Normal test case of delete
     * @tc.desc 1.Insert data
     *		2.Execute delete
     */
    it('testSyncRdbStoreDelete0001', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreDelete0001 start *************");
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
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 38,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            let ret = rdbStore.deleteSync(predicates)
            expect(3).assertEqual(ret)
            console.log(TAG + "Delete done: " + ret)
        }
        done()
        console.log(TAG + "************* testSyncRdbStoreDelete0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0020
     * @tc.name Normal test case of delete, "name" is "zhangsan"
     * @tc.desc 1.Insert data
     * 		2.Configure predicates ("name": "zhangsan")
     * 		3.Execute delete
     */
    it('testSyncRdbStoreDelete0002', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreDelete0002 start *************");
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
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 38,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", "zhangsan")
            let ret = rdbStore.deleteSync(predicates)
            expect(1).assertEqual(ret)
            console.log(TAG + "Delete done: " + ret)
        }
        done()
        console.log(TAG + "************* testSyncRdbStoreDelete0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0030
     * @tc.name Normal test case of query and delete, "age" is 28
     * @tc.desc 1.Insert data
     * 		2.Query data ("age", 28)
     * 		3.Execute delete ("age", 28)
     * 		4.Query data ("age", 28)
     */
    it('testSyncRdbStoreDelete0003', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreDelete0003 start *************");
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
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", 28)
            let resultSet = await rdbStore.query(predicates)
            expect(1).assertEqual(resultSet.rowCount)
            resultSet.close()
        }
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", 28)
            let ret = rdbStore.deleteSync(predicates)
            expect(1).assertEqual(ret)
            console.log(TAG + "Delete done: " + ret)
        }
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("age", 28)
            let resultSet = await rdbStore.query(predicates)
            expect(0).assertEqual(resultSet.rowCount)
            resultSet.close()
        }
        done()
        console.log(TAG + "************* testSyncRdbStoreDelete0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0040
     * @tc.name Abnormal test case of delete, if column is invalid
     * @tc.desc 1.Insert data
     * 		2.Configure predicates ("aaa id", 1)
     * 		3.Execute delete
     */
    it('testSyncRdbStoreDelete0004', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreDelete0004 start *************");
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
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 38,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("aaa id", 1)
            try {
                let ret = rdbStore.deleteSync(predicates)
                expect(null).assertFail()
            } catch (err) {
                console.log(TAG + "delete with wrong conditions")
            }
        }
        done()
        console.log(TAG + "************* testSyncRdbStoreDelete0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0050
     * @tc.name Normal test case of delete, "name" is "lisi"
     * @tc.desc 1.Insert data
     *		2.Configure predicates ("name", "lisi")
     *		3.Execute delete
     */
    it('testSyncRdbStoreDelete0005', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreDelete0005 start *************");
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
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 38,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", "lisi")
            let ret = rdbStore.deleteSync(predicates)
            expect(2).assertEqual(ret)
            console.log(TAG + "Delete done: " + ret)
        }
        done()
        console.log(TAG + "************* testSyncRdbStoreDelete0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0060
     * @tc.name Abnormal test case of delete, if TABLE "name" is ""
     * @tc.desc 1.Configure predicates ("name", "")
     * 		2.Execute delete
     */
    it('testSyncRdbStoreDelete0006', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreDelete0006 start *************");

        try {
            let predicates = await new data_relationalStore.RdbPredicates("")
            let ret = rdbStore.deleteSync(predicates)
            expect(null).assertFail()
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
            done()
        }
        done()
        console.log(TAG + "************* testSyncRdbStoreDelete0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0070
     * @tc.name Abnormal test case of delete, if non system application calls
     * @tc.desc 1.Configure predicates (Calling system application)
     * 		2.Execute delete
     */
    it('testSyncRdbStoreDelete0007', 0, async function (done) {
        console.log(TAG + "************* testSyncRdbStoreDelete0007 start *************");
        try {
            var predicate = new dataSharePredicates.DataSharePredicates();
            rdbStore.deleteSync("test", predicate);
            expect(null).assertFail();
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("202").assertEqual(err.code)
            done()
        }
        console.log(TAG + "************* testSyncRdbStoreDelete0007 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})
