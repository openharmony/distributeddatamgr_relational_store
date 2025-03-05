/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

const TAG = "[RELATIONAL_STORE_JSKITS_MEMORY_DB_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "MemoryDbTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    persist: false,
}

var rdbStore = undefined
var context = ability_featureAbility.getContext()
function sleep(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    })
}
describe('rdbStoreMemoryDbTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await rdbStore.executeSql("DROP TABLE IF EXISTS test")
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "MemoryDbTest.db");
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number SUB_DDM_JSRDB_MEMORY_DB_NOT_SUPPORT_0001
     * @tc.name nor support test case of memory db
     * @tc.desc
     */
    it('testMemoryDbNotSupport0001', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbNotSupport0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("test");
        try {
            await rdbStore.cleanDirtyData("test");
            expect(null).assertFail()
        } catch (err) {
            console.log("cleanDirtyData catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            await rdbStore.backup("memoryBackup");
            expect(null).assertFail();
        } catch (err) {
            console.log("backup catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            await rdbStore.restore("memoryBackup");
            expect(null).assertFail();
        } catch (err) {
            console.log("restore catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            await rdbStore.setDistributedTables(["test"]);
            expect(null).assertFail();
        } catch (err) {
            console.log("setDistributedTables catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            await rdbStore.sync(data_relationalStore.SyncMode.SYNC_MODE_PUSH, predicates);
            expect(null).assertFail();
        } catch (err) {
            console.log("sync catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            await rdbStore.queryLockedRow(predicates);
            expect(null).assertFail();
        } catch (err) {
            console.log("queryLockedRow catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        done();
        console.log(TAG + "************* testMemoryDbNotSupport0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_JSRDB_MEMORY_DB_NOT_SUPPORT_0002
     * @tc.name nor support on test case of memory db
     * @tc.desc
     */
    it('testMemoryDbNotSupport0002', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbNotSupport0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("test");
        function storeObserver(devices) {
            console.info(TAG + devices + " dataChange");
            expect(devices).assertEqual(null)
        }
        try {
            rdbStore.on("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_REMOTE, storeObserver);
            expect(null).assertFail();
        } catch (err) {
            console.log("on dataChange SUBSCRIBE_TYPE_REMOTE catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            rdbStore.on("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_CLOUD, storeObserver);
            expect(null).assertFail();
        } catch (err) {
            console.log("on dataChange SUBSCRIBE_TYPE_CLOUD catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            rdbStore.on("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_CLOUD_DETAILS, storeObserver);
            expect(null).assertFail();
        } catch (err) {
            console.log("on dataChange SUBSCRIBE_TYPE_CLOUD_DETAILS catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            rdbStore.on("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver);
            expect(null).assertFail();
        } catch (err) {
            console.log("on dataChange SUBSCRIBE_TYPE_LOCAL_DETAILS catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            rdbStore.on("autoSyncProgress",function (detail) {
                console.log(TAG + `Progress:` + JSON.stringify(detail));
            });
            expect(null).assertFail();
        } catch (err) {
            console.log("on autoSyncProgress catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            rdbStore.on("shareEvent", true, function () {
            });
            expect(null).assertFail();
        } catch (err) {
            console.log("on interProcess catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        done();
        console.log(TAG + "************* testMemoryDbNotSupport0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_JSRDB_MEMORY_DB_NOT_SUPPORT_0003
     * @tc.name nor support getRdbStore test case of memory db
     * @tc.desc
     */
    it('testMemoryDbNotSupport0003', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbNotSupport0003 start *************");
        let config = {
            name: "testMemoryDbNotSupport0003.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            persist: false,
        }
        try {
            let tmp = JSON.parse(JSON.stringify(config))
            tmp.encrypt = true;
            let store = await data_relationalStore.getRdbStore(context, tmp);
            expect(null).assertFail();
        } catch (err) {
            console.log("getRdbStore encrypt catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            let tmp = JSON.parse(JSON.stringify(config))
            tmp.customDir = "/mem";
            let store = await data_relationalStore.getRdbStore(context, tmp);
            expect(null).assertFail();
        } catch (err) {
            console.log("getRdbStore customDir catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            let tmp = JSON.parse(JSON.stringify(config))
            tmp.rootDir = "/data/mem";
            let store = await data_relationalStore.getRdbStore(context, tmp);
            expect(null).assertFail();
        } catch (err) {
            console.log("getRdbStore rootDir catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            let tmp = JSON.parse(JSON.stringify(config))
            tmp.isSearchable = true;
            let store = await data_relationalStore.getRdbStore(context, tmp);
            expect(null).assertFail();
        } catch (err) {
            console.log("getRdbStore isSearchable catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            let tmp = JSON.parse(JSON.stringify(config))
            tmp.vector = true;
            let store = await data_relationalStore.getRdbStore(context, tmp);
            expect(null).assertFail();
        } catch (err) {
            console.log("getRdbStore vector catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            let tmp = JSON.parse(JSON.stringify(config))
            tmp.isReadOnly = true;
            let store = await data_relationalStore.getRdbStore(context, tmp);
            expect(null).assertFail();
        } catch (err) {
            console.log("getRdbStore isReadOnly catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            let tmp = JSON.parse(JSON.stringify(config))
            tmp.haMode = data_relationalStore.HAMode.MAIN_REPLICA;
            let store = await data_relationalStore.getRdbStore(context, tmp);
            expect(null).assertFail();
        } catch (err) {
            console.log("getRdbStore HAMode catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        try {
            let tmp = JSON.parse(JSON.stringify(config))
            tmp.cryptoParam = {
                encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y']),
                iterationCount: 25000,
                encryptionAlgo: data_relationalStore.EncryptionAlgo.AES_256_CBC,
                hmacAlgo: data_relationalStore.HmacAlgo.SHA512,
                kdfAlgo: data_relationalStore.KdfAlgo.KDF_SHA512,
                cryptoPageSize: 1024
            };
            await data_relationalStore.getRdbStore(context, tmp);
            expect(null).assertFail();
        } catch (err) {
            console.log("getRdbStore cryptoParam catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 801);
        }
        done();
        console.log(TAG + "************* testMemoryDbNotSupport0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_JSRDB_Insert_0001
     * @tc.name Normal test case of insert
     * @tc.desc 1.Insert data
     *          2.Query data
     */
    it('testMemoryDbInsert0001', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbInsert0001 start *************");
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
        console.log(TAG + "************* testMemoryDbInsert0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_JSRDB_Insert_0002
     * @tc.name Abnormal test case of insert, if TABLE name is wrong
     * @tc.desc 1.Create value
     *          2.Execute insert (with wrong table)
     */
    it('testMemoryDbInsert0002', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbInsert0002 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        try{
            let ret = await rdbStore.insert("wrong", valueBucket);
            console.log(TAG + "insert wrong success: " + ret)
            expect(null).assertFail()
        } catch (err) {
            console.log("testMemoryDbInsert0002 insert wrong catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect(true).assertEqual(err.code == 14800021);
        }
        done()
        console.log(TAG + "************* testMemoryDbInsert0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_JSRDB_Insert_0003
     * @tc.name Normal test case of insert (Chinese and long string)
     * @tc.desc 1.Insert data
     *          2.Configure predicates
     *          3.Query data
     */
    it('testMemoryDbInsert0003', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbInsert0003 start *************");
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
        console.log(TAG + "************* testMemoryDbInsert0003 end   *************");
    })

    /**
     * @tc.number SUB_DDM_JSRDB_Insert_With_Conflict_resolution_0001
     * @tc.name Abnormal test case of insert with ON_CONFLICT_ROLLBACK, if primary key conflict
     * @tc.desc 1.Insert data with ON_CONFLICT_ROLLBACK
     *          2.Create value (conflict "id")
     *          3.Begin Transaction
     *          4.Insert data
     *          5.Insert data with ON_CONFLICT_ROLLBACK (conflict "id")
     *          6.Query data
     */
    it('testMemoryDbInsertWithConflictResolution0001', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbInsertWithConflictResolution0001 start *************");
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

        console.log(TAG + "************* testMemoryDbInsertWithConflictResolution0001 end   *************");
    })

    /**
     * @tc.number SUB_DDM_JSRDB_BatchInsert_0001
     * @tc.name Normal test case of batchInsert
     * @tc.desc 1.Create valueBucket
     *          2.Execute push
     *          3.BatchInsert data
     *          4.Query data
     */
    it('testMemoryDbBatchInsert0001', 0, async function () {
        console.log(TAG + "************* testMemoryDbBatchInsert0001 start *************");

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
        console.log(TAG + "************* testMemoryDbBatchInsert0001 end *************");
    })

    /**
     * @tc.number testMemoryDbBatchInsertWithConflictResolution001
     * @tc.name batch insert with conflict resolution
     * @tc.desc normal batch insert with conflict resolution
     */
    it('testMemoryDbBatchInsertWithConflictResolution001', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbBatchInsertWithConflictResolution001 start *************");
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
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution001 batch num1 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK)
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution001 batch num2 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_ABORT)
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution001 batch num3 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_FAIL)
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution001 batch num4 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE)
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution001 batch num5 " + num)
            expect(2).assertEqual(num);

            num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE)
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution001 batch num6 " + num)
            expect(2).assertEqual(num);

            let resultSet = await rdbStore.querySql("select * from test")
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution001 result count " + resultSet.rowCount)
            expect(12).assertEqual(resultSet.rowCount)
            resultSet.close()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution001 failed");
        }
        done()
        console.log(TAG + "************* testMemoryDbBatchInsertWithConflictResolution001 end *************");
    })

    /**
     * @tc.number testMemoryDbBatchInsertWithConflictResolution002
     * @tc.name batch insert with conflict resolution
     * @tc.desc conflict when batch insert with conflict resolution
     */
    it('testMemoryDbBatchInsertWithConflictResolution002', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbBatchInsertWithConflictResolution002 start *************");
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
                console.log(TAG + e + "testMemoryDbBatchInsertWithConflictResolution002 ON_CONFLICT_NONE code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testMemoryDbBatchInsertWithConflictResolution002 ON_CONFLICT_ROLLBACK code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_ABORT);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testMemoryDbBatchInsertWithConflictResolution002 ON_CONFLICT_ABORT code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_FAIL);
                expect(null).assertFail();
            } catch (e) {
                console.log(TAG + e + "testMemoryDbBatchInsertWithConflictResolution002 ON_CONFLICT_FAIL code: " + e.code);
                expect(14800032).assertEqual(e.code)
            }
            try {
                let num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_IGNORE);
                console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution002 ON_CONFLICT_IGNORE num " + num)
                expect(2).assertEqual(num)
            } catch (e) {
                console.log(TAG + e + "testMemoryDbBatchInsertWithConflictResolution002 ON_CONFLICT_IGNORE code: " + e.code);
                expect(null).assertFail();
            }
            try {
                let num = await rdbStore.batchInsertWithConflictResolution("test", valueBucketArray,
                    data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
                console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution002 ON_CONFLICT_REPLACE num " + num)
                expect(5).assertEqual(num)
            } catch (e) {
                console.log(TAG + e + "testMemoryDbBatchInsertWithConflictResolution002 ON_CONFLICT_REPLACE code: " + e.code);
                expect(null).assertFail();
            }
            let resultSet = await rdbStore.querySql("select * from test")
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution002 result count " + resultSet.rowCount)
            expect(5).assertEqual(resultSet.rowCount)
            resultSet.close()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
            console.log(TAG + "testMemoryDbBatchInsertWithConflictResolution002 failed");
        }
        done()
        console.log(TAG + "************* testMemoryDbBatchInsertWithConflictResolution002 end *************");
    })

    /**
     * @tc.number testMemoryDbExecute0001
     * @tc.name Normal test case of Execute, check integrity for store
     * @tc.desc 1. Execute sql: PRAGMA integrity_check
     *          2. Check returned value
     */
    it('testMemoryDbExecute0001', 0, async function (done) {
        console.info(TAG + "************* testMemoryDbExecute0001 start *************");
        try {
            let ret = await rdbStore.execute("PRAGMA integrity_check");
            console.error("integrity_check result:" + ret);
            expect("ok").assertEqual(ret);
            ret = await rdbStore.execute("PRAGMA quick_check");
            console.error("quick_check result:" + ret);
            expect("ok").assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`check failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testMemoryDbExecute0001 end   *************");
    })

    /**
     * @tc.number testMemoryDbExecute0002
     * @tc.name Normal test case of Execute, get user_version of store
     * @tc.desc 1. Execute sql: PRAGMA user_version
     *          2. Check returned value
     */
    it('testMemoryDbExecute0002', 0, async function (done) {
        console.info(TAG + "************* testMemoryDbExecute0002 start *************");
        try {
            // set user_version as 5
            rdbStore.version = 5;
            let ret = await rdbStore.execute("PRAGMA user_version");
            // get user_version 5
            expect(5).assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`get user_version failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testMemoryDbExecute0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0004
     * @tc.name AbNormal test case of Execute, execute select sql
     * @tc.desc 1. Execute select sql
     *          2. Check returned value
     */
    it('testMemoryDbExecute0003', 0, async function (done) {
        console.info(TAG + "************* testMemoryDbExecute0003 start *************");
        try {
            await rdbStore.execute("SELECT * FROM test");
            expect(null).assertFail();
        } catch (err) {
            // 14800021: SQLite: Generic error.
            expect(14800021).assertEqual(err.code);
            console.error(`execute select sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testMemoryDbExecute0003 end   *************");
    })

    /**
     * @tc.number testMemoryDbExecute0004
     * @tc.name Normal test case of Execute, execute sql for inserting data
     * @tc.desc 1. Execute insert sql
     *          2. Check returned value
     */
    it('testMemoryDbExecute0004', 0, async function (done) {
        console.info(TAG + "************* testMemoryDbExecute0004 start *************");
        try {
            let ret = await rdbStore.execute("INSERT INTO test(name, age, salary) VALUES ('tt', 28, 50000)");
            // 1 represent that the last data is inserted in the first row
            expect(1).assertEqual(ret);
        } catch (err) {
            console.error(`execute select sql failed, code:${err.code}, message: ${err.message}`);
            expect(null).assertFail();
        }
        done();
        console.info(TAG + "************* testMemoryDbExecute0004 end   *************");
    })

    /**
     * @tc.number testMemoryDbExecute0005
     * @tc.name Normal test case of Execute, execute sql for inserting data
     * @tc.desc 1. Execute insert sql
     *          2. Check returned value
     */
    it('testMemoryDbExecute0005', 0, async function (done) {
        console.info(TAG + "************* testMemoryDbExecute0005 start *************");
        try {
            let ret = await rdbStore.execute("INSERT INTO test(name, age, salary) VALUES (?, ?, ?)", ['tt', 28, 50000]);
            // 1 represent that the last data is inserted in the first row
            expect(1).assertEqual(ret);
        } catch (err) {
            console.error(`execute insert sql failed, code:${err.code}, message: ${err.message}`);
            expect(null).assertFail();
        }
        done();
        console.info(TAG + "************* testMemoryDbExecute0005 end   *************");
    })

    /**
     * @tc.number testMemoryDbExecute0006
     * @tc.name Normal test case of Execute, execute sql for updating data
     * @tc.desc 1. Execute update sql
     *          2. Check returned value
     */
    it('testMemoryDbExecute0006', 0, async function (done) {
        console.info(TAG + "************* testMemoryDbExecute0006 start *************");
        try {
            let ret = await rdbStore.execute("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ? ,?)",
                ['tt', 28, 50000, 'ttt', 278, 500800]);
            // 2 represent that the last data is inserted in the second row
            expect(2).assertEqual(ret);

            ret = await rdbStore.execute("UPDATE test SET name='dd' WHERE id = 1");
            // 1 represent that effected row id
            expect(1).assertEqual(ret);
        } catch (err) {
            console.error(`execute update sql failed, code:${err.code}, message: ${err.message}`);
            expect(null).assertFail();
        }
        done();
        console.info(TAG + "************* testMemoryDbExecute0006 end   *************");
    })

    /**
     * @tc.number testMemoryDbExecute0007
     * @tc.name Normal test case of Execute, execute sql for deleting data
     * @tc.desc 1. Execute delete sql
     *          2. Check returned value
     */
    it('testMemoryDbExecute0007', 0, async function (done) {
        console.info(TAG + "************* testMemoryDbExecute0007 start *************");
        try {
            let ret = await rdbStore.execute("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ? ,?)",
                ['tt', 28, 50000, 'ttt', 278, 500800]);
            // 2 represent that the last data is inserted in the second row
            expect(2).assertEqual(ret);

            ret = await rdbStore.execute("DELETE FROM test");
            // 2 represent that effected row id
            expect(2).assertEqual(ret);
        } catch (err) {
            console.error(`execute delete sql failed, code:${err.code}, message: ${err.message}`);
            expect(null).assertFail();
        }
        done();
        console.info(TAG + "************* testMemoryDbExecute0007 end   *************");
    })

    /**
     * @tc.number testMemoryDbUpdate0001
     * @tc.name Normal test case of update
     * @tc.desc 1.Insert data
     *          2.Update data
     *          3.Query data
     */
    it('testMemoryDbUpdate0001', 0, async function () {
        console.log(TAG + "************* testMemoryDbUpdate0001 start *************");
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
            let ret = await rdbStore.update(valueBucket, predicates)
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

                expect(1).assertEqual(id);
                expect("lisi").assertEqual(name);
                expect(20).assertEqual(age);
                expect(200.5).assertEqual(salary);
                expect(4).assertEqual(blobType[0]);
                expect(5).assertEqual(blobType[1]);
                expect(6).assertEqual(blobType[2]);
                expect(false).assertEqual(resultSet.goToNextRow())
            } finally {
                resultSet.close()
                resultSet = null
            }
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }

        console.log(TAG + "************* testMemoryDbUpdate0001 end   *************");
    })

    /**
     * @tc.number testMemoryDbUpdate0002
     * @tc.name Normal test case of update, value is long string and special characters
     * @tc.desc 1.Insert data
     *          2.Update data
     *          3.Query data
     */
    it('testMemoryDbUpdate0002', 0, async function () {
        console.log(TAG + "************* testMemoryDbUpdate0002 start *************");
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
            let ret = await rdbStore.update(valueBucket, predicates)
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
        console.log(TAG + "************* testMemoryDbUpdate0002 end   *************");
    })

    /**
     * @tc.number testMemoryDbUpdate0003
     * @tc.name Normal test case of insert with ON_CONFLICT_REPLACE
     * @tc.desc 1.Insert data
     *          2.Create value
     *          3.Execute update with ON_CONFLICT_REPLACE
     *          4.Query data
     */
    it('testMemoryDbUpdate0003', 0, async function () {
        console.log(TAG + "************* testMemoryDbUpdate0003 start *************");
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
        console.log(TAG + "************* testMemoryDbUpdate0003 end   *************");
    })

    /**
     * @tc.number testMemoryDbDelete0001
     * @tc.name Normal test case of delete
     * @tc.desc 1.Insert data
     *		2.Execute delete
     */
    it('testMemoryDbDelete0001', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbDelete0001 start *************");
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
            let deletePromise = rdbStore.delete(predicates)
            deletePromise.then(async (ret) => {
                expect(3).assertEqual(ret)
                console.log(TAG + "Delete done: " + ret)
            }).catch((err) => {
                expect(null).assertFail()
            })
            await deletePromise
        }
        done()
        console.log(TAG + "************* testMemoryDbDelete0001 end *************");
    })

    /**
     * @tc.number testMemoryDbDelete0002
     * @tc.name Abnormal test case of delete, if column is invalid
     * @tc.desc 1.Insert data
     * 		    2.Configure predicates ("aaa id", 1)
     * 		    3.Execute delete
     */
    it('testMemoryDbDelete0002', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbDelete0002 start *************");
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
        console.log(TAG + "************* testMemoryDbDelete0002 end *************");
    })

    /**
     * @tc.name Normal case for Statistics insert data execution time
     * @tc.number testMemoryDbStatistics0001
     * @tc.desc 1. Register callback for statistics
     *          2. Insert data
     *          3. UnRegister callback
     */
    it('testMemoryDbStatistics0001', 0, async function (done) {
        console.info(TAG + "************* testMemoryDbStatistics0001 start *************");
        let sql = "";
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                sql = SqlExeInfo.sql[0];
                console.info(TAG + "on statistics success, sql:" + sql);
            })
        } catch (err) {
            console.error(TAG + `on statistics fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done()
        }

        try {
            const valueBucket1 = {
                'name': 'zhangsan',
                'age': 18,
                'salary': 25000,
                'blobType': new Uint8Array([1, 2, 3]),
            };
            let rowId = await rdbStore.insert('test', valueBucket1);
            expect(1).assertEqual(rowId);
            await sleep(500);
            expect('INSERT INTO test(age,blobType,name,salary) VALUES (?,?,?,?)').assertEqual(sql)
        } catch (error) {
            console.error(TAG + `testMemoryDbStatistics0001 fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
        }
        done();
        console.info(TAG + "************* testMemoryDbStatistics0001 end *************");
    })

    /**
     * @tc.number testMemoryDbQueryByStep0001
     * @tc.name Normal test case of queryByStep, query all data
     * @tc.desc 1. Execute queryByStep, sql is 'select * from test'
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testMemoryDbQueryByStep0001', 0, async function (done) {
        console.info(TAG + "************* testMemoryDbQueryByStep0001 start *************");
        try {
            let u8 = new Uint8Array([1, 2, 3]);
            let valuesBucket1 = {
                "name": "lisi",
                "age": 15,
                "salary": 153.3,
                "blobType": u8,
            }
            await rdbStore.insert("test", valuesBucket1);

            let valuesBucket2 = {
                "name": "tom",
                "age": 56,
                "salary": 1503.3,
            }
            await rdbStore.insert("test", valuesBucket2);

            let valuesBucket3 = {
                "name": "bob",
                "age": 116,
                "salary": 5503.3,
            }
            await rdbStore.insert("test", valuesBucket3);
            console.info(TAG, "testMemoryDbQueryByStep0001 insertTest data end");
            let resultSet = await rdbStore.queryByStep('select * from test');
            // resultSet.rowCount is 3
            expect(3).assertEqual(resultSet.rowCount);
            resultSet.close();
        } catch (err) {
            console.error(TAG + `query failed, err code:${err.code}, message:${err.message}`)
            expect().assertFail();
        }

        console.info(TAG + "************* testMemoryDbQueryByStep0001 end *************");
        done();
    })

    /**
     * @tc.number testMemoryDbExecuteSqlTest0006
     * @tc.name Normal test case of executeSql and querySql, PRAGMA table_info
     * @tc.desc 1.Get table_info
     *          2.Check table_info
     */
    it('testMemoryDbExecuteSqlTest0001', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbExecuteSqlTest0001 start *************");
        let resultSet = await rdbStore.querySql("PRAGMA table_info(test)");
        try{
            resultSet.goToFirstRow();
            expect(0).assertEqual(resultSet.getLong(0))
            expect("id").assertEqual(resultSet.getString(1))
            expect("INTEGER").assertEqual(resultSet.getString(2))
            resultSet.goToNextRow();
            expect(1).assertEqual(resultSet.getLong(0))
            expect("name").assertEqual(resultSet.getString(1))
            expect("TEXT").assertEqual(resultSet.getString(2))
            expect(1).assertEqual(resultSet.getLong(3))
            resultSet.goToNextRow();
            expect(2).assertEqual(resultSet.getLong(0))
            expect("age").assertEqual(resultSet.getString(1))
            expect("INTEGER").assertEqual(resultSet.getString(2))
            resultSet.goToNextRow();
            expect(3).assertEqual(resultSet.getLong(0))
            expect("salary").assertEqual(resultSet.getString(1))
            expect("REAL").assertEqual(resultSet.getString(2))
            resultSet.goToNextRow();
            expect(4).assertEqual(resultSet.getLong(0))
            expect("blobType").assertEqual(resultSet.getString(1))
            expect("BLOB").assertEqual(resultSet.getString(2))
            resultSet.close();
        }catch (err) {
            console.error(TAG + `testMemoryDbExecuteSqlTest0001 failed, err code:${err.code}, message:${err.message}`)
            expect().assertFail();
        }
        console.log(TAG + "************* testMemoryDbExecuteSqlTest0001 end   *************");
        done();
    })

    /**
     * @tc.number testMemoryDbExecuteSqlTest0002
     * @tc.name Normal test case of ExecuteSql
     * @tc.desc 1.Insert data (param is long string)
     *          2.Query data
     *          3.ExecuteSql (delete age = 19 AND name = nameStr)
     *          4.Query data
     */
    it('testMemoryDbExecuteSqlTest0002', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbExecuteSqlTest0002 start *************");
        var u8 = new Uint8Array([3, 4, 5])
        var nameStr = "lisi" + "e".repeat(2000) + "zhangsan"
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(1).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": nameStr,
                "age": 19,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(2).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": nameStr,
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(3).assertEqual(ret);
        }
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", nameStr)
            let querySqlPromise = rdbStore.query(predicates)
            querySqlPromise.then(async (resultSet) => {
                await expect(2).assertEqual(resultSet.rowCount)
                resultSet.close()
            }).catch((err) => {
                console.error(TAG + `testMemoryDbExecuteSqlTest0002 failed, err code:${err.code}, message:${err.message}`)
                expect(null).assertFail();
            })
            await querySqlPromise
        }
        {
            let executeSqlPromise = rdbStore.executeSql("DELETE FROM test WHERE age = 19 AND name ='" + nameStr + "'")
            executeSqlPromise.then(async () => {
                await console.log(TAG + "executeSql done.");
            }).catch((err) => {
                console.error(TAG + `testMemoryDbExecuteSqlTest0002 failed, err code:${err.code}, message:${err.message}`)
                expect(null).assertFail();
            })
            await executeSqlPromise
        }
        {
            let querySqlPromise = rdbStore.querySql("SELECT * FROM test WHERE name ='" + nameStr + "'")
            querySqlPromise.then(async (resultSet) => {
                await expect(1).assertEqual(resultSet.rowCount)
                expect(true).assertEqual(resultSet.goToFirstRow())
                const name = resultSet.getString(resultSet.getColumnIndex("name"))
                const age = resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                expect(nameStr).assertEqual(name)
                expect(2012).assertEqual(name.length)
                expect(28).assertEqual(age)
                expect(100.5).assertEqual(salary)
                expect(3).assertEqual(blobType[0])
                resultSet.close();
                done();
            }).catch((err) => {
                console.error(TAG + `testMemoryDbExecuteSqlTest0002 failed, err code:${err.code}, message:${err.message}`)
                expect(null).assertFail();
            })
            await querySqlPromise
        }
        console.log(TAG + "************* testMemoryDbExecuteSqlTest0002 end   *************");
    })

    /**
     * @tc.name testMemoryDbPluginLibs0001
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_plugin_Libs_0001
     * @tc.desc Test pluginLibs are empty
     */
    it('testMemoryDbPluginLibs0001', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbPluginLibs0001 start *************");
        try {
            const testPluginLibsConfig = {
                name: "testPluginLibs0001.db",
                securityLevel: data_relationalStore.SecurityLevel.S1,
                persist: false,
            }
            testPluginLibsConfig.pluginLibs = ["", ""]
            await data_relationalStore.getRdbStore(context, testPluginLibsConfig);
        } catch (e) {
            console.log("testMemoryDbPluginLibs0001 getRdbStore err: failed, err: code=" + e.code + " message=" + e.message)
            expect().assertFail();
        }
        done()
        console.log(TAG + "************* testMemoryDbPluginLibs0001 end   *************");
    })

    /**
     * @tc.name testMemoryDbTokenizer0001
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_plugin_Libs_0001
     * @tc.desc Test pluginLibs are empty
     */
    it('testMemoryDbTokenizer0001', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbTokenizer0001 start *************");
        try {
            const testPluginLibsConfig = {
                name: "testMemoryDbTokenizer0001.db",
                securityLevel: data_relationalStore.SecurityLevel.S1,
                persist: false,
                tokenizer:data_relationalStore.Tokenizer.ICU_TOKENIZER
            }
            await data_relationalStore.getRdbStore(context, testPluginLibsConfig);
        } catch (e) {
            console.log("testMemoryDbTokenizer0001 getRdbStore err: failed, err: code=" + e.code + " message=" + e.message)
            expect().assertFail();
        }
        done()
        console.log(TAG + "************* testMemoryDbTokenizer0001 end   *************");
    })

    /**
     * @tc.number testMemoryDbTransaction0001
     * @tc.name Normal test case of transactions, insert a row of data
     * @tc.desc 1.Execute beginTransaction
     *          2.BatchInsertSync data
     *          3.InsertSync data
     *          4.UpdateSync data
     *          5.DeleteSync data
     *          6.Execute commit
     *          7.querySqlSync
     *          7.ExecuteSync
     */
    it('testMemoryDbTransaction0001', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbTransaction0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var num = await transaction.insertSync("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
            expect(1).assertEqual(num);
            const updateValueBucket = {
                "name": "update",
                "age": 28,
                "salary": 25,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi")
            num = await transaction.updateSync(updateValueBucket, predicates)
            expect(1).assertEqual(num);

            let deletePredicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "update")
            num = await transaction.deleteSync(deletePredicates);
            expect(1).assertEqual(num);

            let resultSet = await transaction.querySqlSync("select * from test")
            console.log(TAG + "testMemoryDbTransaction0001 result count " + resultSet.rowCount)
            expect(0).assertEqual(resultSet.rowCount)
            resultSet.close()

            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testMemoryDbTransaction0001 failed");
        }
        done()
        console.log(TAG + "************* testMemoryDbTransaction0001 end *************");
    })

    /**
     * @tc.number testMemoryDbTransactionIsolation0002
     * @tc.name testTransactionIsolation. DEFERRED and EXCLUSIVE
     * @tc.desc 1.begin DEFERRED Transaction
     *          2.begin EXCLUSIVE Transaction again
     *          3.insert data with EXCLUSIVE Transaction
     *          4.query data with DEFERRED Transaction -> no data
     *          5.execute commit with EXCLUSIVE Transaction
     *          6.query data with DEFERRED Transaction -> no data  -> why? step 4 start isolation
     *          7.query data with Rdb -> has data
     */
    it('testMemoryDbTransactionIsolation0002', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbTransactionIsolation0002 start *************");
        var deferredTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            var exclusiveTrans = await rdbStore.createTransaction({
                transactionType: data_relationalStore.TransactionType.IMMEDIATE
            })
            try {
                const valueBucket = {
                    "name": "lisi",
                    "age": 18,
                    "salary": 100.5,
                }
                var insertRow = await exclusiveTrans.insert("test", valueBucket);
                console.log(TAG + "testMemoryDbTransactionIsolation0002 exclusiveTrans.insert row " + insertRow)
                expect(1).assertEqual(insertRow)

                var resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
                console.log(TAG + "testMemoryDbTransactionIsolation0002 deferredTrans querySqlSync before exclusiveTrans commit count " + resultSet.rowCount);
                expect(-1).assertEqual(resultSet.rowCount);
                resultSet.close()

                await exclusiveTrans.commit();

                resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
                console.log(TAG + "testMemoryDbTransactionIsolation0002 deferredTrans querySqlSync after exclusiveTrans commit count " + resultSet.rowCount);
                expect(1).assertEqual(resultSet.rowCount);

                resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
                console.log(TAG + "testMemoryDbTransactionIsolation0002 rdbStore querySqlSync after exclusiveTrans commit count " + resultSet.rowCount);
                expect(1).assertEqual(resultSet.rowCount);
                resultSet.close()

            } catch (e) {
                exclusiveTrans.rollback();
                console.log(TAG + e);
                expect(null).assertFail()
                console.log(TAG + "insert failed");
            }
            await deferredTrans.commit();
        } catch (e) {
            await deferredTrans.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testMemoryDbTransactionIsolation0002 failed");
        }
        done()
        console.log(TAG + "************* testMemoryDbTransactionIsolation0002 end *************");
    })

    /**
     * @tc.number testMemoryDbTransactionIsolation0003
     * @tc.name testTransactionIsolation. IMMEDIATE and rdbStore
     * @tc.desc 1.begin IMMEDIATE Transaction
     *          2.insert data with rdbStore -> busy
     *          3.insert data with IMMEDIATE Transaction
     *          4.execute commit with IMMEDIATE Transaction
     *          5.query data with rdbStore -> has data
     */
    it('testMemoryDbTransactionIsolation0003', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbTransactionIsolation0003 start *************");
        var immediateTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.IMMEDIATE
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            try {
                await rdbStore.insert("test", valueBucket);
                console.log(TAG + "testMemoryDbTransactionIsolation0003 rdbStore.insert success ");
                expect(null).assertFail()
            } catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800025)
                console.log(TAG + "insert failed");
            }
            var insertRow = await immediateTrans.insert("test", valueBucket);
            console.log(TAG + "testMemoryDbTransactionIsolation0003 immediateTrans.insert row " + insertRow);
            expect(insertRow).assertEqual(1);

            await immediateTrans.commit();

            var resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testMemoryDbTransactionIsolation0003 querySqlSync count " + resultSet.rowCount);
            expect(1).assertEqual(resultSet.rowCount);
            resultSet.close()
        } catch (e) {
            await immediateTrans.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testMemoryDbTransactionIsolation0003 failed");
        }
        done()
        console.log(TAG + "************* testMemoryDbTransactionIsolation0003 end *************");
    })

    /**
     * @tc.number testMemoryDbTransactionIsolation0004
     * @tc.name testTransactionIsolation. DEFERRED and rdbStore
     * @tc.desc 1.begin DEFERRED Transaction
     *          2.insert data with rdbStore
     *          3.insert data with DEFERRED Transaction
     *          4.query data with rdbStore -> has 2 row
     *          5.insert data with rdbStore again -> busy
     *          6.query data with DEFERRED Transaction -> has 2 row
     *          7.execute commit with DEFERRED Transaction
     *          8.insert data with rdbStore again
     *          9.query data with rdbStore -> has 3 row
     */
    it('testMemoryDbTransactionIsolation0004', 0, async function (done) {
        console.log(TAG + "************* testMemoryDbTransactionIsolation0004 start *************");
        var deferredTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            await rdbStore.insert("test", valueBucket);

            await deferredTrans.insert("test", valueBucket);

            var resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testMemoryDbTransactionIsolation0004 rdbStore.querySqlSync count " + resultSet.rowCount);
            // because sqlite_locked
            expect(-1).assertEqual(resultSet.rowCount);

            try {
                await rdbStore.insert("test", valueBucket);
                console.log(TAG + "testMemoryDbTransactionIsolation0004 insert success ");
                expect(null).assertFail()
            } catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800025)
                console.log(TAG + "insert failed");
            }
            resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testMemoryDbTransactionIsolation0004 deferredTrans.querySqlSync count " + resultSet.rowCount);
            expect(2).assertEqual(resultSet.rowCount);

            await deferredTrans.commit();

            await rdbStore.insert("test", valueBucket);

            resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testMemoryDbTransactionIsolation0004 rdbStore.querySqlSync after deferredTrans commit count " + resultSet.rowCount);
            expect(3).assertEqual(resultSet.rowCount);
            resultSet.close()
        } catch (e) {
            await deferredTrans.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testMemoryDbTransactionIsolation0004 failed");
        }
        done()
        console.log(TAG + "************* testMemoryDbTransactionIsolation0004 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})