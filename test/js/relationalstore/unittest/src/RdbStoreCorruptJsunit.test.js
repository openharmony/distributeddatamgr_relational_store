/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'
import fs from '@ohos.file.fs'


var context = ability_featureAbility.getContext();

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "data1 text," + "data2 long, " + "data3 double," + "data4 blob)";
const CREATE_TABLE_TEST1 = "CREATE TABLE IF NOT EXISTS test1 (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "data1 text," + "data2 long, " + "data3 double," + "data4 blob)";
const dbName = "Resultset.db"
let STORE_CONFIG = {
    name: dbName,
    securityLevel: data_relationalStore.SecurityLevel.S1,
    allowRebuild: false,
}
var rdbStore = undefined;
const dbPath = "/data/storage/el2/database/entry/rdb/" + dbName;
const dbPathWal = "/data/storage/el2/database/entry/rdb/" + dbName + "-wal";
const dbPathShm = "/data/storage/el2/database/entry/rdb/" + dbName + "-shm";

describe('RdbStoreCorruptTest', function () {
    beforeAll(async function () {
        console.log(TAG + 'beforeAll');
    })

    beforeEach(async function () {
        console.log(TAG + 'beforeEach');
    })

    afterEach(async function () {
        console.log(TAG + 'afterEach')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "Resultset.db");
    })

    afterAll(async function () {
        console.log(TAG + 'afterAll');
    })

    async function Generate() {
        let dir = await context.getFilesDir();
        console.log(TAG, `filepath is${dir},databaseDir is${context.databaseDir},dbpath is${dbPath}`)
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
        await createTest();
        let u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
            "data1": 'hello'.repeat(500),
            "data2": 10,
            "data3": 1.0,
            "data4": u8,
        }
        let valueBucketArray = new Array();
        for (let i = 0; i < 100; ++i) {
            valueBucketArray.push(valueBucket);
        }
        let count = await rdbStore.batchInsert("test", valueBucketArray)
        rdbStore.close();
        rdbStore = null
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        try {
            await CreateCorruptDb();
        } catch (e) {
            console.log(TAG, `catch error,errCode${e.code}`);
            expect(null).assertFail();
        }
    }

    async function CreateCorruptDb() {
        try {
            let fileExist = fs.accessSync(dbPath);
            expect(fileExist).assertTrue();
            fs.truncateSync(dbPathWal, 4)
            fs.truncateSync(dbPathShm, 4)
            let file = fs.openSync(dbPath, fs.OpenMode.READ_WRITE);
            fs.truncateSync(file.fd, 4);
            fs.fsyncSync(file.fd)
            fs.closeSync(file)
        } catch (err) {
            console.log(TAG, `CreateCorruptDb err.code ${err.code}, err.message ${err.message}`)
        }
        console.log(TAG, `quit create corrupt store`);
    }

    async function createTest() {
        console.log(TAG, "createTest data start");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "data1": "hello",
                "data2": 10,
                "data3": 1.0,
                "data4": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([3, 4, 5])
            const valueBucket = {
                "data1": "2",
                "data2": -5,
                "data3": 2.5,
                "data4": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array(0)
            const valueBucket = {
                "data1": "hello world",
                "data2": 3,
                "data3": 1.8,
                "data4": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        console.log(TAG, "createTest data end");
    }
    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name the rebuilt function
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_rebuilt_001
     * @tc.desc rebuild the database while corrupt
     */
    it('rebuiltTest001', 0, async function (done) {
        console.log(TAG + "************* rebuiltTest001 start *************");
        await Generate();
        await rdbStore.close();
        rdbStore = undefined;
        try {
            rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        } catch (e) {
            console.log(TAG, `rebuiltTest001 open error ${e.code}. ${e.message}`);
            expect(14800011).assertEqual(e.code);
        }
        rdbStore = undefined;
        let STORE_CONFIG1 = {
            name: dbName,
            securityLevel: data_relationalStore.SecurityLevel.S1,
            allowRebuild: true,
        }

        try {
            rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG1);
            expect(rdbStore == null).assertFalse();
            expect(rdbStore.rebuilt).assertEqual(data_relationalStore.RebuildType.REBUILT);
        } catch (e) {
            console.log(TAG, `rebuiltTest001 reopen failed ${e.code}`);
            expect().assertFail();
        }
        done();
        console.log(TAG + "************* rebuiltTest001 end *************");
    })

    /**
     * @tc.name the insert function
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_insert_002
     * @tc.desc insert while corrupt
     */
    it('insertTest0001', 0, async function (done) {
        console.log(TAG + "************* insertTest0001 start *************");
        await Generate()
        var u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
            "data1": "hello",
            "data2": 10,
            "data3": 1.0,
            "data4": u8,
        }
        try {
            await rdbStore.insert("test", valueBucket);
            expect(null).assertFalse();
        } catch (e) {
            console.log(TAG, `insertTest0001 insert error ${e.code}, message ${e.message}`);
            expect(14800011).assertEqual(e.code);
        }
        done();
        console.log(TAG + "************* insertTest0001 end *************");
    })

    /**
     * @tc.name the batchInsert function
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_batch_insert_001
     * @tc.desc batchInsert while corrupt
     */
    it('batchInsertTest0001', 0, async function (done) {
        console.log(TAG + "************* batchInsertTest0001 start *************");
        await Generate();
        var u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
            "data1": "hello",
            "data2": 10,
            "data3": 1.0,
            "data4": u8,
        }
        let valueBucketArray = new Array();
        for (let i = 0; i < 100; ++i) {
            valueBucketArray.push(valueBucket);
        }
        try {
            await rdbStore.batchInsert("test", valueBucketArray);
        } catch (e) {
            console.log(TAG, `batchInsertTest0001 insert error ${e.code}`);
            expect(14800011).assertEqual(e.code);
        }
        done();
        console.log(TAG + "************* batchInsertTest0001 end *************");
    })

    /**
     * @tc.name the update function
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_update_001
     * @tc.desc update while corrupt
     */
    it('updateTest0001', 0, async function (done) {
        console.log(TAG + "************* updateTest0001 start *************");
        await Generate();
        let u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
            "data1": "failed",
            "data2": 10,
            "data3": 1.0,
            "data4": u8,
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("id", 88).or().equalTo("id", 89).or().equalTo("id", 90).or().equalTo("id", 91);
            let ret = await rdbStore.update(valueBucket, predicates);
            console.log(TAG, `updateTest0001 update count ${ret}`);
            expect().assertFail();
        } catch (e) {
            console.log(TAG, `updateTest0001 update error ${e.code}`);
            expect(14800011).assertEqual(e.code);
        }
        done();
        console.log(TAG + "************* updateTest0001 end *************");
    })

    /**
     * @tc.name the delete function
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_delete_001
     * @tc.desc delete while corrupt
     */
    it('deleteTest0001', 0, async function (done) {
        console.log(TAG + "************* deleteTest0001 start *************");
        await Generate();
        try {
            let u8 = new Uint8Array([1, 2, 3]);
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("data1", "hello");
            await rdbStore.delete(predicates);
            expect().assertFail();
        } catch (e) {
            console.log(TAG, `deleteTest0001 insert error ${e.code}`);
            expect(14800011).assertEqual(e.code);
        }
        done();
        console.log(TAG + "************* deleteTest0001 end *************");
    })

    /**
     * @tc.name the execute function
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_execute_001
     * @tc.desc execute while corrupt
     */
    it('executeTest0001', 0, async function (done) {
        console.log(TAG + "************* executeTest0001 start *************");
        await Generate();
        try {
            await rdbStore.execute(CREATE_TABLE_TEST1);
            expect().assertFail();
        } catch (e) {
            console.log(TAG, `executeTest0001 insert error ${e.code}`);
            expect(14800011).assertEqual(e.code);
        }
        done();
        console.log(TAG + "************* executeTest0001 end *************");
    })

    /**
     * @tc.name the executeSql function
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_executeSql_001
     * @tc.desc executeSql while corrupt
     */
    it('executeSqlTest0001', 0, async function (done) {
        console.log(TAG + "************* executeSqlTest0001 start *************");
        await Generate();
        const SQL_DELETE_TABLE = "DEletE FROM TEST WHERE data1 = '2'";
        try {
            await rdbStore.executeSql(SQL_DELETE_TABLE);
            expect(true).assertFail();
        } catch (e) {
            console.log(TAG, `executeSqlTest0001 insert error ${e.code}`);
            expect(14800011).assertEqual(e.code);
        }
        done();
        console.log(TAG + "************* executeSqlTest0001 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})