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
var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "rdbstore.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG1 = {
    name: "rdbstore1.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
describe('rdbStoreTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
    })

    beforeEach(function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name rdb store getRdbStore test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0010
     * @tc.desc rdb store getRdbStore test
     */
    it('testRdbStore0001', 0, async function () {
        console.log(TAG + "************* testRdbStore0001 start *************");
        try {
            let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
            console.log(TAG + "getRdbStore done: " + store);
            store = null
        } catch (e) {
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStore0001 end   *************");
    })

    /**
     * @tc.name rdb store getRdbStore and create table
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0020
     * @tc.desc rdb store getRdbStore and create table
     */
    it('testRdbStore0002', 0, async function () {
        console.log(TAG + "************* testRdbStore0002 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        try {
            console.log(TAG + "getRdbStore done: " + store);
            await store.executeSql(CREATE_TABLE_TEST);
        } catch (e) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0002 end   *************");
    })

    /**
     * @tc.name rdb storegetRdbStore with wrong path
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0030
     * @tc.desc rdb store getRdbStore with wrong path
     */
    it('testRdbStore0003', 0, async function () {
        console.log(TAG + "************* testRdbStore0003 start *************");
        let storeConfig = {
            name: "/wrong/rdbstore.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
        }
        try {
            await data_relationalStore.getRdbStore(context, storeConfig)
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect("401").assertEqual(e.code)
            console.info(TAG + "************* testRdbStore0003 end   *************");
        }
    })

    /**
     * @tc.name rdb store deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0040
     * @tc.desc rdb store deleteRdbStore
     */
    it('testRdbStore0004', 0, async function () {
        console.log(TAG + "************* testRdbStore0004 start *************");
        try {
            let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
            await store.executeSql(CREATE_TABLE_TEST);
        } catch (e) {
            console.log(TAG + "create table error");
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStore0004 end   *************");
    })

    /**
     * @tc.name rdb store setVersion & getVersion
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0050
     * @tc.desc rdb store setVersion & getVersion
     */
    it('testRdbStore0005', 0, async function () {
        console.log(TAG + "************* testRdbStore0005 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);

        try {
            store.version = 5
            expect(5).assertEqual(store.version)
            store.version = 2147483647
            expect(2147483647).assertEqual(store.version)
        } catch (e) {
            expect().assertFail();
        }
        store = null

        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        console.log(TAG + "************* testRdbStore0005 end   *************");
    })

    /**
     * @tc.name rdb store setVersion & getVersion
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0060
     * @tc.desc rdb store setVersion
     */
    it('testRdbStore0006', 0, async function () {
        console.log(TAG + "************* testRdbStore0006 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);

        try {
            store.version = -2147483648;
        } catch (err) {
            expect("401").assertEqual(err.code);
        }

        try {
            store.version = 2147483647000;
        } catch (err) {
            expect("401").assertEqual(err.code);
        }

        try {
            store.version = 0;
        } catch (err) {
            expect("401").assertEqual(err.code);
        }
        store = null

        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        console.log(TAG + "************* testRdbStore0006 end   *************");
    })

    /**
     * @tc.name rdb store getRdbStore with securityLevel
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0070
     * @tc.desc rdb store getRdbStore with securityLevel
     * @tc.require: I5PIL6
     */
    it('testRdbStore0007', 0, async function () {
        console.log(TAG + "************* testRdbStore0007 start *************");
        let config = {
            name: "secure.db",
            securityLevel: data_relationalStore.SecurityLevel.S3
        }
        try {
            let store = await data_relationalStore.getRdbStore(context, config);
            await store.executeSql(CREATE_TABLE_TEST);
            store = null
            await data_relationalStore.deleteRdbStore(context, "secure.db");
        } catch (e) {
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStore0007 end   *************");
    })

    /**
     * @tc.name rdb store getRdbStore with invalid securityLevel
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0080
     * @tc.desc rdb store getRdbStore with invalid securityLevel
     * @tc.require: I5PIL6
     */
    it('testRdbStore0008', 0, async function () {
        console.log(TAG + "************* testRdbStore0008 start *************");
        let config = {
            name: "secure.db",
            securityLevel: 8
        }
        try {
            await data_relationalStore.getRdbStore(context, config);
        } catch (err) {
            expect("401").assertEqual(err.code)
        }
        console.log(TAG + "************* testRdbStore0008 end   *************");
    })

    /**
     * @tc.name rdb store getRdbStore with different securityLevel
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0009
     * @tc.desc rdb store getRdbStore with different securityLevel
     * @tc.require: I5PIL6
     */
    it('testRdbStore0009', 0, async function () {
        console.log(TAG + "************* testRdbStore0009 start *************");
        let config1 = {
            name: "rdbstore9.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
        }

        let config2 = {
            name: "rdbstore9.db",
            securityLevel: data_relationalStore.SecurityLevel.S2,
        }

        await data_relationalStore.getRdbStore(context, config1);

        try {
            await data_relationalStore.getRdbStore(context, config2);
        } catch (err) {
            console.log(TAG + "************* testRdbStore0009 end   *************");
        }
    })

    /**
     * @tc.name rdb store getRdbStore with different securityLevel
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0100
     * @tc.desc rdb store getRdbStore with different securityLevel
     * @tc.require: I5PIL6
     */
    it('testRdbStore0010', 0, async function (done) {
        console.log(TAG + "************* testRdbStore0010 start *************");
        let config1 = {
            name: "rdbstore10.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
        }

        let config2 = {
            name: "rdbstore10.db",
            securityLevel: data_relationalStore.SecurityLevel.S2,
        }

        await data_relationalStore.getRdbStore(context, config1);

        data_relationalStore.getRdbStore(context, config2, async (err, rdbStore) => {
            if (err) {
                done()
                console.log(TAG + "************* testRdbStore0010 end   *************");
            } else {
                console.log("Get RdbStore successfully.")
                expect(true).assertTrue()
                done()
            }
        })
    })

    /**
     * @tc.name rdb store getRdbStore with invalid securityLevel
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0110
     * @tc.desc rdb store getRdbStore with invalid securityLevel
     */
    it('testRdbStore0011', 0, async function () {
        console.log(TAG + "************* testRdbStore0011 start *************");
        let config = {
            name: "search.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            isSearchable: true
        }
        let store = await data_relationalStore.getRdbStore(context, config);
        try {
            store.isSearchable = true
            expect(true).assertEqual(store.isSearchable)
        } catch (err) {
            expect("401").assertEqual(err.code)
        }
        store = null
        console.log(TAG + "************* testRdbStore0011 end   *************");
    })

    /**
     * @tc.name rdb store wal file overlimit test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0120
     * @tc.desc Checkpoint failure delayed retry
     */
    it('testRdbStore0012', 0, async function (done) {
        console.log(TAG + "************* testRdbStore0012 start *************");

        try {
            const rowCount = 18;
            const rdbStore = await data_relationalStore.getRdbStore(context, {
                name: "walTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                encrypt: true,
            })
            const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                + "blobType BLOB)";

            rdbStore.executeSync(CREATE_TABLE_TEST);
            const valueBuckets = Array(rowCount).fill(0).map(() => {
                return {
                    blobType: new Uint8Array(Array(1024 * 1024).fill(1)),
                }
            })

            rdbStore.batchInsertSync('test', valueBuckets);

            const predicates = new data_relationalStore.RdbPredicates('test');
            const resultSet = rdbStore.querySync(predicates);
            expect(resultSet.rowCount).assertEqual(rowCount);
            resultSet.goToFirstRow()
            const value = new Uint8Array(Array(1024 * 1024).fill(1));
            const startTime = new Date().getTime();
            rdbStore.insertSync('test', {
                blobType: new Uint8Array(Array(1024 * 1024).fill(1)),
            })
            const middleTime = new Date().getTime();
            console.log(TAG + "testRdbStore0012, startTime:" + startTime + " middleTime:" + middleTime + " costTime" + (middleTime-startTime));
            expect((middleTime - startTime) > 500).assertTrue();

            rdbStore.insertSync('test', {
                blobType: value,
            })
            const endTime = new Date().getTime();
            console.log(TAG + "testRdbStore0012, endTime:" + endTime + " middleTime:" + middleTime + " costTime" + (endTime-middleTime));
            expect((endTime - middleTime) < 500).assertTrue();

            console.log(TAG + "************* testRdbStore0012 end *************");
            done();
        } catch (e) {
            console.log(TAG + "testRdbStore0012 failed " + JSON.stringify(e));
            done();
            expect().assertFail();
        }
    })

    /**
     * @tc.name rdb store update after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0130
     * @tc.desc rdb store update after deleteRdbStore
     */
    it('testRdbStore0013', 0, async function () {
        console.log(TAG + "************* testRdbStore0013 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);

        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await store.insert("test", valueBucket)

        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            const valueBucket1 = {
                "name": "zhangsan",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("NAME", "zhangsan");
            await store.update(valueBucket1, predicates)
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0013 end *************");
    })

    /**
     * @tc.name rdb store insert after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0140
     * @tc.desc rdb store insert after deleteRdbStore
     */
    it('testRdbStore0014', 0, async function () {
        console.log(TAG + "************* testRdbStore0014 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            var u8 = new Uint8Array([1, 2, 3])
            {
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": u8,
                }
                await store.insert("test", valueBucket)
            }
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0014 end *************");
    })

    /**
     * @tc.name rdb store batchInsert after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0150
     * @tc.desc rdb store batchInsert after deleteRdbStore
     */
    it('testRdbStore0015', 0, async function () {
        console.log(TAG + "************* testRdbStore0015 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);

        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        let valueBucketArray = new Array();
        for (let i = 0; i < 10; i++) {
            valueBucketArray.push(valueBucket);
        }

        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.batchInsert("test", valueBucketArray)
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0015 end *************");
    })

    /**
     * @tc.name rdb store delete after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0160
     * @tc.desc rdb store delete after deleteRdbStore
     */
    it('testRdbStore0016', 0, async function () {
        console.log(TAG + "************* testRdbStore0016 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await store.insert("test", valueBucket)
        }
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await store.delete(predicates)
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0016 end *************");
    })

    /**
     * @tc.name rdb store query after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0170
     * @tc.desc rdb store query after deleteRdbStore
     */
    it('testRdbStore0017', 0, async function () {
        console.log(TAG + "************* testRdbStore0017 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await store.insert("test", valueBucket)
        }
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await store.query(predicates)
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0017 end *************");
    })

    /**
     * @tc.name rdb store querySql after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0180
     * @tc.desc rdb store querySql after deleteRdbStore
     */
    it('testRdbStore0018', 0, async function () {
        console.log(TAG + "************* testRdbStore0018 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await store.insert("test", valueBucket)
        }
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.querySql("SELECT * FROM test")
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0018 end *************");
    })

    /**
     * @tc.name rdb store backup after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0190
     * @tc.desc rdb store backup after deleteRdbStore
     */
    it('testRdbStore0019', 0, async function () {
        console.log(TAG + "************* testRdbStore0019 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.backup("backup.db");
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0019 end *************");
    })

    /**
     * @tc.name rdb store restore after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0200
     * @tc.desc rdb store restore after deleteRdbStore
     */
    it('testRdbStore0020', 0, async function () {
        console.log(TAG + "************* testRdbStore0020 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.backup("backup.db");
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.restore("backup.db");
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0020 end *************");
    })

    /**
     * @tc.name rdb store cleanDirtyData after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0210
     * @tc.desc rdb store cleanDirtyData after deleteRdbStore
     */
    it('testRdbStore0021', 0, async function () {
        console.log(TAG + "************* testRdbStore0021 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.cleanDirtyData('test')
            expect().assertFail();
        } catch (err) {
            expect(14800000).assertEqual(err.code)
        }
        store = null
        console.log(TAG + "************* testRdbStore0021 end *************");
    })

    /**
     * @tc.name rdb store executeSql after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0220
     * @tc.desc rdb store executeSql after deleteRdbStore
     */
    it('testRdbStore0022', 0, async function () {
        console.log(TAG + "************* testRdbStore0022 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.executeSql(CREATE_TABLE_TEST)
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0022 end *************");
    })

    /**
     * @tc.name rdb store execute after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0230
     * @tc.desc rdb store execute after deleteRdbStore
     */
    it('testRdbStore0023', 0, async function () {
        console.log(TAG + "************* testRdbStore0023 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.execute(CREATE_TABLE_TEST)
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0023 end *************");
    })

    /**
     * @tc.name rdb store beginTransaction after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0240
     * @tc.desc rdb store beginTransaction after deleteRdbStore
     */
    it('testRdbStore0024', 0, async function () {
        console.log(TAG + "************* testRdbStore0024 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            store.beginTransaction();
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0024 end *************");
    })

    /**
     * @tc.name rdb store setDistributedTables after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0250
     * @tc.desc rdb store setDistributedTables after deleteRdbStore
     */
    it('testRdbStore0025', 0, async function () {
        console.log(TAG + "************* testRdbStore0025 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.setDistributedTables(['test'])
            expect().assertFail();
        } catch (err) {
            expect(14800000).assertEqual(err.code);
        }
        store = null
        console.log(TAG + "************* testRdbStore0025 end *************");
    })

    /**
     * @tc.name rdb store attach after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0260
     * @tc.desc rdb store attach after deleteRdbStore
     */
    it('testRdbStore0026', 0, async function () {
        console.log(TAG + "************* testRdbStore0026 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.attach(context, STORE_CONFIG1, "attachDB");
            expect().assertFail();
        } catch (err) {
            expect(14800010).assertEqual(err.code);
        }
        store = null
        console.log(TAG + "************* testRdbStore0026 end *************");
    })

    /**
     * @tc.name rdb store detach after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0270
     * @tc.desc rdb store detach after deleteRdbStore
     */
    it('testRdbStore0027', 0, async function () {
        console.log(TAG + "************* testRdbStore0027 start *************");

        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await data_relationalStore.getRdbStore(context, STORE_CONFIG1);
        await store.executeSql(CREATE_TABLE_TEST);

        await store.attach(context, STORE_CONFIG1, "attachDB");
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.detach("attachDB")
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0027 end *************");
    })

    /**
     * @tc.name rdb store createTransaction after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0280
     * @tc.desc rdb store createTransaction after deleteRdbStore
     */
    it('testRdbStore0028', 0, async function () {
        console.log(TAG + "************* testRdbStore0028 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");

        try {
            await store?.createTransaction({
                transactionType: data_relationalStore.TransactionType.IMMEDIATE
            });
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0028 end *************");
    })

    /**
     * @tc.name rdb store beginTrans after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0290
     * @tc.desc rdb store beginTrans after deleteRdbStore
     */
    it('testRdbStore0029', 0, async function () {
        console.log(TAG + "************* testRdbStore0029 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.beginTrans();
            expect().assertFail();
        } catch (err) {
            expect(801).assertEqual(err.code);
        }
        store = null
        console.log(TAG + "************* testRdbStore0029 end *************");
    })

    /**
     * @tc.name rdb store commit after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0300
     * @tc.desc rdb store commit after deleteRdbStore
     */
    it('testRdbStore0030', 0, async function () {
        console.log(TAG + "************* testRdbStore0030 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);

        store.beginTransaction();
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await store.insert("test", valueBucket)
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            store.commit();
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0030 end *************");
    })

    /**
     * @tc.name rdb store getModifyTime after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0310
     * @tc.desc rdb store getModifyTime after deleteRdbStore
     */
    it('testRdbStore0031', 0, async function () {
        console.log(TAG + "************* testRdbStore0031 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await store.insert("test", valueBucket)
        }
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            await store.getModifyTime('test', 'name', [1]);
            expect().assertFail();
        } catch (err) {
            expect(14800000).assertEqual(err.code);
        }
        store = null
        console.log(TAG + "************* testRdbStore0031 end *************");
    })

    /**
     * @tc.name rdb store rollBack after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0320
     * @tc.desc rdb store rollBack after deleteRdbStore
     */
    it('testRdbStore0032', 0, async function () {
        console.log(TAG + "************* testRdbStore0032 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);

        store.beginTransaction();
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await store.insert("test", valueBucket)
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
        try {
            store.rollBack();
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0032 end *************");
    })

    /**
     * @tc.name rdb store queryLockedRow after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0330
     * @tc.desc rdb store queryLockedRow after deleteRdbStore
     */
    it('testRdbStore0033', 0, async function () {
        console.log(TAG + "************* testRdbStore0033 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);

        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await store.insert("test", valueBucket)
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");

        try {
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo('age', 18);
            await store.queryLockedRow(predicates);
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0033 end *************");
    })

    /**
     * @tc.name rdb store lockRow after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0340
     * @tc.desc rdb store lockRow after deleteRdbStore
     */
    it('testRdbStore0034', 0, async function () {
        console.log(TAG + "************* testRdbStore0034 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);

        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await store.insert("test", valueBucket)
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");

        try {
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo('age', 18);
            await store.lockRow(predicates);
            expect().assertFail();
        } catch (err) {
            expect(14800018).assertEqual(err.code);
        }
        store = null
        console.log(TAG + "************* testRdbStore0034 end *************");
    })

    /**
     * @tc.name rdb store unlockRow after deleteRdbStore
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0350
     * @tc.desc rdb store unlockRow after deleteRdbStore
     */
    it('testRdbStore0035', 0, async function () {
        console.log(TAG + "************* testRdbStore0035 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);

        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await store.insert("test", valueBucket)
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");

        try {
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo('age', 18);
            await store.unlockRow(predicates);
            expect().assertFail();
        } catch (err) {
            expect(14800018).assertEqual(err.code);
        }
        store = null
        console.log(TAG + "************* testRdbStore0035 end *************");
    })

    /**
    * @tc.name rdb store transaction insert after deleteRdbStore
    * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0360
    * @tc.desc rdb store transaction insert after deleteRdbStore
    */
    it('testRdbStore0036', 0, async function () {
        console.log(TAG + "************* testRdbStore0036 start *************");
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
        var transaction = await store?.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        await data_relationalStore.deleteRdbStore(context, "rdbstore.db");

        try {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await transaction.insert("test", valueBucket)
        } catch (err) {
            expect().assertFail();
        }
        store = null
        console.log(TAG + "************* testRdbStore0036 end *************");
    })

    /**
     * @tc.name rootDir support test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0037
     * @tc.desc invalid rootDir path async
     */
    it('testRdbStore0037', 0, async function (done) {
        console.log(TAG + "************* testRdbStore0037 start *************");
        try {
            await data_relationalStore.getRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "invalidPath",
                customDir: "entry/rdb"
            });
            expect().assertFail();
        } catch (e) {
            expect("14800010").assertEqual(e.code);
        }
        console.log(TAG + "************* testRdbStore0037 end *************");
        done();
    })

    /**
     * @tc.name rootDir support test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0038
     * @tc.desc invalid rootDir path callback
     */
    it('testRdbStore0038', 0, async (done) => {
        console.log(TAG + "************* testRdbStore0038 start *************");
        try {
            data_relationalStore.getRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "invalidPath",
                customDir: "entry/rdb"
            }, () => {
                expect().assertFail();
            })
        } catch (e) {
            expect("14800010").assertEqual(e.code);
            console.log(TAG + "************* testRdbStore0038 end *************");
            done();
        };
    })

    /**
     * @tc.name rootDir support test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0039
     * @tc.desc db not exist test async
     */
    it('testRdbStore0039', 0, async function (done) {
        console.log(TAG + "************* testRdbStore0039 start *************");
        try {
            await data_relationalStore.getRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "/data/storage/el2/database",
                customDir: "entry/rdb"
            });
            expect().assertFail();
        } catch (e) {
            expect("14800010").assertEqual(e.code);
        }
        console.log(TAG + "************* testRdbStore0039 end *************");
        done();
    })

    /**
     * @tc.name rootDir support test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0040
     * @tc.desc db not exist test callback
     */
    it('testRdbStore0040', 0, async function (done) {
        console.log(TAG + "************* testRdbStore0040 start *************");
        try {
            data_relationalStore.getRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "/data/storage/el2/database",
                customDir: "entry/rdb"
            }, () => {
                expect().assertFail();
            })
        } catch (e) {
            expect("14800010").assertEqual(e.code);
            console.log(TAG + "************* testRdbStore0040 end *************");
            done();
        }
    })

    /**
     * @tc.name rootDir support test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0041
     * @tc.desc query test async
     */
    it('testRdbStore0041', 0, async function (done) {
        console.log(TAG + "************* testRdbStore0041 start *************");
        try {
            const rowCount = 18;
            const rdbStore = await data_relationalStore.getRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
            })

            rdbStore.executeSync(CREATE_TABLE_TEST);

            const valueBuckets = Array(rowCount).fill(0).map(() => {
                return  {
                    "name": "lisi",
                    "age": 15,
                    "salary": 153.3,
                    "blobType": new Uint8Array([1, 2, 3]),
                };
            })
            rdbStore.batchInsertSync('test', valueBuckets);
            rdbStore.close();

            const rdbStore1 = await data_relationalStore.getRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "/data/storage/el2/database",
                customDir: "entry/rdb"
            })

            const predicates = new data_relationalStore.RdbPredicates('test');
            const resultSet = rdbStore1.querySync(predicates);
            expect(resultSet.rowCount).assertEqual(rowCount);
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect().assertFail();
        }
        await data_relationalStore.deleteRdbStore(context, "rootDirTest");
        console.log(TAG + "************* testRdbStore0041 end *************");
        done();
    })

    /**
     * @tc.name rootDir support test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0042
     * @tc.desc query test callback
     */
    it('testRdbStore0042', 0, async function (done) {
        console.log(TAG + "************* testRdbStore0042 start *************");
        const rowCount = 18;
        const rdbStore = await data_relationalStore.getRdbStore(context, {
            name: "rootDirTest",
            securityLevel: data_relationalStore.SecurityLevel.S3,
        })

        rdbStore.executeSync(CREATE_TABLE_TEST);

        const valueBuckets = Array(rowCount).fill(0).map(() => {
            return  {
                "name": "lisi",
                "age": 15,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            };
        })
        rdbStore.batchInsertSync('test', valueBuckets);
        rdbStore.close();

        data_relationalStore.getRdbStore(context, {
            name: "rootDirTest",
            securityLevel: data_relationalStore.SecurityLevel.S3,
            rootDir: "/data/storage/el2/database",
            customDir: "entry/rdb"
        }, (e, rdbStore) => {
            if (e) {
                console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
                expect().assertFail();
            } else {
                const predicates = new data_relationalStore.RdbPredicates('test');
                const resultSet = rdbStore.querySync(predicates);
                expect(resultSet.rowCount).assertEqual(rowCount);
                data_relationalStore.deleteRdbStore(context, "rootDirTest");
                console.log(TAG + "************* testRdbStore0042 end *************");
                done();
            }
        })
    })

    /**
     * @tc.name rootDir support test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0043
     * @tc.desc write test async
     */
    it('testRdbStore0043', 0, async function (done) {
        console.log(TAG + "************* testRdbStore0043 start *************");
        try {
            const rdbStore = await data_relationalStore.getRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
            })

            rdbStore.executeSync(CREATE_TABLE_TEST);
            rdbStore.close();

            const rdbStore1 = await data_relationalStore.getRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "/data/storage/el2/database",
                customDir: "entry/rdb"
            })

            rdbStore1.insertSync('test', {
                "name": "lisi",
                "age": 15,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            });
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect(801).assertEqual(e.code);
        }
        await data_relationalStore.deleteRdbStore(context, "rootDirTest");
        console.log(TAG + "************* testRdbStore0043 end *************");
        done();
    })

    /**
     * @tc.name rootDir support test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0044
     * @tc.desc write test callback
     */
    it('testRdbStore0044', 0, async function (done) {
        console.log(TAG + "************* testRdbStore0044 start *************");
        const rdbStore = await data_relationalStore.getRdbStore(context, {
            name: "rootDirTest",
            securityLevel: data_relationalStore.SecurityLevel.S3,
        })

        rdbStore.executeSync(CREATE_TABLE_TEST);
        rdbStore.close();

        data_relationalStore.getRdbStore(context, {
            name: "rootDirTest",
            securityLevel: data_relationalStore.SecurityLevel.S3,
            rootDir: "/data/storage/el2/database",
            customDir: "entry/rdb"
        }, (e, rdbStore) => {
            try {
                rdbStore.insertSync('test', {
                    "name": "lisi",
                    "age": 15,
                    "salary": 153.3,
                    "blobType": new Uint8Array([1, 2, 3]),
                });
                expect().assertFail();
            } catch (e) {
                console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
                expect(801).assertEqual(e.code);
            }
            data_relationalStore.deleteRdbStore(context, "rootDirTest");
            console.log(TAG + "************* testRdbStore0044 end *************");
            done();
        })
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0045
     * @tc.desc deleteRdb test async
     */
    it('testRdbStore0045', 0, async (done) => {
        console.log(TAG + "************* testRdbStore0045 start *************");
        try {
            const rdbStore = await data_relationalStore.getRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
            })

            rdbStore.executeSync(CREATE_TABLE_TEST);
            rdbStore.close();

            await data_relationalStore.deleteRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "/data/storage/el2/database",
                customDir: "entry/rdb"
            })
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStore0045 end *************");
        done();
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0046
     * @tc.desc deleteRdb test callback
     */
    it('testRdbStore0046', 0, async (done) => {
        console.log(TAG + "************* testRdbStore0046 start *************");
        const rdbStore = await data_relationalStore.getRdbStore(context, {
            name: "rootDirTest",
            securityLevel: data_relationalStore.SecurityLevel.S3,
        })

        rdbStore.executeSync(CREATE_TABLE_TEST);
        rdbStore.close();

        data_relationalStore.deleteRdbStore(context, {
            name: "rootDirTest",
            securityLevel: data_relationalStore.SecurityLevel.S3,
            rootDir: "/data/storage/el2/database",
            customDir: "entry/rdb"
        }, (e) => {
            if (e) {
                console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
                expect().assertFail();
            } else {
                console.log(TAG + "************* testRdbStore0046 end *************");
                done();
            }
        })
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0047
     * @tc.desc invalid rootDir test async
     */
    it('testRdbStore0047', 0, async (done) => {
        console.log(TAG + "************* testRdbStore0047 start *************");
        try {
            await data_relationalStore.deleteRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "invalidPath",
                customDir: "entry/rdb"
            })
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect("14800010").assertEqual(e.code);
        }
        console.log(TAG + "************* testRdbStore0047 end *************");
        done();
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0048
     * @tc.desc invalid rootDir test callback
     */
    it('testRdbStore0048', 0, (done) => {
        console.log(TAG + "************* testRdbStore0048 start *************");
        try {
            data_relationalStore.deleteRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "invalidPath",
                customDir: "entry/rdb"
            }, (e) => {
                expect().assertFail();
            })
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect("14800010").assertEqual(e.code);
            console.log(TAG + "************* testRdbStore0048 end *************");
            done();
        }
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0049
     * @tc.desc db not exist test async
     */
    it('testRdbStore0049', 0, async (done) => {
        console.log(TAG + "************* testRdbStore0049 start *************");
        try {
            await data_relationalStore.deleteRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "/data/storage/el2/database/entry/rdb",
            })
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect("14800010").assertEqual(e.code);
        }
        console.log(TAG + "************* testRdbStore0049 end *************");
        done();
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0050
     * @tc.desc db not exist test async
     */
    it('testRdbStore0050', 0, (done) => {
        console.log(TAG + "************* testRdbStore0050 start *************");
        try {
            data_relationalStore.deleteRdbStore(context, {
                name: "rootDirTest",
                securityLevel: data_relationalStore.SecurityLevel.S3,
                rootDir: "/data/storage/el2/database/entry/rdb",
            }, () => {
                expect().assertFail();
            })
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect("14800010").assertEqual(e.code);
            console.log(TAG + "************* testRdbStore0050 end *************");
            done();
        }
    })
    
    /**
     * @tc.name tokenizer supported test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0051
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0051', 0, (done) => {
        console.log(TAG + "************* testRdbStore0051 start *************");
        try {
            data_relationalStore.isTokenizerSupported(112321);
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect("401").assertEqual(e.code);
            console.log(TAG + "************* testRdbStore0051 end *************");
            done();
        }
    })

    /**
     * @tc.name tokenizer supported test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0052
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0052', 0, (done) => {
        console.log(TAG + "************* testRdbStore0052 start *************");
        try {
            data_relationalStore.isTokenizerSupported("abc");
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect("401").assertEqual(e.code);
            console.log(TAG + "************* testRdbStore0052 end *************");
            done();
        }
    })

    /**
     * @tc.name tokenizer supported test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0053
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0053', 0, (done) => {
        console.log(TAG + "************* testRdbStore0053 start *************");
        try {
            data_relationalStore.isTokenizerSupported(undefined);
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect("401").assertEqual(e.code);
            console.log(TAG + "************* testRdbStore0053 end *************");
            done();
        }
    })

    /**
     * @tc.name tokenizer supported test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0054
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0054', 0, (done) => {
        console.log(TAG + "************* testRdbStore0054 start *************");
        try {
            data_relationalStore.isTokenizerSupported();
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect("401").assertEqual(e.code);
            console.log(TAG + "************* testRdbStore0054 end *************");
            done();
        }
    })

    /**
     * @tc.name tokenizer supported test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0055
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0055', 0, async (done) => {
        console.log(TAG + "************* testRdbStore0055 start *************");
        let storeConfig = {
            name: "testSupportTokenizer.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            tokenizer: data_relationalStore.Tokenizer.CUSTOM_TOKENIZER,
        }
        try {
            await data_relationalStore.getRdbStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect(String(e.code)).assertEqual(String(801));
            console.info(TAG + "************* testRdbStore0055 end   *************");
            done();
        }
    })

    /**
     * @tc.number testCrypt
     * @tc.name testCrypt0001
     * @tc.desc
     */
    it('testCrypt0001', 0, async () => {
        console.log(TAG + "************* testCrypt0001 start *************");
        let cryptoParam = {
            encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
        }
        let storeConfig = {
            name: "testCrypt0001.db",
            securityLevel: data_relationalStore.SecurityLevel.S2,
            cryptoParam: cryptoParam
        }
        try {
            let store = await data_relationalStore.getRdbStore(context, storeConfig);
            await store.executeSql(CREATE_TABLE_TEST);
            store.close();
            console.log(TAG + "getRdbStore success 1");
            cryptoParam.encryptionKey = new Uint8Array([6, 5, 4, 3, 2, 1]);
            store = await data_relationalStore.getRdbStore(context, storeConfig);
            store.close();
            console.log(TAG + "getRdbStore success 2");
            expect(false).assertTrue();
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800011)
            console.log(TAG + "testCorrupt0001 success");
        }
        await data_relationalStore.deleteRdbStore(context, storeConfig);
        console.log(TAG + "************* testCorrupt0001 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");
})