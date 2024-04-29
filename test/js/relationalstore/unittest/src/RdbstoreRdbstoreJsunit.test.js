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

import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
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
            expect(14800017).assertEqual(err.code)
            console.log(TAG + "************* testRdbStore0009 end   *************");
        }
    })

    /**
     * @tc.name rdb store getRdbStore with different securityLevel
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0010
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
                expect(14800017).assertEqual(err.code)
                console.log(TAG + "************* testRdbStore0010 end   *************");
            } else {
                console.log("Get RdbStore successfully.")
                expect(false).assertTrue()
            }
        })
    })

    /**
     * @tc.name rdb store getRdbStore with invalid securityLevel
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_0011
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

    console.log(TAG + "*************Unit Test End*************");
})