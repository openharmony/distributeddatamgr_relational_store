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
import dataRdb from '@ohos.data.rdb';

const TAG = "[RDB_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "rdbstore.db",
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
        await dataRdb.deleteRdbStore("rdbstore.db");
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
            await dataRdb.getRdbStore(STORE_CONFIG, 1);
        } catch (err) {
            expect().assertFail()
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
        try {
            let store = await dataRdb.getRdbStore(STORE_CONFIG, 2);
            await store.executeSql(CREATE_TABLE_TEST);
        } catch (err) {
            console.log(TAG + `failed, errcode:${JSON.stringify(err)}.`);
            expect().assertFail()
        }
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
        }
        try {
            await dataRdb.getRdbStore(storeConfig, 4);
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, errcode:${JSON.stringify(err)}.`);
            expect("401").assertEqual(err.code)
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
            let store = await dataRdb.getRdbStore(STORE_CONFIG, 6);
            await store.executeSql(CREATE_TABLE_TEST);
        } catch (err) {
            console.log(TAG + `failed, errcode:${JSON.stringify(err)}.`);
            expect().assertFail()
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

        let store = await dataRdb.getRdbStore(STORE_CONFIG, 2);
        try {
            expect(2).assertEqual(store.getVersion())
            store.setVersion(5)
            expect(5).assertEqual(store.getVersion())
            store.setVersion(2147483647)
            expect(2147483647).assertEqual(store.getVersion())
            store.setVersion(-2147483648)
            expect(-2147483648).assertEqual(store.getVersion())

            // Exceeds the range of 32-bit signed integer value.
            store.setVersion(2147483647000)
            expect(-1000).assertEqual(store.getVersion())
            store.setVersion(-2147483648100)
            expect(-100).assertEqual(store.getVersion())
            store = null
        } catch (err) {
            console.log(TAG + `failed, errcode:${JSON.stringify(err)}.`);
            expect().assertFail()
        }
        await dataRdb.deleteRdbStore("rdbstore.db");
        console.log(TAG + "************* testRdbStore0005 end   *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})