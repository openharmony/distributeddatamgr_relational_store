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
import relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]";
const STORE_NAME = "AfterCloseTest.db";
const context = ability_featureAbility.getContext();

async function createRdb() {
    const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "name TEXT UNIQUE, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
    const STORE_CONFIG = {
        name: STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
    };
    const rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
    await rdbStore.executeSql(CREATE_TABLE_TEST);
    var u8 = new Uint8Array([1, 2, 3]);
    const valueBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
    };
    await rdbStore.insert('test', valueBucket);
    return rdbStore;
}

describe('rdbStoreAfterCloseSyncTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
    })

    /**
     * @tc.number testSyncRdbAfterClose0001
     * @tc.name RDB Close test
     * @tc.desc executeSync after RDB closed
     */
    it('testSyncRdbAfterClose0001', 0, async function () {
        console.log(TAG + "************* testSyncRdbAfterClose0001 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            rdbStore.executeSync('SELECT * FROM test LIMIT 100');
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testSyncRdbAfterClose0001 end *************");
    })

    /**
     * @tc.number testSyncRdbAfterClose0002
     * @tc.name RDB Close test
     * @tc.desc querySync after RDB closed
     */
    it('testSyncRdbAfterClose0002', 0, async function () {
        console.log(TAG + "************* testSyncRdbAfterClose0002 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            let predicates = new relationalStore.RdbPredicates("test");
            predicates.equalTo('age', 18);
            rdbStore.querySync(predicates);
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testSyncRdbAfterClose0002 end *************");
    })

    /**
     * @tc.number testSyncRdbAfterClose0003
     * @tc.name RDB Close test
     * @tc.desc querySqlSync after RDB closed
     */
    it('testSyncRdbAfterClose0003', 0, async function () {
        console.log(TAG + "************* testSyncRdbAfterClose0003 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }
        try {
            rdbStore.querySqlSync("SELECT * FROM test");
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testSyncRdbAfterClose0003 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");
})