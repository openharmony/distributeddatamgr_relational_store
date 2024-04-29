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

import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST] "

const STORE_NAME = "queryByStep_rdb.db"
let rdbStore = null;
let context = ability_featureAbility.getContext()

const asset1 = {
    name: "name1",
    uri: "uri1",
    createTime: "createTime1",
    modifyTime: "modifyTime1",
    size: "size1",
    path: "path1",
    status: relationalStore.AssetStatus.ASSET_NORMAL,
}

const asset2 = {
    name: "name2",
    uri: "uri2",
    createTime: "createTime2",
    modifyTime: "modifyTime2",
    size: "size2",
    path: "path2",
    status: relationalStore.AssetStatus.ASSET_NORMAL,
}

describe('rdbStoreQueryByStepTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        try {
            const config = {
                "name": STORE_NAME,
                securityLevel: relationalStore.SecurityLevel.S1,
            }
            rdbStore = await relationalStore.getRdbStore(context, config);
        } catch (err) {
            console.error(TAG + `create database failed, err code:${err.code}, message:${err.message}`)
            expect().assertFail()
        }

        try {
            let sqlForCreateTable = "CREATE TABLE IF NOT EXISTS test (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "name TEXT, age INTEGER, salary REAL, blobType BLOB, data1 asset, data2 assets)";
            await rdbStore.executeSql(sqlForCreateTable);
        } catch (err) {
            console.error(TAG + `create table test failed, err code:${err.code}, message:${err.message}`)
            expect().assertFail()
        }

        try {
            await InsertTest();
        } catch (err) {
            console.error(TAG + `insert data into table test failed, err code:${err.code}, message:${err.message}`)
            expect().assertFail()
        }
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach');
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach');
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll');
        await rdbStore.deleteRdbStore(context, STORE_NAME);
        rdbStore = null;
    })

    async function InsertTest() {
        console.info(TAG,  "insertTest data start");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets1 = [asset1, asset2];
        let valuesBucket1 = {
            "name": "lisi",
            "age": 15,
            "salary": 153.3,
            "blobType": u8,
            "data1": asset1,
            "data2": assets1,
        }
        await rdbStore.insert("test", valuesBucket1);

        let valuesBucket2 = {
            "name": "tom",
            "age": 56,
            "salary": 1503.3,
        }
        await rdbStore.insert("test", valuesBucket2);

        let valuesBucket3 = {
            "age": 116,
            "salary": 5503.3,
        }
        await rdbStore.insert("test", valuesBucket3);
        console.info(TAG,  "insertTest data end");
    }

    console.info(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number testRdbStoreQueryByStep0001
     * @tc.name Normal test case of queryByStep, query all data
     * @tc.desc 1. Execute queryByStep, sql is 'select * from test'
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreQueryByStep0001', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreQueryByStep0001 start *************");
        try {
            let resultSet = await rdbStore.queryByStep('select * from test');
            // resultSet.rowCount is 3
            expect(3).assertEqual(resultSet.rowCount);
            resultSet.close();
        } catch (err) {
            console.error(TAG + `query failed, err code:${err.code}, message:${err.message}`)
        }

        console.info(TAG + "************* testRdbStoreQueryByStep0001 end *************");
        done();
    })

    /**
     * @tc.number testRdbStoreQueryByStep0002
     * @tc.name Normal test case of queryByStep, query specified data
     * @tc.desc 1. Query data for age > 50
     *          2. Execute queryByStep
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreQueryByStep0002', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreQueryByStep0002 start *************");
        try {
            let resultSet = await rdbStore.queryByStep('select * from test where age > ?', [50]);
            // resultSet.rowCount is 2
            expect(2).assertEqual(resultSet.rowCount);
            resultSet.close();
        } catch (err) {
            console.error(TAG + `query failed, err code:${err.code}, message:${err.message}`)
        }

        console.info(TAG + "************* testRdbStoreQueryByStep0002 end *************");
        done();
    })

    /**
     * @tc.number testRdbStoreQueryByStep0003
     * @tc.name Normal test case of queryByStep, query specified data
     * @tc.desc 1. Query data for age > 50 and salary < 5000
     *          2. Execute queryByStep
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreQueryByStep0003', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreQueryByStep0003 start *************");
        try {
            let resultSet = await rdbStore.queryByStep('select * from test where age > ? and salary < ?', [50, 5000]);
            // resultSet.rowCount is 1
            expect(1).assertEqual(resultSet.rowCount);
            resultSet.close();
        } catch (err) {
            console.error(TAG + `query failed, err code:${err.code}, message:${err.message}`)
        }

        console.info(TAG + "************* testRdbStoreQueryByStep0003 end *************");
        done();
    })

    /**
     * @tc.number testRdbStoreQueryByStep0004
     * @tc.name Normal test case of queryByStep, query specified data
     * @tc.desc 1. Query data for age > 50 or salary < 5000
     *          2. Execute queryByStep
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreQueryByStep0004', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreQueryByStep0004 start *************");
        try {
            let resultSet = await rdbStore.queryByStep('select * from test where age > ? or salary < ?', [50, 5000]);
            // resultSet.rowCount is 3
            expect(3).assertEqual(resultSet.rowCount);
            resultSet.close();
        } catch (err) {
            console.error(TAG + `query failed, err code:${err.code}, message:${err.message}`)
        }

        console.info(TAG + "************* testRdbStoreQueryByStep0004 end *************");
        done();
    })

    /**
     * @tc.number testRdbStoreQueryByStep0005
     * @tc.name AbNormal test case of queryByStep, if param is ''
     * @tc.desc 1. Execute queryByStep
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreQueryByStep0005', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreQueryByStep0005 start *************");
        try {
            let resultSet = await rdbStore.queryByStep('');
            resultSet.close();
        } catch (err) {
            // err.code is 401
            expect("401").assertEqual(err.code)
            console.error(TAG + `query failed, err code:${err.code}, message:${err.message}`)
        }

        console.info(TAG + "************* testRdbStoreQueryByStep0005 end *************");
        done();
    })

    /**
     * @tc.number testRdbStoreQueryByStep0006
     * @tc.name AbNormal test case of queryByStep, if param is null
     * @tc.desc 1. Execute queryByStep
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreQueryByStep0006', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreQueryByStep0006 start *************");
        try {
            let resultSet = await rdbStore.queryByStep(null);
            resultSet.close();
        } catch (err) {
            // err.code is 401
            expect("401").assertEqual(err.code)
            console.error(TAG + `query failed, err code:${err.code}, message:${err.message}`)
        }

        console.info(TAG + "************* testRdbStoreQueryByStep0006 end *************");
        done();
    })

    /**
     * @tc.number testRdbStoreQueryByStep0007
     * @tc.name AbNormal test case of queryByStep, if param is null
     * @tc.desc 1. Execute queryByStep
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreQueryByStep0007', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreQueryByStep0007 start *************");
        try {
            let resultSet = await rdbStore.queryByStep(undefined);
            resultSet.close();
        } catch (err) {
            // err.code is 401
            expect("401").assertEqual(err.code)
            console.error(TAG + `query failed, err code:${err.code}, message:${err.message}`)
        }

        console.info(TAG + "************* testRdbStoreQueryByStep0007 end *************");
        done();
    })

    /**
     * @tc.number testRdbStoreQueryByStep0008
     * @tc.name AbNormal test case of queryByStep, if args is []
     * @tc.desc 1. Execute queryByStep
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreQueryByStep0008', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreQueryByStep0008 start *************");
        try {
            let resultSet = await rdbStore.queryByStep('select * from test where age > ?', []);
            // resultSet.rowCount is 0
            expect(0).assertEqual(resultSet.rowCount);
            resultSet.close();
        } catch (err) {
            console.error(TAG + `query failed, err code:${err.code}, message:${err.message}`)
        }

        console.info(TAG + "************* testRdbStoreQueryByStep0008 end *************");
        done();
    })

    console.info(TAG + "*************Unit Test End*************");
})
