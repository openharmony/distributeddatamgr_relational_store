/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
import featureAbility from '@ohos.ability.featureAbility'

var context = featureAbility.getContext();

const TAG = "[RELATIONAL_STORE_VECTOR_JSKITS_TEST]"

const STORE_CONFIG = {
    name: "VectorTest.db",
    securityLevel: relationalStore.SecurityLevel.S1,
    vector: true
}
var store = undefined;
var isSupported = false;
describe('ActsRdbStoreVectorTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll');
        isSupported = relationalStore.isVectorSupported();
        if (!isSupported) {
            return;
        }
        store = await relationalStore.getRdbStore(context, STORE_CONFIG);
        expect(store != null).assertTrue();
    })

    beforeEach(async function () {
        if (!isSupported) {
            return;
        }
        await store.execute("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 floatvector(2));");
        let floatVector = Float32Array.from([1.2, 2.3]);
        await store.execute("INSERT INTO test (id, data1) VALUES (?, ?);", 0, [1, floatVector]);
        console.info(TAG + 'beforeEach');
    })

    afterEach(async function () {
        if (!isSupported) {
            return;
        }
        await store.execute("DROP TABLE IF EXISTS test;");
        console.info(TAG + 'afterEach');
    })

    afterAll(async function () {
        if (!isSupported) {
            return;
        }
        console.info(TAG + 'afterAll');
        store = null;
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name Vector test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Vector_0001
     * @tc.desc Vector test
     */
    it('testVectorStore0001', 0, async function () {
        console.log(TAG + "************* testVectorStore0001 start *************");
        if (!isSupported) {
            return;
        }
        try {
            let resultSet = await store.querySql("select * from test where id = ?;", [1]);
            expect(1).assertEqual(resultSet.rowCount);
            while (resultSet.goToNextRow()) {
                let dataId = resultSet.getLong(0);
                let floats = resultSet.getValue(1);
                expect(1).assertEqual(dataId);
                expect(floats[0] > 1).assertTrue();
                expect(floats[1] > 1).assertTrue();
            }
            resultSet.close();
        } catch (err) {
            console.log(TAG + `Query failed,code is ${err.code},message is ${err.message}`);
        }
    })
    /**
     * @tc.name Vector test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Vector_0002
     * @tc.desc Vector test
     */
    it('testVectorStore0002', 0, async function () {
        console.log(TAG + "************* testVectorStore0002 start *************");
        if (!isSupported) {
            return;
        }
        try {
            let floatVector = Float32Array.from([1.2, 2.3]);
            let resultSet = await store.querySql("select id, data1 <-> ? as distance from test ORDER BY " +
                "data1 <-> '[1.5,5.6]' limit 5;", [floatVector]);
            expect(1).assertEqual(resultSet.rowCount);
            while (resultSet.goToNextRow()) {
                let dataId = resultSet.getLong(0);
                let distance = resultSet.getValue(1);
                expect(1).assertEqual(dataId);
                expect(distance == 0).assertTrue();
            }
            resultSet.close();
        } catch (err) {
            console.log(TAG + `Query failed,code is ${err.code},message is ${err.message}`);
        }
    })

    /**
     * @tc.name Vector test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Vector_0003
     * @tc.desc Vector test
     */
    it('testVectorStore0003', 0, async function () {
        console.log(TAG + "************* testVectorStore0003 start *************");
        if (!isSupported) {
            return;
        }
        try {
            let floatVector = Float32Array.from([1.5, 2.7]);
            let resultSet = await store.querySql("select id, data1 <-> ? as distance from test where id = ? and " +
                "data1 <-> ? > 0.5 ORDER BY data1 <-> ?  limit 10;", [floatVector, 1, floatVector, floatVector]);
            expect(1).assertEqual(resultSet.rowCount);
            while (resultSet.goToNextRow()) {
                let dataId = resultSet.getLong(0);
                let distance = resultSet.getValue(1);
                expect(1).assertEqual(dataId);
                expect(distance > 0).assertTrue();
            }
            resultSet.close();
        } catch (err) {
            console.log(TAG + `Query failed,code is ${err.code},message is ${err.message}`);
        }
    })

    /**
     * @tc.name Vector test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Vector_0004
     * @tc.desc Vector test
     */
    it('testVectorStore0004', 0, async function () {
        console.log(TAG + "************* testVectorStore0004 start *************");
        if (!isSupported) {
            return;
        }
        try {
            let floatVector = Float32Array.from([1.5, 2.7]);
            let resultSet = await store.querySql("select id, data1 from test where id > ? group by " +
                "id, data1 having max(data1<=>?);", [0, floatVector]);
            expect(1).assertEqual(resultSet.rowCount);
            while (resultSet.goToNextRow()) {
                let dataId = resultSet.getLong(0);
                let floats = resultSet.getValue(1);
                expect(1).assertEqual(dataId);
                expect(floats[0] > 0).assertTrue();
                expect(floats[1] > 0).assertTrue();
            }
            resultSet.close();
        } catch (err) {
            console.log(TAG + `Query failed,code is ${err.code},message is ${err.message}`);
        }
    })

    /**
     * @tc.name Vector test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Vector_0005
     * @tc.desc Vector test
     */
    it('testVectorStore0005', 0, async function () {
        console.log(TAG + "************* testVectorStore0005 start *************");
        if (!isSupported) {
            return;
        }
        try {
            let resultSet = await store.querySql("select id, data1 <-> '[1.5, 3.0]' as distance from test union select " +
                "id, data1 <-> '[1.5, 3.0]' as distance from test order by distance limit 5;");
            expect(1).assertEqual(resultSet.rowCount);
            while (resultSet.goToNextRow()) {
                let dataId = resultSet.getLong(0);
                let distance = resultSet.getValue(1);
                expect(1).assertEqual(dataId);
                expect(distance > 0).assertTrue();
            }
        } catch (err) {
            console.log(TAG + `Query failed,code is ${err.code},message is ${err.message}`);
        }
    })

    /**
     * @tc.name Vector test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Vector_0006
     * @tc.desc Vector test
     */
    it('testVectorStore0006', 0, async function () {
        console.log(TAG + "************* testVectorStore0006 start *************");
        if (!isSupported) {
            return;
        }
        try {
            await this.store.execute("create view v1 as select * from test where id > 0;");
            let resultSet = await store.querySql("select * from v1 where id > ?", [0]);
            expect(1).assertEqual(resultSet.rowCount);
            while (resultSet.goToNextRow()) {
                let dataId = resultSet.getLong(0);
                let floats = resultSet.getValue(1);
                expect(1).assertEqual(dataId);
                expect(floats[0] > 0).assertTrue();
                expect(floats[1] > 0).assertTrue();
            }
        } catch (err) {
            console.log(TAG + `Query failed,code is ${err.code},message is ${err.message}`);
        }
    })

    console.log(TAG + "*************Unit Test End*************");
})