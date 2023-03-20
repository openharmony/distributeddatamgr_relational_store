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

const STORE_CONFIG = {
    name: "stepResultSet_getRow_test.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
let store
describe('rdbStoreResultSetGetRowTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        await data_relationalStore.deleteRdbStore(context, "stepResultSet_getRow_test.db");
        store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        await store.executeSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, " +
            "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await store.executeSql("DROP TABLE IF EXISTS test");
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        await data_relationalStore.deleteRdbStore(context, "stepResultSet_getRow_test.db");
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0001
     * @tc.desc resultSet getRow test
     */
    it('rdbStoreResultSetGetRowTest0001', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0001 start *************");
        let valueBucket = {
            "id": 1
        };
        let rowId = await store.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let resultSet = await store.queryByStep("SELECT * FROM test", []);
        expect(true).assertEqual(resultSet.goToFirstRow());

        let data = resultSet.getRow();
        console.info('ggggg' + JSON.stringify(data));

        expect(1).assertEqual(data[5][1]);
        expect(null).assertEqual(data[0][1]);
        expect(null).assertEqual(data[1][1]);
        expect(null).assertEqual(data[2][1]);
        expect(null).assertEqual(data[3][1]);
        expect(null).assertEqual(data[4][1]);

        resultSet.close();
        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0001 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0002
     * @tc.desc resultSet getRow test
     */
    it('rdbStoreResultSetGetRowTest0002', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0002 start *************");
        let valueBucket = {
            "data1": null,
            "data2": undefined,
            "data4": undefined,
            "data5": null
        };
        let rowId = await store.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let resultSet = await store.queryByStep("SELECT * FROM test", []);
        expect(true).assertEqual(resultSet.goToFirstRow());

        let data = resultSet.getRow();

        expect(1).assertEqual(data[5][1]);
        expect(null).assertEqual(data[0][1]);
        expect(null).assertEqual(data[1][1]);
        expect(null).assertEqual(data[2][1]);
        expect(null).assertEqual(data[3][1]);
        expect(null).assertEqual(data[4][1]);

        resultSet.close();
        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0002 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0003
     * @tc.desc resultSet getRow test
     */
    it('rdbStoreResultSetGetRowTest0003', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0003 start *************");
        let valueBucket = {
            "data1": "olleh",
            "data2": 20,
            "data3": 2.0,
            "data4": new Uint8Array([4, 3, 2, 1]),
            "data5": true
        };
        let rowId = await store.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let resultSet = await store.queryByStep("SELECT * FROM test", []);
        expect(true).assertEqual(resultSet.goToFirstRow());

        let data = resultSet.getRow();

        expect(1).assertEqual(data[5][1]);
        expect("olleh").assertEqual(data[0][1]);
        expect(20).assertEqual(data[1][1]);
        expect(2.0).assertEqual(data[2][1]);
        expect(1).assertEqual(data[3][1][3]);
        expect(1).assertEqual(data[4][1]);

        resultSet.close();
        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0003 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0004
     * @tc.desc resultSet getRow test
     */
    it('rdbStoreResultSetGetRowTest0004', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0004 start *************");
        let valueBucket = {
            "data1": "hello",
            "data2": 10,
            "data3": 1.0,
            "data4": new Uint8Array([1, 2, 3, 4]),
            "data5": true,
        };
        let rowId = await store.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let resultSet = await store.queryByStep("SELECT * FROM test", []);
        expect(true).assertEqual(resultSet.goToFirstRow());

        let data = resultSet.getRow();

        expect(1).assertEqual(data[5][1]);
        expect("hello").assertEqual(data[0][1]);
        expect(10).assertEqual(data[1][1]);
        expect(1.0).assertEqual(data[2][1]);
        expect(4).assertEqual(data[3][1][3]);
        expect(1).assertEqual(data[4][1]);

        resultSet.close();
        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0004 end   *************");
    })
    console.log(TAG + "*************Unit Test End*************");
})