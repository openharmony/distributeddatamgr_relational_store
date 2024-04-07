/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
import relationalStore from '@ohos.data.relationalStore'
import featureAbility from '@ohos.ability.featureAbility'

var context = featureAbility.getContext();

const TAG = "[RELATIONAL_STORE_JSKITS_VALUE_TYPE_TEST]"

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS bigint_table(id INTEGER PRIMARY KEY AUTOINCREMENT, value1 UNLIMITED INT NOT NULL, value2 UNLIMITED INT, value3 VECS)";

const DROP_TABLE_TEST = "DROP TABLE IF EXISTS bigint_table";

const STORE_CONFIG = {
    name: 'value_type.db',
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var store = undefined;
describe('ActsRdbStoreValueTypeTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll');
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
        store = await relationalStore.getRdbStore(context, STORE_CONFIG);
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach');
        await relationalStore.execute(DROP_TABLE_TEST);
        await relationalStore.execute(CREATE_TABLE_TEST);

    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await relationalStore.execute(DROP_TABLE_TEST);
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll');
        store = null;
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name the value type function
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_001
     * @tc.desc non encrypted database attach non encrypted database
     */
    it('testValueType0001', 0, async function () {
        console.log(TAG + "************* testValueType0001 start *************");
        var bucket = {
            'value1':bigint(158),
            'value2':bigint(-158)
        };
        try {
            await store.insert('bigint_table', bucket);
            let resultSet = await store.querySql('select value1, value2 from bigint_table');
            expect(resultSet === null).assertFail(null);
            expect(true).assertEqual(resultSet.goToNextRow());
            let value1 = resultSet.getValue(0);
            expect(typeof value1).assertEqual('bigint');
            expect(value1).assertEqual(bucket['value1']);
            let value2 = resultSet.getValue(1);
            expect(typeof value2).assertEqual('bigint');
            expect(value2).assertEqual(bucket['value2']);
        } catch (err) {
            expect(false).assertFail();
            console.error(`failed, code:${err.code}, message: ${err.message}`);
        }
        expect(true).assertTrue();
        console.log(TAG + "************* testValueType0001 end *************");
    })

    /**
     * @tc.name the value type function
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ValueType_002
     * @tc.desc the bigint
     */
    it('testValueType0002', 0, async function () {
        console.log(TAG + "************* testValueType0002 start *************");
        var bucket = {
            'value1':bigint('15822401018187971961171'),
            'value2':bigint('-15822401018187971961171')
        };
        try {
            await store.insert('bigint_table', bucket);
            let resultSet = await store.querySql('select value1, value2 from bigint_table');
            expect(resultSet === null).assertFail(null);
            expect(true).assertEqual(resultSet.goToNextRow());
            let value1 = resultSet.getValue(0);
            expect(typeof value1).assertEqual('bigint');
            expect(value1).assertEqual(bucket['value1']);
            let value2 = resultSet.getValue(1);
            expect(typeof value2).assertEqual('bigint');
            expect(value2).assertEqual(bucket['value2']);
        } catch (err) {
            expect(false).assertFail();
            console.error(`failed, code:${err.code}, message: ${err.message}`);
        }
        expect(true).assertTrue();
        console.log(TAG + "************* testValueType0002 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})
