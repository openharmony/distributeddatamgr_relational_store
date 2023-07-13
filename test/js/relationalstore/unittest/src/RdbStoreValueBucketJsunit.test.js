/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
"data1 text," + "data2 long, " + "data3 double," + "data4 blob)";

const DELETE_TABLE_TEST = "DELETE FROM test;";

const STORE_CONFIG = {
    name: "Resultset.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined;


describe('rdbResultSetTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(globalThis.context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        await rdbStore.executeSql(DELETE_TABLE_TEST, null);
    })

    afterEach(function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(globalThis.context, "Resultset.db");
    })

    /**
     * @tc.name testInsertEmptyInValueBucket0001
     * @tc.number testInsertEmptyInValueBucket0001
     * @tc.desc should support to insert empty string and blob
     */
    it('testInsertEmptyInValueBucket0001', 0, async function (done) {
        console.log(TAG + "************* testInsertEmptyInValueBucket0001 start *************");
        try {
            const valueBucket = {
                "data1": "", //hello world",
                "data2": 0,
                "data3": 0,
                "data4": new Uint8Array(0),
            }
            await rdbStore.insert("test", valueBucket)
        } catch (e) {
            expect(null).assertFail();
        }

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(1).assertEqual(resultSet.rowCount)
            const data1 = resultSet.getString(resultSet.getColumnIndex("data1"))
            const data2 = resultSet.getLong(resultSet.getColumnIndex("data2"))
            const data3 = resultSet.getDouble(resultSet.getColumnIndex("data3"))
            const data4 = resultSet.getBlob(resultSet.getColumnIndex("data4"))
            expect("").assertEqual(data1);
            expect(0).assertEqual(data2);
            expect(0).assertEqual(data3);
            expect(0).assertEqual(data4.length);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed);
        } catch (e) {
            expect(null).assertFail();
        }
        done();
        console.log(TAG + "************* testInsertEmptyInValueBucket0001 end *************");
    })

    /**
     * @tc.name testInsertNullInValueBucket0002
     * @tc.number testInsertNullInValueBucket0002
     * @tc.desc should support null
     */
    it('testInsertNullInValueBucket0002', 0, async function (done) {
        console.log(TAG + "************* testInsertNullInValueBucket0002 start *************");
        try {
            const valueBucket = {
                "data1": null, //hello world",
                "data2": null,
                "data3": null,
                "data4": null,
            }
            await rdbStore.insert("test", valueBucket)
        } catch (e) {
            console.log(TAG + `{code:${e.code}, message:${e.message}`);
            expect(null).assertFail();
        }

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(1).assertEqual(resultSet.rowCount)
            const data1 = resultSet.getString(resultSet.getColumnIndex("data1"))
            const data2 = resultSet.getLong(resultSet.getColumnIndex("data2"))
            const data3 = resultSet.getDouble(resultSet.getColumnIndex("data3"))
            const data4 = resultSet.getBlob(resultSet.getColumnIndex("data4"))
            expect("").assertEqual(data1);
            expect(0).assertEqual(data2);
            expect(0).assertEqual(data3);
            expect(0).assertEqual(data4.length);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed);
        } catch (e) {
            console.log(TAG + `{code:${e.code}, message:${e.message}`);
            expect(null).assertFail();
        }
        done();
        console.log(TAG + "************* testInsertNullInValueBucket0002 end *************");
    })

    /**
     * @tc.name testInsertUndefinedInValueBucket0003
     * @tc.number testInsertUndefinedInValueBucket0003
     * @tc.desc take undefined value as no input
     */
    it('testInsertUndefinedInValueBucket0003', 0, async function (done) {
        console.log(TAG + "************* testInsertUndefinedInValueBucket0003 start *************");
        try {
            const valueBucket = {
                "data1": undefined, //hello world",
                "data2": 0,
                "data3": undefined,
                "data4": undefined,
            }
            /**
             * the valueBucket is same as:
             * const valueBucket = {
             *    "data2": 0
             * }
             */
            await rdbStore.insert("test", valueBucket)
        } catch (e) {
            console.log(TAG + `{code:${e.code}, message:${e.message}`);
            expect(null).assertFail();
        }

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(1).assertEqual(resultSet.rowCount)
            const data1 = resultSet.getString(resultSet.getColumnIndex("data1"))
            const data2 = resultSet.getLong(resultSet.getColumnIndex("data2"))
            const data3 = resultSet.getDouble(resultSet.getColumnIndex("data3"))
            const data4 = resultSet.getBlob(resultSet.getColumnIndex("data4"))
            expect("").assertEqual(data1);
            expect(0).assertEqual(data2);
            expect(0).assertEqual(data3);
            expect(0).assertEqual(data4.length);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed);
        } catch (e) {
            console.log(TAG + `{code:${e.code}, message:${e.message}`);
            expect(null).assertFail();
        }
        done();
        console.log(TAG + "************* testInsertUndefinedInValueBucket0003 end *************");
    })

    /**
     * @tc.name testInsertAllUndefinedInValueBucket0004
     * @tc.number testInsertAllUndefinedInValueBucket0004
     * @tc.desc empty valueBucket should not be support to insert
     */
    it('testInsertAllUndefinedInValueBucket0004', 0, async function (done) {
        console.log(TAG + "************* testInsertAllUndefinedInValueBucket0004 start *************");
        try {
            const valueBucket = {
                "data1": undefined, //hello world",
                "data2": undefined,
                "data3": undefined,
                "data4": undefined,
            }
            /**
             * the valueBucket is same as:
             * const valueBucket = {
             * }
             */
            await rdbStore.insert("test", valueBucket);
            expect(null).assertFail();
        } catch (e) {
            expect(e.code).assertEqual(14800000);
            done();
        }
        console.log(TAG + "************* testInsertAllUndefinedInValueBucket0004 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})