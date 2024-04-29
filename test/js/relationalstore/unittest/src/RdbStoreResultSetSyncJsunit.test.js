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
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "data1 text," + "data2 long, " + "data3 double," + "data4 blob)";

const STORE_CONFIG = {
    name: "Resultset.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined;

describe('rdbResultSetSyncTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
        await createTest();
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "Resultset.db");
    })

    // insert data
    async function createTest() {
        console.log(TAG + "createTest data start");
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
        console.log(TAG + "createTest data end");
    }

    function createUint8Array(length) {
        let i = 0
        let index = 0
        let temp = null
        let u8 = new Uint8Array(length)
        length = typeof (length) === 'undefined' ? 9 : length
        for (i = 1; i <= length; i++) {
            u8[i - 1] = i
        }
        for (i = 1; i <= length; i++) {
            index = parseInt(Math.random() * (length - i)) + i
            if (index != i) {
                temp = u8[i - 1]
                u8[i - 1] = u8[index - 1]
                u8[index - 1] = temp
            }
        }
        return u8;
    }

    async function createBigData(size) {
        await rdbStore.executeSql("DELETE FROM test");
        let u8 = createUint8Array(32768);
        let valueBucketArray = new Array();
        for (let i = 0; i < size; i++) {
            valueBucketArray.push({
                "data1": "test" + i,
                "data2": 18,
                "data3": 100.5,
                "data4": u8,
            });
        }
        if (valueBucketArray.length != 0) {
            await rdbStore.batchInsert("test", valueBucketArray);
        }
    }

    /**
     * @tc.name resultSet getBlob normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0010
     * @tc.desc resultSet getBlob normal test
     */
    it('testSyncSyncGetBlob0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGetBlob0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data4 = resultSet.getBlob(resultSet.getColumnIndex("data4"))
            console.log(TAG + "id=" + id + ", data4=" + data4);
            expect(1).assertEqual(data4[0]);
            expect(2).assertEqual(data4[1]);
            expect(3).assertEqual(data4[2]);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetBlob0001 end *************");
    })

    /**
     * @tc.name resultSet getBlob normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0011
     * @tc.desc resultSet getBlob normal test
     */
    it('testSyncGetBlob0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGetBlob0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data4 = resultSet.getBlob(resultSet.getColumnIndex("data4"))
            console.log(TAG + "id=" + id + ", data4=" + data4);
            expect(3).assertEqual(data4[0]);
            expect(4).assertEqual(data4[1]);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetBlob0002 end *************");
    })

    /**
     * @tc.name resultSet getBlob normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0012
     * @tc.desc resultSet getBlob normal test
     */
    it('testSyncGetBlob0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGetBlob0003 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data4 = resultSet.getBlob(resultSet.getColumnIndex("data4"))
            console.log(TAG + "id=" + id + ", data4=" + data4);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetBlob0003 end *************");
    })

    /**
     * @tc.name resultSet isStarted normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0020
     * @tc.desc resultSet isStarted normal test
     */
    it('testSyncIsStarted0001', 0, async function (done) {
        console.log(TAG + "************* testSyncIsStarted0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(false).assertEqual(resultSet.isStarted)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsStarted0001 end *************");
    })

    /**
     * @tc.name resultSet isStarted normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0021
     * @tc.desc resultSet isStarted normal test
     */
    it('testSyncIsStarted0002', 0, async function (done) {
        console.log(TAG + "************* testSyncIsStarted0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            resultSet.goTo(1)
            expect(true).assertEqual(resultSet.isStarted)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsStarted0002 end *************");
    })

    /**
     * @tc.name resultSet isStarted normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0022
     * @tc.desc resultSet isStarted normal test
     */
    it('testSyncIsStarted0003', 0, async function (done) {
        console.log(TAG + "************* testSyncIsStarted0003 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToNextRow())
            expect(true).assertEqual(resultSet.isStarted)
            expect(false).assertEqual(resultSet.goToPreviousRow())
            expect(true).assertEqual(resultSet.isStarted)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsStarted0003 end *************");
    })

    /**
     * @tc.name resultSet isStarted with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0023
     * @tc.desc resultSet isStarted with no result test
     */
    it('testSyncIsStarted0004', 0, async function (done) {
        console.log(TAG + "************* testSyncIsStarted0004 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToNextRow())
            expect(true).assertEqual(resultSet.isStarted)
            expect(true).assertEqual(resultSet.isStarted)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsStarted0004 end *************");
    })


    /**
     * @tc.name resultSet isEnded normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0030
     * @tc.desc resultSet isEnded normal test
     */
    it('testSyncIsEnded0001', 0, async function (done) {
        console.log(TAG + "************* testSyncIsEnded0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(false).assertEqual(resultSet.isEnded)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsEnded0001 end *************");
    })

    /**
     * @tc.name resultSet isEnded normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0031
     * @tc.desc resultSet isEnded normal test
     */
    it('testSyncIsEnded0002', 0, async function (done) {
        console.log(TAG + "************* testSyncIsEnded0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToLastRow())
            expect(false).assertEqual(resultSet.isEnded)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsEnded0002 end *************");
    })

    /**
     * @tc.name resultSet isEnded normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0032
     * @tc.desc resultSet isEnded normal test
     */
    it('testSyncIsEnded0003', 0, async function (done) {
        console.log(TAG + "************* testSyncIsEnded0003 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            resultSet.goToRow(3)
            expect(true).assertEqual(resultSet.isEnded)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsEnded0003 end *************");
    })

    /**
     * @tc.name resultSet isEnded normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0033
     * @tc.desc resultSet isEnded normal test
     */
    it('testSyncIsEnded0004', 0, async function (done) {
        console.log(TAG + "************* testSyncIsEnded0004 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            resultSet.goToRow(3)
            expect(true).assertEqual(resultSet.isEnded)
            expect(true).assertEqual(resultSet.isEnded)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsEnded0004 end *************");
    })

    /**
     * @tc.name resultSet rowCount normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0040
     * @tc.desc resultSet rowCount normal test
     */
    it('testSyncRowCount0001', 0, async function (done) {
        console.log(TAG + "************* testSyncRowCount0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(3).assertEqual(resultSet.rowCount)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncRowCount0001 end *************");
    })

    /**
     * @tc.name resultSet rowCount with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0041
     * @tc.desc resultSet rowCount with no result test
     */
    it('testSyncRowCount0002', 0, async function (done) {
        console.log(TAG + "************* testSyncRowCount0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(-1).assertEqual(resultSet.rowCount)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncRowCount0002 end *************");
    })

    /**
     * @tc.name resultSet rowCount test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0042
     * @tc.desc resultSet rowCount test
     */
    it('testSyncRowCount0003', 0, async function (done) {
        console.log(TAG + "************* testSyncRowCount0003 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("data1", "hello");
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(1).assertEqual(resultSet.rowCount)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncRowCount0003 end *************");
    })

    /**
     * @tc.name resultSet rowCount test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0043
     * @tc.desc resultSet rowCount test
     */
    it('testSyncRowCount0004', 0, async function (done) {
        console.log(TAG + "************* testSyncRowCount0004 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("data1", "hello");
        predicates.equalTo("data2", 3);
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(0).assertEqual(resultSet.rowCount)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncRowCount0003 end *************");
    })

    /**
     * @tc.name resultSet getLong test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0050
     * @tc.desc resultSet getLong test
     */
    it('testSyncGetLong0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGetLong0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data2 = resultSet.getLong(resultSet.getColumnIndex("data2"))
            console.log(TAG + "id=" + id + ", data2=" + data2);
            expect(10).assertEqual(data2);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetLong0001 end *************");
    })

    /**
     * @tc.name resultSet getLong test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0051
     * @tc.desc resultSet getLong test
     */
    it('testSyncGetLong0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGetLong0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            const data1 = resultSet.getLong(resultSet.getColumnIndex("data1"))
            expect(2).assertEqual(data1);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetLong0002 end *************");
    })

    /**
     * @tc.name resultSet getLong test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0052
     * @tc.desc resultSet getLong test
     */
    it('testSyncGetLong0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGetLong0003 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            const data2 = resultSet.getLong(resultSet.getColumnIndex("data2"))
            expect(-5).assertEqual(data2);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetLong0003 end *************");
    })

    /**
     * @tc.name resultSet getString test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0060
     * @tc.desc resultSet getString test
     */
    it('testSyncGetString0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGetString0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow())
        const data1 = resultSet.getString(resultSet.getColumnIndex("data1"))
        expect("hello").assertEqual(data1);

        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetString0001 end *************");
    })

    /**
     * @tc.name resultSet getString test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0061
     * @tc.desc resultSet getString test
     */
    it('testSyncGetString0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGetString0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow())
        const data2 = resultSet.getString(resultSet.getColumnIndex("data2"))
        expect("10").assertEqual(data2);

        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetString0002 end *************");
    })

    /**
     * @tc.name resultSet getString test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0062
     * @tc.desc resultSet getString test
     */
    it('testSyncGetString0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGetString0003 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        const data3 = resultSet.getString(resultSet.getColumnIndex("data3"))
        expect("2.5").assertEqual(data3);

        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetString0003 end *************");
    })

    /**
     * @tc.name resultSet getString test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0063
     * @tc.desc resultSet getString test
     */
    it('testSyncGetString0004', 0, async function (done) {
        console.log(TAG + "************* testSyncGetString0004 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        const data1 = resultSet.getString(resultSet.getColumnIndex("data1"))
        const data2 = resultSet.getString(resultSet.getColumnIndex("data2"))
        const data3 = resultSet.getString(resultSet.getColumnIndex("data3"))
        expect("hello world").assertEqual(data1);
        expect("3").assertEqual(data2);
        expect("1.8").assertEqual(data3);

        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGetString0004 end *************");
    })

    /**
     * @tc.name resultSet isClosed test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0070
     * @tc.desc resultSet isClosed test
     */
    it('testSyncIsClosed0001', 0, async function (done) {
        console.log(TAG + "************* testSyncIsClosed0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(3).assertEqual(resultSet.rowCount)
        resultSet.close();
        expect(true).assertEqual(resultSet.isClosed)

        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsClosed0001 end *************");
    })

    /**
     * @tc.name resultSet isClosed with not close test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0071
     * @tc.desc resultSet isClosed with not close test
     */
    it('testSyncIsClosed0002', 0, async function (done) {
        console.log(TAG + "************* testSyncIsClosed0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(false).assertEqual(resultSet.isClosed)

        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsClosed0002 end *************");
    })

    /**
     * @tc.name resultSet isClosed with not close test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0072
     * @tc.desc resultSet isClosed with not close test
     */
    it('testSyncIsClosed0003', 0, async function (done) {
        console.log(TAG + "************* testSyncIsClosed0003 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)
        expect(false).assertEqual(resultSet.isClosed)

        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncIsClosed0003 end *************");
    })

    /**
     * @tc.name resultSet columnCount test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0080
     * @tc.desc resultSet columnCount test
     */
    it('testSyncColumnCount0001', 0, async function (done) {
        console.log(TAG + "************* testSyncColumnCount0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(5).assertEqual(resultSet.columnCount);
        resultSet.close();
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncColumnCount0001 end *************");
    })

    /**
     * @tc.name resultSet columnCount test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0081
     * @tc.desc resultSet columnCount test
     */
    it('testSyncColumnCount0002', 0, async function (done) {
        console.log(TAG + "************* testSyncColumnCount0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)
        expect(0).assertEqual(resultSet.columnCount);
        resultSet.close();
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncColumnCount0002 end *************");
    })

    /**
     * @tc.name resultSet rowIndex test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0090
     * @tc.desc resultSet rowIndex test
     */
    it('testSyncRowIndex0001', 0, async function (done) {
        console.log(TAG + "************* testSyncRowIndex0001 *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(0).assertEqual(resultSet.rowIndex)

        resultSet.close();
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncRowIndex0001 end *************");
    })

    /**
     * @tc.name resultSet rowIndex at last row test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0091
     * @tc.desc resultSet rowIndex at last row test
     */
    it('testSyncRowIndex0002', 0, async function (done) {
        console.log(TAG + "************* testSyncRowIndex0002 *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(true).assertEqual(resultSet.goToLastRow())
        expect(2).assertEqual(resultSet.rowIndex)

        resultSet.close();
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncRowIndex0002 end *************");
    })

    /**
     * @tc.name resultSet goToFirstRow normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0100
     * @tc.desc resultSet goToFirstRow normal test
     */
    it('testSyncGoToFirstRow0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToFirstRow0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close();
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGoToFirstRow0001 end *************");
    })

    /**
     * @tc.name resultSet goToFirstRow with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0101
     * @tc.desc resultSet goToFirstRow with no result test
     */
    it('testSyncGoToFirstRow0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToFirstRow0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(false).assertEqual(resultSet.goToFirstRow())
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close()
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGoToFirstRow0002 end *************");
    })

    /**
     * @tc.name resultSet goToFirstRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0102
     * @tc.desc resultSet goToFirstRow test
     */
    it('testSyncGoToFirstRow0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToFirstRow0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            expect(true).assertEqual(resultSet.goToFirstRow())
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet.close()
        resultSet = null
        done();
        console.log(TAG + "************* testSyncGoToFirstRow0003 end *************");
    })

    /**
     * @tc.name resultSet goToLastRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0110
     * @tc.desc resultSet goToFirstRow test
     */
    it('testSyncGoToLastRow0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToLastRow0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        {
            expect(true).assertEqual(resultSet.goToLastRow())
        }
        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToLastRow0001 end *************");
    })

    /**
     * @tc.name resultSet goToLastRow with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0111
     * @tc.desc resultSet goToLastRow with no result test
     */
    it('testSyncGoToLastRow0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToLastRow0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)
        expect(false).assertEqual(resultSet.goToLastRow())
        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToLastRow0002 end *************");
    })

    /**
     * @tc.name resultSet goToLastRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0112
     * @tc.desc resultSet goToLastRow test
     */
    it('testSyncGoToLastRow0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToLastRow0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToLastRow())
        expect(true).assertEqual(resultSet.goToPreviousRow())
        expect(true).assertEqual(resultSet.goToLastRow())

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToLastRow0003 end *************");

    })

    /**
     * @tc.name resultSet goToNextRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0120
     * @tc.desc resultSet goToNextRow test
     */
    it('testSyncGoToNextRow0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToNextRow0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToNextRow())

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToNextRow0001 end *************");

    })

    /**
     * @tc.name resultSet goToNextRow with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0121
     * @tc.desc resultSet goToNextRow with no result test
     */
    it('testSyncGoToNextRow0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToNextRow0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)

        expect(false).assertEqual(resultSet.goToNextRow())

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToNextRow0002 end *************");

    })

    /**
     * @tc.name resultSet goToNextRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0122
     * @tc.desc resultSet goToNextRow test
     */
    it('testSyncGoToNextRow0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToNextRow0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        expect(true).assertEqual(resultSet.goToPreviousRow())
        expect(true).assertEqual(resultSet.goToNextRow())

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToNextRow0003 end *************");

    })

    /**
     * @tc.name resultSet goToNextRow after last row test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0123
     * @tc.desc resultSet goToNextRow after last row test
     */
    it('testSyncGoToNextRow0004', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToNextRow0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToLastRow())
        expect(false).assertEqual(resultSet.goToNextRow())

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToNextRow0004 end *************");

    })

    /**
     * @tc.name resultSet goToPreviousRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0130
     * @tc.desc resultSet goToPreviousRow test
     */
    it('testSyncGoToPreviousRow0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToPreviousRow0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(false).assertEqual(resultSet.goToPreviousRow())

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToPreviousRow0001 end *************");

    })

    /**
     * @tc.name resultSet goToPreviousRow with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0131
     * @tc.desc resultSet goToPreviousRow with no result test
     */
    it('testSyncGoToPreviousRow0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToPreviousRow0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)

        expect(false).assertEqual(resultSet.goToPreviousRow())

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToPreviousRow0002 end *************");

    })

    /**
     * @tc.name resultSet goToPreviousRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0132
     * @tc.desc resultSet goToPreviousRow test
     */
    it('testSyncGoToPreviousRow0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToPreviousRow0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        expect(true).assertEqual(resultSet.goToPreviousRow())

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToPreviousRow0003 end *************");

    })

    /**
     * @tc.name resultSet goToPreviousRow after last row test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0133
     * @tc.desc resultSet goToPreviousRow after last row test
     */
    it('testSyncGoToPreviousRow0004', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToPreviousRow0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToLastRow())
        expect(true).assertEqual(resultSet.goToPreviousRow())

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToPreviousRow0004 end *************");

    })

    /**
     * @tc.name resultSet goTo test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0140
     * @tc.desc resultSet goTo test
     */
    it('testSyncGoTo0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGoTo0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        resultSet.goTo(1)
        expect(1).assertEqual(resultSet.rowIndex)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoTo0001 end *************");

    })

    /**
     * @tc.name resultSet goTo with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0141
     * @tc.desc resultSet goTo with no result test
     */
    it('testSyncGoTo0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGoTo0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)

        resultSet.goTo(1)
        expect(-1).assertEqual(resultSet.rowIndex)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoTo0002 end *************");

    })

    /**
     * @tc.name resultSet goTo test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0142
     * @tc.desc resultSet goTo test
     */
    it('testSyncGoTo0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGoTo0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        resultSet.goTo(1)
        expect(2).assertEqual(resultSet.rowIndex)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoTo0003 end *************");

    })

    /**
     * @tc.name resultSet goTo after last row test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0143
     * @tc.desc resultSet goTo after last row test
     */
    it('testSyncGoTo0004', 0, async function (done) {
        console.log(TAG + "************* testSyncGoTo0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToLastRow())
        resultSet.goTo(5)
        expect(3).assertEqual(resultSet.rowIndex)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoTo0004 end *************");

    })

    /**
     * @tc.name resultSet goToRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0150
     * @tc.desc resultSet goToRow test
     */
    it('testSyncGoToRow0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToRow0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        resultSet.goToRow(1)
        expect(1).assertEqual(resultSet.rowIndex)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToRow0001 end *************");

    })

    /**
     * @tc.name resultSet goToRow with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0151
     * @tc.desc resultSet goToRow with no result test
     */
    it('testSyncGoToRow0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToRow0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)

        resultSet.goToRow(1)
        expect(-1).assertEqual(resultSet.rowIndex)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToRow0002 end *************");

    })

    /**
     * @tc.name resultSet goToRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0152
     * @tc.desc resultSet goToRow test
     */
    it('testSyncGoToRow0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToRow0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        resultSet.goToRow(1)
        expect(1).assertEqual(resultSet.rowIndex)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToRow0003 end *************");

    })

    /**
     * @tc.name resultSet goToRow after last row test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0153
     * @tc.desc resultSet goToRow after last row test
     */
    it('testSyncGoToRow0004', 0, async function (done) {
        console.log(TAG + "************* testSyncGoToRow0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToLastRow())
        resultSet.goToRow(5)
        expect(3).assertEqual(resultSet.rowIndex)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGoToRow0004 end *************");

    })

    /**
     * @tc.name resultSet isAtFirstRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0160
     * @tc.desc resultSet isAtFirstRow test
     */
    it('testSyncIsAtFirstRow0001', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtFirstRow0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.isAtFirstRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtFirstRow0001 end *************");

    })

    /**
     * @tc.name resultSet isAtFirstRow with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0161
     * @tc.desc resultSet isAtFirstRow with no result test
     */
    it('testSyncIsAtFirstRow0002', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtFirstRow0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)

        expect(false).assertEqual(resultSet.isAtFirstRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtFirstRow0002 end *************");

    })

    /**
     * @tc.name resultSet isAtFirstRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0162
     * @tc.desc resultSet isAtFirstRow test
     */
    it('testSyncIsAtFirstRow0003', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtFirstRow0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        expect(false).assertEqual(resultSet.isAtFirstRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtFirstRow0003 end *************");

    })

    /**
     * @tc.name resultSet isAtFirstRow after last row test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0163
     * @tc.desc resultSet isAtFirstRow after last row test
     */
    it('testSyncIsAtFirstRow0004', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtFirstRow0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToLastRow())
        expect(false).assertEqual(resultSet.isAtFirstRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtFirstRow0004 end *************");

    })

    /**
     * @tc.name resultSet isAtFirstRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0165
     * @tc.descresultSet isAtFirstRow test
     */
    it('testSyncIsAtFirstRow0005', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtFirstRow0005 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        resultSet.goTo(1)
        resultSet.goTo(0)
        expect(true).assertEqual(resultSet.isAtFirstRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtFirstRow0005 end *************");

    })

    /**
     * @tc.name resultSet isAtFirstRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0166
     * @tc.descresultSet isAtFirstRow test
     */
    it('testSyncIsAtFirstRow0006', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtFirstRow0006 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        resultSet.goTo(1)
        expect(true).assertEqual(resultSet.isAtFirstRow)
        expect(true).assertEqual(resultSet.isAtFirstRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtFirstRow0006 end *************");

    })

    /**
     * @tc.name resultSet isAtLastRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0170
     * @tc.desc resultSet isAtLastRow test
     */
    it('testSyncIsAtLastRow0001', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtLastRow0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(false).assertEqual(resultSet.isAtLastRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtLastRow0001 end *************");

    })

    /**
     * @tc.name resultSet isAtLastRow with no result test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0171
     * @tc.desc resultSet isAtLastRow with no result test
     */
    it('testSyncIsAtLastRow0002', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtLastRow0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)

        expect(false).assertEqual(resultSet.isAtLastRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtLastRow0002 end *************");

    })

    /**
     * @tc.name resultSet isAtLastRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0172
     * @tc.desc resultSet isAtLastRow test
     */
    it('testSyncIsAtLastRow0003', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtLastRow0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        expect(false).assertEqual(resultSet.isAtLastRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtLastRow0003 end *************");

    })

    /**
     * @tc.name resultSet isAtLastRow after last row test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0173
     * @tc.desc resultSet isAtLastRow after last row test
     */
    it('testSyncIsAtLastRow0004', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtLastRow0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToLastRow())
        expect(true).assertEqual(resultSet.isAtLastRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtLastRow0004 end *************");

    })

    /**
     * @tc.name resultSet isAtLastRow test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0174
     * @tc.desc resultSet isAtLastRow test
     */
    it('testSyncIsAtLastRow0005', 0, async function (done) {
        console.log(TAG + "************* testSyncIsAtLastRow0005 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        resultSet.goToRow(2)
        expect(true).assertEqual(resultSet.isAtLastRow)
        expect(true).assertEqual(resultSet.isAtLastRow)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsAtLastRow0005 end *************");

    })

    /**
     * @tc.name resultSet getDouble test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0180
     * @tc.desc resultSet getDouble test
     */
    it('testSyncGetDouble0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGetDouble0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        resultSet.goTo(1)
        const data3 = resultSet.getDouble(resultSet.getColumnIndex("data3"))
        expect(1.0).assertEqual(data3)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetDouble0001 end *************");

    })

    /**
     * @tc.name resultSet getDouble test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0181
     * @tc.desc resultSet getDouble test
     */
    it('testSyncGetDouble0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGetDouble0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        resultSet.goTo(2)
        const data3 = resultSet.getDouble(resultSet.getColumnIndex("data3"))
        expect(2.5).assertEqual(data3)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetDouble0002 end *************");

    })

    /**
     * @tc.name resultSet getDouble test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0182
     * @tc.desc resultSet getDouble test
     */
    it('testSyncGetDouble0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGetDouble0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        resultSet.goTo(3)
        const data3 = resultSet.getDouble(resultSet.getColumnIndex("data3"))
        expect(1.8).assertEqual(data3)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetDouble0003 end *************");

    })

    /**
     * @tc.name resultSet getDouble test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0183
     * @tc.desc resultSet getDouble test
     */
    it('testSyncGetDouble0004', 0, async function (done) {
        console.log(TAG + "************* testSyncGetDouble0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        resultSet.goTo(1)
        const data2 = resultSet.getDouble(resultSet.getColumnIndex("data2"))
        expect(10).assertEqual(data2)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetDouble0004 end *************");

    })

    /**
     * @tc.name resultSet isColumnNull test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0190
     * @tc.desc resultSet isColumnNull test
     */
    it('testSyncIsColumnNull0001', 0, async function (done) {
        console.log(TAG + "************* testSyncIsColumnNull0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        const isColumnNull1 = resultSet.isColumnNull(resultSet.getColumnIndex("data1"))
        expect(false).assertEqual(isColumnNull1)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsColumnNull0001 end *************");

    })

    /**
     * @tc.name resultSet isColumnNull test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0191
     * @tc.desc resultSet isColumnNull test
     */
    it('testSyncIsColumnNull0002', 0, async function (done) {
        console.log(TAG + "************* testSyncIsColumnNull0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        expect(true).assertEqual(resultSet.goToNextRow())
        const isColumnNull4 = resultSet.isColumnNull(resultSet.getColumnIndex("data4"))
        expect(true).assertEqual(isColumnNull4)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsColumnNull0002 end *************");

    })

    /**
     * @tc.name resultSet isColumnNull test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0192
     * @tc.desc resultSet isColumnNull test
     */
    it('testSyncIsColumnNull0003', 0, async function (done) {
        console.log(TAG + "************* testSyncIsColumnNull0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        resultSet.goToRow(5)
        try {
            expect(false).assertEqual(resultSet.isColumnNull(1));
        } catch (e) {
            expect(e.code).assertEqual("14800012");
        }
        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsColumnNull0003 end *************");

    })
    /**
     * @tc.name resultSet isColumnNull test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0193
     * @tc.desc resultSet isColumnNull test
     */
    it('testSyncIsColumnNull0004', 0, async function (done) {
        console.log(TAG + "************* testSyncIsColumnNull0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        {
            resultSet.goToRow(2)
            expect(false).assertEqual(resultSet.isColumnNull(1))
            expect(true).assertEqual(resultSet.isColumnNull(4))
        }
        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncIsColumnNull0004 end *************");

    })

    /**
     * @tc.name resultSet getColumnIndex test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0200
     * @tc.desc resultSet getColumnIndex test
     */
    it('testSyncGetColumnIndex0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGetColumnIndex0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow())
        expect(1).assertEqual(resultSet.getColumnIndex("data1"))

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetColumnIndex0001 end *************");

    })

    /**
     * @tc.name resultSet getColumnIndex test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0201
     * @tc.desc resultSet getColumnIndex test
     */
    it('testSyncGetColumnIndex0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGetColumnIndex0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)
        expect(-1).assertEqual(resultSet.getColumnIndex("data1"))

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetColumnIndex0002 end *************");

    })

    /**
     * @tc.name resultSet getColumnIndex test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0202
     * @tc.desc resultSet getColumnIndex test
     */
    it('testSyncGetColumnIndex0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGetColumnIndex0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        expect(-1).assertEqual(resultSet.getColumnIndex("dataX"))

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetColumnIndex0003 end *************");

    })

    /**
     * @tc.name resultSet getColumnIndex test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0203
     * @tc.desc resultSet getColumnIndex test
     */
    it('testSyncGetColumnIndex0004', 0, async function (done) {
        console.log(TAG + "************* testSyncGetColumnIndex0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        try {
            expect(-1).assertEqual(resultSet.getColumnIndex(""))
        } catch (err) {
            expect("401").assertEqual(err.code)
        }
        resultSet.close()
        resultSet = null
        done()
        console.log(TAG + "************* testSyncGetColumnIndex0004 end *************");

    })

    /**
     * @tc.name resultSet getColumnName test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0210
     * @tc.desc resultSet getColumnName test
     */
    it('testSyncGetColumnName0001', 0, async function (done) {
        console.log(TAG + "************* testSyncGetColumnIndex0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect("data1").assertEqual(resultSet.getColumnName(1))
        expect("data4").assertEqual(resultSet.getColumnName(4))

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetColumnName0001 end *************");

    })

    /**
     * @tc.name resultSet getColumnName test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0211
     * @tc.desc resultSet getColumnName test
     */
    it('testSyncGetColumnName0002', 0, async function (done) {
        console.log(TAG + "************* testSyncGetColumnName0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)

        expect("").assertEqual(resultSet.getColumnName(1))
        expect("").assertEqual(resultSet.getColumnName(4))

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetColumnName0002 end *************");

    })

    /**
     * @tc.name resultSet getColumnName test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0212
     * @tc.desc resultSet getColumnName test
     */
    it('testSyncGetColumnName0003', 0, async function (done) {
        console.log(TAG + "************* testSyncGetColumnName0003 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)

        expect("").assertEqual(resultSet.getColumnName(10))

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetColumnName0003 end *************");

    })

    /**
     * @tc.name resultSet getColumnName test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0213
     * @tc.desc resultSet getColumnName test
     */
    it('testSyncGetColumnName0004', 0, async function (done) {
        console.log(TAG + "************* testSyncGetColumnName0004 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)

        expect("").assertEqual(resultSet.getColumnName(10))

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncGetColumnName0004 end *************");

    })

    /**
     * @tc.name resultSet close test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0220
     * @tc.desc resultSet close test
     */
    it('testSyncClose0001', 0, async function (done) {
        console.log(TAG + "************* testSyncClose0001 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = rdbStore.querySync(predicates)
        resultSet.goToRow(1)
        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncClose0001 end *************");

    })

    /**
     * @tc.name resultSet close test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0221
     * @tc.desc resultSet close test
     */
    it('testSyncClose0002', 0, async function (done) {
        console.log(TAG + "************* testSyncClose0002 start *************");

        let predicates = await new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "wangwu");
        let resultSet = rdbStore.querySync(predicates)
        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)

        resultSet.close()
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncClose0002 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0222
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0001', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0001 start *************");

        await createBigData(500);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(500).assertEqual(count);

        resultSet.goToFirstRow();
        let i = 0;
        while (resultSet.isEnded == false) {
            expect("test" + i++).assertEqual(resultSet.getString(1))
            resultSet.goToNextRow();
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0001 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0223
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0002', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0002 start *************");

        await createBigData(500);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(500).assertEqual(count);

        resultSet.goToLastRow();
        let i = resultSet.rowCount;
        while (i >= 1) {
            expect("test" + --i).assertEqual(resultSet.getString(1))
            resultSet.goToPreviousRow();
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0002 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0224
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0003', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0003 start *************");

        await createBigData(500);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(500).assertEqual(count);

        let rows = [62, 80, 59, 121, 45, 99, 42, 104, 41, 105, 499, 248];
        for (const i of rows) {
            resultSet.goToRow(i);
            expect("test" + i).assertEqual(resultSet.getString(1))
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0003 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0225
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0004', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0004 start *************");

        await createBigData(0);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(0).assertEqual(count);

        resultSet.goToFirstRow();
        expect(true).assertEqual(resultSet.isStarted);
        console.log(TAG + "************* testSyncBigData0004 after goto first row *************");
        let rows = [1, 2, 0, -1, -2];
        for (const i of rows) {
            resultSet.goToRow(i);
            expect(true).assertEqual(resultSet.isStarted);
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0004 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0226
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0005', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0005 start *************");

        await createBigData(1);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(1).assertEqual(count);

        resultSet.goToFirstRow();
        expect(true).assertEqual(resultSet.isStarted);
        expect("test0").assertEqual(resultSet.getString(1))
        try {
            let rows = [1, 2, -1, -2];
            for (const i of rows) {
                resultSet.goToRow(i)
                expect(true).assertEqual(resultSet.isStarted)
                expect("").assertEqual(resultSet.getString(1))
            }
        } catch (e) {
            expect(e.code).assertEqual("14800012");
        }
        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0005 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0227
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0006', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0006 start *************");

        await createBigData(2);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(2).assertEqual(count);

        resultSet.goToFirstRow();
        expect(true).assertEqual(resultSet.isStarted);

        let rows = [0, 1];
        for (const i of rows) {
            resultSet.goToRow(i);
            expect(true).assertEqual(resultSet.isStarted);
            expect("test" + i).assertEqual(resultSet.getString(1))
        }

        try {
            rows = [2, 3, 4, -1, -2];
            for (const i of rows) {
                resultSet.goToRow(i);
                expect(true).assertEqual(resultSet.isStarted);
                expect("").assertEqual(resultSet.getString(1))
            }
        } catch (e) {
            expect(e.code).assertEqual("14800012");
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0006 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0228
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0007', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0007 start *************");

        await createBigData(500);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(500).assertEqual(count);

        let rows = [62, 80, 59, 121, 45, -1, 99, 42, 104, 41, 105, 499, 248];
        for (const i of rows) {
            resultSet.goToRow(i);
            if (i > 0) {
                expect("test" + i).assertEqual(resultSet.getString(1))
            } else {
                expect("test45").assertEqual(resultSet.getString(1))
            }
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0007 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0229
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0008', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0008 start *************");

        await createBigData(200);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(200).assertEqual(count);

        let i = 0;
        while (resultSet.goToNextRow() == 0) {
            expect("test" + i++).assertEqual(resultSet.getString(1))
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0008 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0230
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0009', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0009 start *************");

        await createBigData(200);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(200).assertEqual(count);

        let i = 0;
        while (i < 200) {
            resultSet.goToRow(i);
            expect("test" + i).assertEqual(resultSet.getString(1))
            i++;
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0009 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0231
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0010', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0010 start *************");

        await createBigData(200);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(200).assertEqual(count);

        resultSet.goToFirstRow();
        let i = 0;
        while (resultSet.isEnded == false) {
            expect("test" + i++).assertEqual(resultSet.getString(1))
            resultSet.goToNextRow();
        }

        i = 0;
        while (i < 200) {
            resultSet.goToRow(i);
            expect("test" + i).assertEqual(resultSet.getString(1))
            i++;
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0010 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0232
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0011', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0011 start *************");

        await createBigData(200);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(200).assertEqual(count);

        let i = 0;
        while (i < 200) {
            resultSet.goToRow(i);
            expect("test" + i).assertEqual(resultSet.getString(1))
            i++;
        }

        resultSet.goToFirstRow();
        i = 0;
        while (resultSet.isEnded == false) {
            expect("test" + i++).assertEqual(resultSet.getString(1))
            resultSet.goToNextRow();
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0011 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0232
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0012', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0012 start *************");

        await createBigData(1);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(1).assertEqual(count);

        resultSet.goToNextRow();
        expect("test0").assertEqual(resultSet.getString(1))

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0012 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0232
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0013', 0, async function () {
        console.log(TAG + "************* testSyncBigData0013 start *************");

        await createBigData(200);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(200).assertEqual(count);
        resultSet.goToFirstRow();
        let i = 0;
        while (resultSet.isEnded == false) {
            expect("test" + i++).assertEqual(resultSet.getString(1))
            resultSet.goToNextRow();
        }
        resultSet.goToRow(1);
        expect("test1").assertEqual(resultSet.getString(1))
        resultSet.goToRow(5);
        expect("test5").assertEqual(resultSet.getString(1))
        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        console.log(TAG + "************* testSyncBigData0013 end *************");

    })

    /**
     * @tc.name big resultSet data test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0233
     * @tc.desc big resultSet data test
     */
    it('testSyncBigData0014', 0, async function (done) {
        console.log(TAG + "************* testSyncBigData0014 start *************");

        await createBigData(5);
        let resultSet = rdbStore.querySqlSync("SELECT * FROM test");
        let count = resultSet.rowCount;
        expect(5).assertEqual(count);

        resultSet.goToFirstRow();
        let i = 0;
        while (resultSet.isEnded == false) {
            expect("test" + i++).assertEqual(resultSet.getString(1))
            resultSet.goToNextRow();
        }

        i = 0;
        while (i < 5) {
            resultSet.goToRow(i);
            expect("test" + i).assertEqual(resultSet.getString(1))
            i++;
        }

        resultSet.close()
        expect(true).assertEqual(resultSet.isClosed)
        resultSet = null;
        done();
        console.log(TAG + "************* testSyncBigData0014 end *************");

    })
    console.log(TAG + "*************Unit Test End*************");
})