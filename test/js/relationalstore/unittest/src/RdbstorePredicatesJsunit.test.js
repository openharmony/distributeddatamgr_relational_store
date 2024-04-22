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
import dataSharePredicates from '@ohos.data.dataSharePredicates';

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_ALL_DATA_TYPE_SQL = "CREATE TABLE IF NOT EXISTS AllDataType "
    + "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
    + "integerValue INTEGER , longValue INTEGER , shortValue INTEGER , booleanValue INTEGER , "
    + "doubleValue REAL , floatValue REAL , stringValue TEXT , blobValue BLOB , clobValue TEXT , "
    + "byteValue INTEGER , dateValue INTEGER , timeValue INTEGER , timestampValue INTEGER , "
    + "calendarValue INTEGER , characterValue TEXT , primIntValue INTEGER , primLongValue INTEGER , "
    + "primShortValue INTEGER , primFloatValue REAL , primDoubleValue REAL , "
    + "primBooleanValue INTEGER , primByteValue INTEGER , primCharValue TEXT, `order` INTEGER);";

const STORE_CONFIG = {
    name: "Predicates.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined
var context = ability_featureAbility.getContext()
var DOUBLE_MAX = 9223372036854775807;
describe('rdbPredicatesTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_ALL_DATA_TYPE_SQL, null);
        await buildAllDataType1();
        await buildAllDataType2();
        await buildAllDataType3();
    })

    beforeEach(function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "Predicates.db");
    })

    async function buildAllDataType1() {
        console.log(TAG + "buildAllDataType1 start");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "integerValue": 2147483647,
                "doubleValue": DOUBLE_MAX,
                "booleanValue": true,
                "floatValue": -0.123,
                "longValue": 9223372036854775807,
                "shortValue": 32767,
                "characterValue": ' ',
                "stringValue": "ABCDEFGHIJKLMN",
                "blobValue": u8,
                "byteValue": 127,
            }
            await rdbStore.insert("AllDataType", valueBucket)
        }
    }

    async function buildAllDataType2() {
        console.log(TAG + "buildAllDataType2 start");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "integerValue": 1,
                "doubleValue": 1.0,
                "booleanValue": false,
                "floatValue": 1.0,
                "longValue": 1,
                "shortValue": 1,
                "characterValue": '中',
                "stringValue": "ABCDEFGHIJKLMN",
                "blobValue": u8,
                "byteValue": 1,
            }
            await rdbStore.insert("AllDataType", valueBucket)
        }
    }

    async function buildAllDataType3() {
        console.log(TAG + "buildAllDataType3 start");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "integerValue": -2147483648,
                "doubleValue": Number.MIN_VALUE,
                "booleanValue": false,
                "floatValue": 0.1234567,
                "longValue": -9223372036854775808,
                "shortValue": -32768,
                "characterValue": '#',
                "stringValue": "ABCDEFGHIJKLMN",
                "blobValue": u8,
                "byteValue": -128,
            }
            await rdbStore.insert("AllDataType", valueBucket)
        }
    }

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0010
     * @tc.name Normal test case of predicates, test "equalTo" for boolean value
     * @tc.desc 1.Execute equalTo("boolType", true)
     *          2.Query data
     */
    it('testEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("booleanValue", true);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0001 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0011
     * @tc.name Normal test case of predicates, test "or"
     * @tc.desc 1.Execute equalTo().or().equalTo()
     *          2.Query data
     */
    it('testEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("byteValue", -128).or().equalTo("byteValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0012
     * @tc.name Normal test case of predicates, test "equalTo" for string value
     * @tc.desc 1.Execute equalTo("stringValue", "ABCDEFGHIJKLMN")
     *          2.Query data
     */
    it('testEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0003 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0013
     * @tc.name Normal test case of predicates, test "equalTo" for boundary value of doubleValue
     * @tc.desc 1.Execute equalTo("doubleValue", DOUBLE_MAX)
     *          2.Query data
     */
    it('testEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("doubleValue", DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0014
     * @tc.name Normal test case of predicates, test "equalTo" for boundary value of shortValue
     * @tc.desc 1.Execute equalTo("shortValue", -32768.0)
     *          2.Query data
     */
    it('testEqualTo0005', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0005 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("shortValue", -32768.0);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0015
     * @tc.name Normal test case of predicates, test "equalTo" for integer value
     * @tc.desc 1.Execute equalTo("integerValue", 1)
     *          2.Query data
     *          3.Execute getLong
     */
    it('testEqualTo0006', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0006 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(true).assertEqual(result.goToFirstRow());
        expect(2).assertEqual(result.getLong(0));
        result.close()

        done();
        console.log(TAG + "************* testEqualTo0006 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0016
     * @tc.name Normal test case of predicates, test "equalTo" for long value
     * @tc.desc 1.Execute equalTo("longValue", 1)
     *          2.Query data
     *          3.Execute getLong
     */
    it('testEqualTo0007', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0007 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(true).assertEqual(result.goToFirstRow());
        expect(2).assertEqual(result.getLong(0))
        result.close()

        done();
        console.log(TAG + "************* testEqualTo0007 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0017
     * @tc.name Normal test case of predicates, test "equalTo" for float type
     * @tc.desc 1.Execute equalTo("floatValue", -0.123)
     *          2.Query data
     *          3.Execute getLong
     */
    it('testEqualTo0008', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0008 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("floatValue", -0.123);
        let result = await rdbStore.query(predicates);
        expect(true).assertEqual(result.goToFirstRow());
        expect(1).assertEqual(result.getLong(0))
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0008 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0018
     * @tc.name Normal test case of predicates, test "equalTo" for true param
     * @tc.desc 1.Execute equalTo('1', 1)
     *          2.Query data
     *          3.Execute equalTo('1', Number.NaN)
     *          4.Query data
     */
    it('testEqualTo0009', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0009 start *************");

        let predicates1 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates1.equalTo('1', 1);
        let result1 = await rdbStore.query(predicates1);
        expect(true).assertEqual(result1.goToFirstRow());
        expect(3).assertEqual(result1.rowCount)
        result1.close()
        result1 = null

        let predicates2 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates2.equalTo('1', Number.NaN);
        let result2 = await rdbStore.query(predicates2);
        expect(0).assertEqual(result2.rowCount)
        result2.close()
        result2 = null

        done();
        console.log(TAG + "************* testEqualTo0009 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0020
     * @tc.name Normal test case of predicates, test "notEqualTo" for boolean value
     * @tc.desc 1.Execute notEqualTo("boolType", true)
     *          2.Query data
     */
    it('testNotEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notEqualTo("booleanValue", true);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0021
     * @tc.name Normal test case of predicates, test "notEqualTo" for byte value
     * @tc.desc 1.Execute notEqualTo("byteValue", -128)
     *          2.Execute notEqualTo("byteValue", 1)
     *          3.Query data
     */
    it('testNotEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notEqualTo("byteValue", -128);
        predicates.notEqualTo("byteValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0022
     * @tc.name Normal test case of predicates, test "notEqualTo" for string value
     * @tc.desc 1.Execute notEqualTo("stringValue", "ABCDEFGHIJKLMN")
     *          2.Query data
     */
    it('testNotEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notEqualTo("stringValue", "ABCDEFGHIJKLMN");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0023
     * @tc.name Normal test case of predicates, test "notEqualTo" for double value
     * @tc.desc 1.Execute notEqualTo ("doubleValue", DOUBLE_MAX)
     *          2.Query data
     */
    it('testNotEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notEqualTo("doubleValue", DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0024
     * @tc.name Normal test case of predicates, test "notEqualTo" for boundary value of shortValue
     * @tc.desc 1.Execute notEqualTo ("shortValue", -32768)
     *          2.Query data
     */
    it('testNotEqualTo0005', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0005 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notEqualTo("shortValue", -32768);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0025
     * @tc.name Normal test case of predicates, test "notEqualTo" for integer value
     * @tc.desc 1.Execute notEqualTo ("integerValue", 1)
     *          2.Query data
     */
    it('testNotEqualTo0006', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0006 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notEqualTo("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0026
     * @tc.name Normal test case of predicates, test "notEqualTo" for long value
     * @tc.desc 1.Execute notEqualTo ("longValue", 1)
     *          2.Query data
     */
    it('testNotEqualTo0007', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0007 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notEqualTo("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0007 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0027
     * @tc.name Normal test case of predicates, test "notEqualTo" for float value
     * @tc.desc 1.Execute notEqualTo ("floatValue", -0.123)
     *          2.Query data
     */
    it('testNotEqualTo0008', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0008 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notEqualTo("floatValue", -0.123);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0008 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0028
     * @tc.name Normal test case of predicates, test "notEqualTo" for true field
     * @tc.desc 1.Execute notEqualTo ('1', 1)
     *          2.Query data
     *          3.Execute notEqualTo ('1', Number.NaN)
     *          4.Query data
     */
    it('testNotEqualTo0009', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0009 start *************");

        let predicates1 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates1.notEqualTo('1', 1);
        let result1 = await rdbStore.query(predicates1);
        expect(0).assertEqual(result1.rowCount)
        result1.close()
        result1 = null

        let predicates2 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates2.notEqualTo('1', Number.NaN);
        let result2 = await rdbStore.query(predicates2);
        expect(0).assertEqual(result2.rowCount)
        result2.close()
        result2 = null

        done();
        console.log(TAG + "************* testNotEqualTo0009 end   *************");
    })


    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0030
     * @tc.name Normal test case of predicates, test "isNull" for primLong value
     * @tc.desc 1.Execute isNull ("primLongValue")
     *          2.Query data
     */
    it('testIsNull0001', 0, async function (done) {
        console.log(TAG + "************* testIsNull001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.isNull("primLongValue");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNull0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0031
     * @tc.name Normal test case of predicates, test "isNull" for long value
     * @tc.desc 1.Execute isNull ("longValue")
     *          2.Query data
     */
    it('testIsNull0002', 0, async function (done) {
        console.log(TAG + "************* testIsNull0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.isNull("longValue");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNull0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0032
     * @tc.name Normal test case of predicates, test "isNull" for string value
     * @tc.desc 1.Execute isNull ("stringValue")
     *          2.Query data
     */
    it('testIsNull0003', 0, async function (done) {
        console.log(TAG + "************* testIsNull0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.isNull("stringValue");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNull0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0033
     * @tc.name Abnormal test case of predicates, test "isNull" for invalid param
     * @tc.desc 1.Execute isNull ("stringValueX")
     *          2.Query data
     */
    it('testIsNull0004', 0, async function (done) {
        console.log(TAG + "************* testIsNull0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.isNull("stringValueX");
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNull0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0040
     * @tc.name Normal test case of predicates, test "isNotNull" for primlong value
     * @tc.desc 1.Execute isNotNull ("primLongValue")
     *          2.Query data
     */
    it('testIsNotNull0001', 0, async function (done) {
        console.log(TAG + "************* testIsNotNull0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.isNotNull("primLongValue");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNotNull0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0041
     * @tc.name Normal test case of predicates, test "isNotNull" for long value
     * @tc.desc 1.Execute isNotNull ("longValue")
     *          2.Query data
     */
    it('testIsNotNull0002', 0, async function (done) {
        console.log(TAG + "************* testIsNotNull0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.isNotNull("longValue");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNotNull0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0042
     * @tc.name Normal test case of predicates, test "isNotNull" for string value
     * @tc.desc 1.Execute isNotNull ("stringValue")
     *          2.Query data
     */
    it('testIsNotNull0003', 0, async function (done) {
        console.log(TAG + "************* testIsNotNull0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.isNotNull("stringValue");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNotNull0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0043
     * @tc.name Abnormal test case of predicates, test "isNotNull" for invalid param
     * @tc.desc 1.Execute isNotNull ("stringValueX")
     *          2.Query data
     */
    it('testIsNotNull0004', 0, async function (done) {
        console.log(TAG + "************* testIsNotNull0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.isNotNull("stringValueX");
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNotNull0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0050
     * @tc.name Normal test case of predicates, test "greaterThan" for string value
     * @tc.desc 1.Execute greaterThan ("stringValue", "ABC")
     *          2.Query data
     */
    it('testGreaterThan0001', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThan("stringValue", "ABC");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0051
     * @tc.name Normal test case of predicates, test "greaterThan" for double value
     * @tc.desc 1.Execute greaterThan ("doubleValue", 0.0)
     *          2.Query data
     */
    it('testGreaterThan0002', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThan("doubleValue", 0.0);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0052
     * @tc.name Normal test case of predicates, test "greaterThan" for integer value
     * @tc.desc 1.Execute greaterThan ("integerValue", 1)
     *          2.Query data
     */
    it('testGreaterThan0003', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThan("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0053
     * @tc.name Normal test case of predicates, test "greaterThan" for long value
     * @tc.desc 1.Execute greaterThan ("longValue", 1)
     *          2.Query data
     */
    it('testGreaterThan0004', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThan("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0054
     * @tc.name Normal test case of predicates, test "greaterThan" for string value
     * @tc.desc 1.Execute greaterThan ("stringValue", "ZZZ")
     *          2.Query data
     */
    it('testGreaterThan0005', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0005 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThan("stringValue", "ZZZ");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0055
     * @tc.name Normal test case of predicates, test "greaterThan" for double value
     * @tc.desc 1.Execute greaterThan ("doubleValue", 999.0)
     *          2.Query data
     */
    it('testGreaterThan0006', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0006 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThan("doubleValue", 999.0);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0056
     * @tc.name Normal test case of predicates, test "greaterThan" for integer value
     * @tc.desc 1.Execute greaterThan ("integerValue", -999)
     *          2.Query data
     */
    it('testGreaterThan0007', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0007 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThan("integerValue", -999);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0007 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0057
     * @tc.name Normal test case of predicates, test "greaterThan" for long value
     * @tc.desc 1.Execute greaterThan ("longValue", -999)
     *          2.Query data
     */
    it('testGreaterThan0008', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0008 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThan("longValue", -999);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0008 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0058
     * @tc.name Normal test case of predicates, test "greaterThan" for boundary value of longValue
     * @tc.desc 1.Execute greaterThan ("longValue", Number.NaN)
     *          2.Execute greaterThan ("longValue", Number.NEGATIVE_INFINITY)
     *          3.Execute greaterThan ("longValue", Number.POSITIVE_INFINITY)
     *          4.Execute greaterThan ("longValue", Number.MIN_SAFE_INTEGER)
     *          5.Execute greaterThan ("longValue", Number.MAX_SAFE_INTEGER)
     */
    it('testGreaterThan0009', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0009 start *************");

        let predicates1 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates1.greaterThan("longValue", Number.NaN);
        let result1 = await rdbStore.query(predicates1);
        expect(0).assertEqual(result1.rowCount);
        result1.close()
        result1 = null

        let predicates2 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates2.greaterThan("longValue", Number.NEGATIVE_INFINITY);
        let result2 = await rdbStore.query(predicates2);
        expect(3).assertEqual(result2.rowCount);
        result2.close()
        result2 = null

        let predicates3 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates3.greaterThan("longValue", Number.POSITIVE_INFINITY);
        let result3 = await rdbStore.query(predicates3);
        expect(0).assertEqual(result3.rowCount);
        result3.close()
        result3 = null

        let predicates4 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates4.greaterThan("longValue", Number.MIN_SAFE_INTEGER);
        let result4 = await rdbStore.query(predicates4);
        expect(2).assertEqual(result4.rowCount);
        result4.close()
        result4 = null

        let predicates5 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates5.greaterThan("longValue", Number.MAX_SAFE_INTEGER);
        let result5 = await rdbStore.query(predicates5);
        expect(1).assertEqual(result5.rowCount);
        result5.close()
        result5 = null

        done();
        console.log(TAG + "************* testGreaterThan0009 end *************");
    })


    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0060
     * @tc.name Normal test case of predicates, test "greaterThanOrEqualTo" for string value
     * @tc.desc 1.Execute greaterThanOrEqualTo ("stringValue", "ABC")
     *          2.Query data
     */
    it('testGreaterThanOrEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testGreaterThanOrEqualTo0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThanOrEqualTo("stringValue", "ABC");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThanOrEqualTo0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0061
     * @tc.name Normal test case of predicates, test "greaterThanOrEqualTo" for double value
     * @tc.desc 1.Execute greaterThanOrEqualTo ("doubleValue", 0.0)
     *          2.Query data
     */
    it('testGreaterThanOrEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testGreaterThanOrEqualTo0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThanOrEqualTo("doubleValue", 0.0);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThanOrEqualTo0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0062
     * @tc.name Normal test case of predicates, test "greaterThanOrEqualTo" for integer value
     * @tc.desc 1.Execute greaterThanOrEqualTo ("integerValue", 1)
     *          2.Query data
     */
    it('testGreaterThanOrEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testGreaterThanOrEqualTo0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThanOrEqualTo("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThanOrEqualTo0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0063
     * @tc.name Normal test case of predicates, test "greaterThanOrEqualTo" for long value
     * @tc.desc 1.Execute greaterThanOrEqualTo ("longValue", 1)
     *          2.Query data
     */
    it('testGreaterThanOrEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testGreaterThanOrEqualTo0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.greaterThanOrEqualTo("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThanOrEqualTo0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0070
     * @tc.name Normal test case of predicates, test "lessThan" for string value
     * @tc.desc 1.Execute lessThan ("stringValue", "ABD")
     *          2.Query data
     */
    it('testLessThan0001', 0, async function (done) {
        console.log(TAG + "************* testLessThan0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThan("stringValue", "ABD");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0071
     * @tc.name Normal test case of predicates, test "lessThan" for double value
     * @tc.desc 1.Execute lessThan ("doubleValue", 0.0)
     *          2.Query data
     */
    it('testLessThan0002', 0, async function (done) {
        console.log(TAG + "************* testLessThan0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThan("doubleValue", 0.0);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0072
     * @tc.name Normal test case of predicates, test "lessThan" for integer value
     * @tc.desc 1.Execute lessThan ("integerValue", 1)
     *          2.Query data
     */
    it('testLessThan0003', 0, async function (done) {
        console.log(TAG + "************* testLessThan0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThan("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0073
     * @tc.name Normal test case of predicates, test "lessThan" for long value
     * @tc.desc 1.Execute lessThan ("longValue", 1)
     *          2.Query data
     */
    it('testLessThan0004', 0, async function (done) {
        console.log(TAG + "************* testLessThan0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThan("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0074
     * @tc.name Normal test case of predicates, test "lessThan" for string value
     * @tc.desc 1.Execute lessThan ("stringValue", "ABD")
     *          2.Query data
     */
    it('testLessThan0005', 0, async function (done) {
        console.log(TAG + "************* testLessThan0005 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThan("stringValue", "ABD");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0075
     * @tc.name Normal test case of predicates, test "lessThan" for double value
     * @tc.desc 1.Execute lessThan ("doubleValue", 1.0)
     *          2.Query data
     */
    it('testLessThan0006', 0, async function (done) {
        console.log(TAG + "************* testLessThan0006 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThan("doubleValue", 1.0);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0076
     * @tc.name Normal test case of predicates, test "lessThan" for boundary value of integerValue
     * @tc.desc 1.Execute lessThan ("integerValue", -2147483648)
     *          2.Query data
     */
    it('testLessThan0007', 0, async function (done) {
        console.log(TAG + "************* testLessThan0007 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThan("integerValue", -2147483648);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0007 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0077
     * @tc.name Normal test case of predicates, test "lessThan" for boundary value of longValue
     * @tc.desc 1.Execute lessThan ("longValue", -9223372036854775808)
     *          2.Query data
     */
    it('testLessThan0008', 0, async function (done) {
        console.log(TAG + "************* testLessThan0008 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThan("longValue", -9223372036854775808);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0008 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0080
     * @tc.name Normal test case of predicates, test "lessThanOrEqualTo" for string value
     * @tc.desc 1.Execute lessThanOrEqualTo ("stringValue", "ABD")
     *          2.Query data
     */
    it('testLessThanOrEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThanOrEqualTo("stringValue", "ABD");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0081
     * @tc.name Normal test case of predicates, test "lessThanOrEqualTo" for double value
     * @tc.desc 1.Execute lessThanOrEqualTo ("doubleValue", 0.0)
     *          2.Query data
     */
    it('testLessThanOrEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThanOrEqualTo("doubleValue", 0.0);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0082
     * @tc.name Normal test case of predicates, test "lessThanOrEqualTo" for integer value
     * @tc.desc 1.Execute lessThanOrEqualTo ("integerValue", 1)
     *          2.Query data
     */
    it('testLessThanOrEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThanOrEqualTo("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0083
     * @tc.name Normal test case of predicates, test "lessThanOrEqualTo" for long value
     * @tc.desc 1.Execute lessThanOrEqualTo ("longValue", 1)
     *          2.Query data
     */
    it('testLessThanOrEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.lessThanOrEqualTo("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0084
     * @tc.name Normal test case of predicates, test "lessThanOrEqualTo" for boundary value of longValue
     * @tc.desc 1.Execute lessThanOrEqualTo ("longValue", Number.NaN)
     *          2.Execute lessThanOrEqualTo ("longValue", Number.NEGATIVE_INFINITY)
     *          3.Execute lessThanOrEqualTo ("longValue", Number.POSITIVE_INFINITY)
     *          4.Execute lessThanOrEqualTo ("longValue", Number.MAX_VALUE)
     *          5.Execute lessThanOrEqualTo ("longValue", Number.MIN_VALUE)
     */
    it('testLessThanOrEqualTo0005', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0005 start *************");

        let predicates1 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates1.lessThanOrEqualTo("longValue", Number.NaN);
        let result1 = await rdbStore.query(predicates1);
        expect(0).assertEqual(result1.rowCount);
        result1.close()
        result1 = null

        let predicates2 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates2.lessThanOrEqualTo("longValue", Number.NEGATIVE_INFINITY);
        let result2 = await rdbStore.query(predicates2);
        expect(0).assertEqual(result2.rowCount);
        result2.close()
        result2 = null

        let predicates3 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates3.lessThanOrEqualTo("longValue", Number.POSITIVE_INFINITY);
        let result3 = await rdbStore.query(predicates3);
        expect(3).assertEqual(result3.rowCount);
        result3.close()
        result3 = null

        let predicates4 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates4.lessThanOrEqualTo("longValue", Number.MAX_VALUE);
        let result4 = await rdbStore.query(predicates4);
        expect(3).assertEqual(result4.rowCount);
        result4.close()
        result4 = null

        let predicates5 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates5.lessThanOrEqualTo("longValue", Number.MIN_VALUE);
        let result5 = await rdbStore.query(predicates5);
        expect(1).assertEqual(result5.rowCount);
        result5.close()
        result5 = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0090
     * @tc.name Normal test case of predicates, test "between" for string value
     * @tc.desc 1.Execute between ("stringValue", "ABB", "ABD")
     *          2.Query data
     */
    it('testBetween0001', 0, async function (done) {
        console.log(TAG + "************* testBetween0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.between("stringValue", "ABB", "ABD");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0091
     * @tc.name Normal test case of predicates, test "between" for double value
     * @tc.desc 1.Execute between ("doubleValue", 0.0, DOUBLE_MAX)
     *          2.Query data
     */
    it('testBetween0002', 0, async function (done) {
        console.log(TAG + "************* testBetween0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.between("doubleValue", 0.0, DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0092
     * @tc.name Normal test case of predicates, test "between" for integer value
     * @tc.desc 1.Execute between ("integerValue", 0, 1)
     *          2.Query data
     */
    it('testBetween0003', 0, async function (done) {
        console.log(TAG + "************* testBetween0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.between("integerValue", 0, 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0093
     * @tc.name Normal test case of predicates, test "between" for long value
     * @tc.desc 1.Execute between ("longValue", 0, 2)
     *          2.Query data
     */
    it('testBetween0004', 0, async function (done) {
        console.log(TAG + "************* testBetween0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.between("longValue", 0, 2);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0094
     * @tc.name Normal test case of predicates, test "between" for string value
     * @tc.desc 1.Execute between ("stringValue", "ABB", "ABB")
     *          2.Query data
     */
    it('testBetween0005', 0, async function (done) {
        console.log(TAG + "************* testBetween0005 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.between("stringValue", "ABB", "ABB");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0095
     * @tc.name Normal test case of predicates, test "between" for boundary value of doubleValue
     * @tc.desc 1.Execute between ("doubleValue", DOUBLE_MAX, DOUBLE_MAX)
     *          2.Query data
     */
    it('testBetween0006', 0, async function (done) {
        console.log(TAG + "************* testBetween0006 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.between("doubleValue", DOUBLE_MAX, DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0096
     * @tc.name Normal test case of predicates, test "between" for integer value
     * @tc.desc 1.Execute between ("integerValue", 1, 0)
     *          2.Query data
     */
    it('testBetween0007', 0, async function (done) {
        console.log(TAG + "************* testBetween0007 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.between("integerValue", 1, 0);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0007 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0097
     * @tc.name Normal test case of predicates, test "between" for long value
     * @tc.desc 1.Execute between ("longValue", 2, -1)
     *          2.Query data
     */
    it('testBetween0008', 0, async function (done) {
        console.log(TAG + "************* testBetween0008 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.between("longValue", 2, -1);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0008 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0098
     * @tc.name  Normal test case of predicates, test "between" for boundary value of longValue
     * @tc.desc 1.Execute between ("longValue", 0, Number.POSITIVE_INFINITY)
     *          2.Execute between ("longValue", Number.NEGATIVE_INFINITY, 0)
     *          3.Execute between ("longValue", Number.NaN, 0)
     *          4.Execute between ("longValue", 0, Number.NaN)
     *          5.Execute between ("longValue", Number.MIN_VALUE, 0)
     */
    it('testBetween0009', 0, async function (done) {
        console.log(TAG + "************* testBetween0009 start *************");

        let predicates1 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates1.between("longValue", 0, Number.POSITIVE_INFINITY);
        let result1 = await rdbStore.query(predicates1);
        expect(2).assertEqual(result1.rowCount);
        result1.close();
        result1 = null

        let predicates2 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates2.between("longValue", Number.NEGATIVE_INFINITY, 0);
        let result2 = await rdbStore.query(predicates2);
        expect(1).assertEqual(result2.rowCount);
        result2.close();
        result2 = null

        let predicates3 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates3.between("longValue", Number.NaN, 0);
        let result3 = await rdbStore.query(predicates3);
        expect(0).assertEqual(result3.rowCount);
        result3.close();
        result3 = null

        let predicates4 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates4.between("longValue", 0, Number.NaN);
        let result4 = await rdbStore.query(predicates4);
        expect(0).assertEqual(result4.rowCount);
        result4.close();
        result4 = null

        let predicates5 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates5.between("longValue", Number.MIN_VALUE, 0);
        let result5 = await rdbStore.query(predicates5);
        expect(0).assertEqual(result5.rowCount);
        result5.close();
        result5 = null

        let predicates6 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates6.between("longValue", 0, Number.MAX_VALUE);
        let result6 = await rdbStore.query(predicates6);
        expect(2).assertEqual(result6.rowCount);
        result6.close();
        result6 = null

        done();
        console.log(TAG + "************* testBetween0009 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0100
     * @tc.name Normal test case of predicates, test "notBetween" for string value
     * @tc.desc 1.Execute notBetween ("stringValue", "ABB", "ABD")
     *          2.Query data
     */
    it('testNotBetween0001', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notBetween("stringValue", "ABB", "ABD");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0101
     * @tc.name Normal test case of predicates, test "notBetween" for double value
     * @tc.desc 1.Execute notBetween ("doubleValue", 0.0, DOUBLE_MAX)
     *          2.Query data
     */
    it('testNotBetween0002', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notBetween("doubleValue", 0.0, DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0102
     * @tc.name Normal test case of predicates, test "notBetween" for integer value
     * @tc.desc 1.Execute notBetween ("integerValue", 0, 1)
     *          2.Query data
     */
    it('testNotBetween0003', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notBetween("integerValue", 0, 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0103
     * @tc.name Normal test case of predicates, test "notBetween" for long value
     * @tc.desc 1.Execute notBetween ("longValue", 0, 2)
     *          2.Query data
     */
    it('testNotBetween0004', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notBetween("longValue", 0, 2);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0104
     * @tc.name Normal test case of predicates, test "notBetween" for boundary value of longValue
     * @tc.desc 1.Execute notBetween ("longValue", 0, Number.NaN)
     *          2.Execute notBetween ("longValue", Number.NaN, 0)
     *          3.Execute notBetween ("longValue", Number.MIN_VALUE, 0)
     *          4.Execute notBetween ("longValue", 0, Number.MAX_VALUE)
     *          5.Execute notBetween ("longValue", Number.NEGATIVE_INFINITY, 0)
     *          6.Execute notBetween ("longValue", 0, Number.POSITIVE_INFINITY)
     */
    it('testNotBetween0005', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0005 start *************");

        let predicates1 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates1.notBetween("longValue", 0, Number.NaN);
        let result = await rdbStore.query(predicates1);
        expect(1).assertEqual(result.rowCount);
        result.close();

        let predicates2 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates2.notBetween("longValue", Number.NaN, 0);
        result = await rdbStore.query(predicates2);
        expect(2).assertEqual(result.rowCount);
        result.close();

        let predicates3 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates3.notBetween("longValue", Number.MIN_VALUE, 0);
        result = await rdbStore.query(predicates3);
        expect(3).assertEqual(result.rowCount);
        result.close();

        let predicates4 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates4.notBetween("longValue", 0, Number.MAX_VALUE);
        result = await rdbStore.query(predicates4);
        expect(1).assertEqual(result.rowCount);
        result.close();

        let predicates5 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates5.notBetween("longValue", Number.NEGATIVE_INFINITY, 0);
        result = await rdbStore.query(predicates5);
        expect(2).assertEqual(result.rowCount);
        result.close();

        let predicates6 = new data_relationalStore.RdbPredicates("AllDataType");
        predicates6.notBetween("longValue", 0, Number.POSITIVE_INFINITY);
        result = await rdbStore.query(predicates6);
        expect(1).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0110
     * @tc.name Normal test case of predicates, test "glob" for string value
     * @tc.desc 1.Execute glob ("stringValue", "ABC*")
     *          2.Query data
     */
    it('testGlob0001', 0, async function (done) {
        console.log(TAG + "************* testGlob0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "ABC*");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0111
     * @tc.name Normal test case of predicates, test "glob" for string value
     * @tc.desc 1.Execute glob ("stringValue", "*LMN")
     *          2.Query data
     */
    it('testGlob0002', 0, async function (done) {
        console.log(TAG + "************* testGlob0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "*LMN");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0112
     * @tc.name Normal test case of predicates, test "glob" for string value
     * @tc.desc 1.Execute glob ("stringValue", "ABCDEFGHIJKLM?")
     *          2.Query data
     */
    it('testGlob0003', 0, async function (done) {
        console.log(TAG + "************* testGlob0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "ABCDEFGHIJKLM?");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0113
     * @tc.name Normal test case of predicates, test "glob" for string value
     * @tc.desc 1.Execute glob ("stringValue", "?BCDEFGHIJKLMN")
     *          2.Query data
     */
    it('testGlob0004', 0, async function (done) {
        console.log(TAG + "************* testGlob0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "?BCDEFGHIJKLMN");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0114
     * @tc.name Normal test case of predicates, test "glob" for string value
     * @tc.desc 1.Execute glob ("stringValue", "*FGHI*")
     *          2.Query data
     */
    it('testGlob0005', 0, async function (done) {
        console.log(TAG + "************* testGlob0005 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "*FGHI*");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0115
     * @tc.name Normal test case of predicates, test "glob" for string value
     * @tc.desc 1.Execute glob ("stringValue", "?BCDEFGHIJKLM?")
     *          2.Query data
     */
    it('testGlob0006', 0, async function (done) {
        console.log(TAG + "************* testGlob0006 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "?BCDEFGHIJKLM?");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0120
     * @tc.name Normal test case of predicates, test "contains" for string value
     * @tc.desc 1.Execute contains ("stringValue", "DEF")
     *          2.Query data
     */
    it('testContains0001', 0, async function (done) {
        console.log(TAG + "************* testContains0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.contains("stringValue", "DEF");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testContains0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0121
     * @tc.name Normal test case of predicates, test "contains" for string value
     * @tc.desc 1.Execute contains ("stringValue", "DEFX")
     *          2.Query data
     */
    it('testContains0002', 0, async function (done) {
        console.log(TAG + "************* testContains0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.contains("stringValue", "DEFX");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testContains0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0122
     * @tc.name Normal test case of predicates, test "contains" for  Chinese character value
     * @tc.desc 1.Execute contains ("characterValue", "中")
     *          2.Query data
     */
    it('testContains0003', 0, async function (done) {
        console.log(TAG + "************* testContains0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.contains("characterValue", "中");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testContains0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0123
     * @tc.name Normal test case of predicates, test "contains" for character value
     * @tc.desc 1.Execute contains ("characterValue", "#")
     *          2.Query data
     */
    it('testContains0004', 0, async function (done) {
        console.log(TAG + "************* testContains0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.contains("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testContains0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0124
     * @tc.name Abnormal test case of predicates, test "contains" for character value
     * @tc.desc 1.Execute contains ("characterValue", null)
     *          2.Query data
     *          3.Execute contains ("characterValue", undefined)
     *          4.Query data
     */
    it('testContains0005', 0, async function (done) {
        console.info(TAG, `************* testContains0005 start *************`);
        try {
            let predicates = new data_relationalStore.RdbPredicates("AllDataType");
            predicates.contains("characterValue", null);
            expect(null).assertFail();
            done();
        } catch (err) {
            console.error(TAG, `predicates.contains failed: err code=${err.code}, message=${err.message}`);
            expect("401").assertEqual(err.code);
        }

        try {
            let predicates = new data_relationalStore.RdbPredicates("AllDataType");
            predicates.contains("characterValue", undefined);
            expect(null).assertFail();
            done();
        } catch (err) {
            console.error(TAG, `predicates.contains failed: err code=${err.code}, message=${err.message}`);
            expect("401").assertEqual(err.code);
            done();
        }
        console.info(TAG, `************* testContains0005 end *************`);
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0130
     * @tc.name Normal test case of predicates, test "beginsWith" for character value
     * @tc.desc 1.Execute beginsWith ("stringValue", "ABC")
     *          2.Query data
     */
    it('testBeginsWith0001', 0, async function (done) {
        console.log(TAG + "************* testBeginsWith0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.beginsWith("stringValue", "ABC");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testBeginsWith0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0131
     * @tc.name Normal test case of predicates, test "beginsWith" for character value
     * @tc.desc 1.Execute beginsWith ("stringValue", "ABCX")
     *          2.Query data
     */
    it('testBeginsWith0002', 0, async function (done) {
        console.log(TAG + "************* testBeginsWith0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.beginsWith("stringValue", "ABCX");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testBeginsWith0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0132
     * @tc.name Normal test case of predicates, test "beginsWith" for Chinese character value
     * @tc.desc 1.Execute beginsWith ("characterValue", "中")
     *          2.Query data
     */
    it('testBeginsWith0003', 0, async function (done) {
        console.log(TAG + "************* testBeginsWith0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.beginsWith("characterValue", "中");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testBeginsWith0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0133
     * @tc.name Normal test case of predicates, test "beginsWith" for character value
     * @tc.desc 1.Execute beginsWith ("characterValue", "#")
     *          2.Query data
     */
    it('testBeginsWith0004', 0, async function (done) {
        console.log(TAG + "************* testBeginsWith0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.beginsWith("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testBeginsWith0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0140
     * @tc.name Normal test case of predicates, test "endsWith" for string value
     * @tc.desc 1.Execute endsWith ("stringValue", "LMN")
     *          2.Query data
     */
    it('testEndsWith0001', 0, async function (done) {
        console.log(TAG + "************* testEndsWith0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.endsWith("stringValue", "LMN");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testEndsWith0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0141
     * @tc.name Normal test case of predicates, test "endsWith" for string value
     * @tc.desc 1.Execute endsWith ("stringValue", "LMNX")
     *          2.Query data
     */
    it('testEndsWith0002', 0, async function (done) {
        console.log(TAG + "************* testEndsWith0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.endsWith("stringValue", "LMNX");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testEndsWith0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0142
     * @tc.name Normal test case of predicates, test "endsWith" for Chinese character value
     * @tc.desc 1.Execute endsWith ("characterValue", "中")
     *          2.Query data
     */
    it('testEndsWith0003', 0, async function (done) {
        console.log(TAG + "************* testEndsWith0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.endsWith("characterValue", "中");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testEndsWith0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0143
     * @tc.name Normal test case of predicates, test "endsWith" for character value
     * @tc.desc 1.Execute endsWith ("characterValue", "#")
     *          2.Query data
     */
    it('testEndsWith0004', 0, async function (done) {
        console.log(TAG + "************* testEndsWith0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.endsWith("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testEndsWith0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0150
     * @tc.name Normal test case of predicates, test "like" for string value
     * @tc.desc 1.Execute like ("stringValue", "%LMN%")
     *          2.Query data
     */
    it('testLike0001', 0, async function (done) {
        console.log(TAG + "************* testLike0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "%LMN%");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLike0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0151
     * @tc.name Normal test case of predicates, test "like" for string value
     * @tc.desc 1.Execute like ("stringValue", "%LMNX%")
     *          2.Query data
     */
    it('testLike0002', 0, async function (done) {
        console.log(TAG + "************* testLike0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "%LMNX%");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLike0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0152
     * @tc.name Normal test case of predicates, test "like" for Chinese character value
     * @tc.desc 1.Execute like ("characterValue", "%中%")
     *          2.Query data
     */
    it('testLike0003', 0, async function (done) {
        console.log(TAG + "************* testLike0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("characterValue", "%中%");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLike0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0153
     * @tc.name Normal test case of predicates, test "like" for character value
     * @tc.desc 1.Execute like ("characterValue", "%#%")
     *          2.Query data
     */
    it('testLike0004', 0, async function (done) {
        console.log(TAG + "************* testLike0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("characterValue", "%#%");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLike0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0154
     * @tc.name Abnormal test case of predicates, test "like" for character value
     * @tc.desc 1.Execute like ("characterValue", null)
     *          2.Query data
     *          3.Execute like ("characterValue", undefined)
     *          4.Query data
     */
    it('testLike0005', 0, async function (done) {
        console.info(TAG, `************* testLike0005 start *************`);
        try {
            let predicates = new data_relationalStore.RdbPredicates("AllDataType");
            predicates.like("characterValue", null);
            expect(null).assertFail();
            done();
        } catch (err) {
            console.error(TAG, `predicates.like failed: err code=${err.code}, message=${err.message}`);
            expect("401").assertEqual(err.code);
        }

        try {
            let predicates = new data_relationalStore.RdbPredicates("AllDataType");
            predicates.like("characterValue", undefined);
            expect(null).assertEqual();
            done();
        } catch (err) {
            console.error(TAG, `predicates.like failed: err code=${err.code}, message=${err.message}`);
            expect("401").assertEqual(err.code);
            done();
        }
        console.info(TAG, `************* testLike0005 end *************`);
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0160
     * @tc.name Normal test case of predicates, test "beginWrap"
     * @tc.desc 1.Execute equalTo().beginWrap().equalTo().or().equalTo().endWrap()
     *          2.Query data
     */
    it('testBeginWrap0001', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
            .beginWrap()
            .equalTo("integerValue", 1)
            .or()
            .equalTo("integerValue", 2147483647)
            .endWrap();
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBeginWrap0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0161
     * @tc.name Normal test case of predicates, test "beginWrap"
     * @tc.desc 1.Execute equalTo().beginWrap().equalTo().endWrap()
     *          2.Query data
     */
    it('testBeginWrap0002', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
            .beginWrap()
            .equalTo("characterValue", ' ')
            .endWrap();
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBeginWrap0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0162
     * @tc.name Normal test case of predicates, test "beginWrap"
     * @tc.desc 1.Execute equalTo().beginWrap().equalTo().endWrap()
     *          2.Query data
     */
    it('testBeginWrap0003', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
            .beginWrap()
            .equalTo("characterValue", '中')
            .endWrap();
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null

        done();
        console.log(TAG + "************* testBeginWrap0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0163
     * @tc.name Abnormal test case of predicates, test "beginWrap" without "beginWrap"
     * @tc.desc 1.Execute equalTo().equalTo().endWrap()
     *          2.Query data
     */
    it('testBeginWrap0004', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
            .equalTo("characterValue", '中')
            .endWrap();
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBeginWrap0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0164
     * @tc.name Abnormal test case of predicates, test "beginWrap" without "endWrap"
     * @tc.desc 1.Execute equalTo().beginWrap().equalTo()
     *          2.Query data
     */
    it('testBeginWrap0005', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0005 start *************");
        {
            let predicates = new data_relationalStore.RdbPredicates("AllDataType");
            predicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
                .beginWrap()
                .equalTo("characterValue", '中');
            let result = await rdbStore.query(predicates);
            expect(-1).assertEqual(result.rowCount);
            result.close()
            result = null
        }
        done();
        console.log(TAG + "************* testBeginWrap0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0170
     * @tc.name Normal test case of predicates, test "and"
     * @tc.desc 1.Execute equalTo().and().equalTo()
     *          2.Query data
     */
    it('testAnd0001', 0, async function (done) {
        console.log(TAG + "************* testAnd0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
            .and()
            .equalTo("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testAnd0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0171
     * @tc.name Normal test case of predicates, test "and"
     * @tc.desc 1.Execute equalTo().beginWrap().equalTo().or().equalTo().endWrap()
     *          2.Query data
     */
    it('testAnd0002', 0, async function (done) {
        console.log(TAG + "************* testAnd0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
            .beginWrap()
            .equalTo("integerValue", 1)
            .or()
            .equalTo("integerValue", 2147483647)
            .endWrap();
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testAnd0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0172
     * @tc.name Abnormal test case of predicates, test "and"
     * @tc.desc 1.Execute equalTo().or().and().equalTo()
     *          2.Query data
     */
    it('testAnd0003', 0, async function (done) {
        console.log(TAG + "************* testAnd0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN").or().and().equalTo("integerValue", 1);
        console.log(TAG + "you should not start a request" + " with \"and\" or use or() before this function");

        done();
        console.log(TAG + "************* testAnd0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0180
     * @tc.name Normal test case of predicates, test "orderByAsc" for integer value
     * @tc.desc 1.Execute orderByAsc ("integerValue")
     *          2.Query data
     */
    it('testOrder0001', 0, async function (done) {
        console.log(TAG + "************* testOrder0001 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByAsc("integerValue").distinct();
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        expect(true).assertEqual(result.goToFirstRow())
        expect(3).assertEqual(result.getLong(0));
        expect(true).assertEqual(result.goToNextRow())
        expect(2).assertEqual(result.getLong(0));
        expect(true).assertEqual(result.goToNextRow())
        expect(1).assertEqual(result.getLong(0));
        result.close() 
        result = null

        done();
        console.log(TAG + "************* testOrder0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0181
     * @tc.name Normal test case of predicates, test "orderByDesc" for integer value
     * @tc.desc 1.Execute orderByDesc ("integerValue")
     *          2.Query data
     */
    it('testOrder0002', 0, async function (done) {
        console.log(TAG + "************* testOrder0002 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByDesc("integerValue").distinct();
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        expect(true).assertEqual(result.goToFirstRow())
        expect(1).assertEqual(result.getLong(0));
        expect(true).assertEqual(result.goToNextRow())
        expect(2).assertEqual(result.getLong(0));
        expect(true).assertEqual(result.goToNextRow())
        expect(3).assertEqual(result.getLong(0));
        result.close()
        result = null

        done();
        console.log(TAG + "************* testOrder0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0182
     * @tc.name Abnormal test case of predicates, test "orderByDesc" for invalid param
     * @tc.desc 1.Execute orderByDesc ("integerValueX")
     *          2.Query data
     */
    it('testOrder0003', 0, async function (done) {
        console.log(TAG + "************* testOrder0003 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByDesc("integerValueX").distinct();
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testOrder0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0183
     * @tc.name Abnormal test case of predicates, test "orderByAsc" for invalid param
     * @tc.desc 1.Execute orderByAsc ("integerValueX")
     *          2.Query data
     */
    it('testOrder0004', 0, async function (done) {
        console.log(TAG + "************* testOrder0004 start *************");

        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByAsc("integerValueX").distinct();
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testOrder0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0190
     * @tc.name Normal test case of predicates, test "limitAs" '1'
     * @tc.desc 1.Execute limitAs
     *          2.Query data
     */
    it('testLimit0001', 0, async function (done) {
        console.log(TAG + "************* testLimit0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0191
     * @tc.name Normal test case of predicates, test "limitAs" '3'
     * @tc.desc 1.Execute limitAs
     *          2.Query data
     */
    it('testLimit0002', 0, async function (done) {
        console.log(TAG + "************* testLimit0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0192
     * @tc.name Normal test case of predicates, test "limitAs" "100"
     * @tc.desc 1.Execute limitAs
     *          2.Query data
     */
    it('testLimit0003', 0, async function (done) {
        console.log(TAG + "************* testLimit0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(100);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0193
     * @tc.name Normal test case of predicates, test "limitAs" for Chinese value
     * @tc.desc 1.Execute limitAs
     *          2.Query data
     */
    it('testLimit0004', 0, async function (done) {
        console.log(TAG + "************* testLimit0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "中").limitAs(1);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0194
     * @tc.name Normal test case of predicates, test "limitAs" '0'
     * @tc.desc 1.Execute limitAs
     *          2.Query data
     */
    it('testLimit0005', 0, async function (done) {
        console.log(TAG + "************* testLimit0005 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(0);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0195
     * @tc.name Normal test case of predicates, test "limitAs" "-1"
     * @tc.desc 1.Execute limitAs
     *          2.Query data
     */
    it('testLimit0006', 0, async function (done) {
        console.log(TAG + "************* testLimit0006 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(-1);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0196
     * @tc.name Normal test case of predicates, test "limitAs"
     * @tc.desc 1.Execute limitAs (-1)
     *          2.Execute limitAs (1, 1))
     *          3.Execute limitAs (0, -1)
     *          4.Execute like ("stringValue", "ABCDEFGHIJKLMN")
     *          5.Execute orderByAsc ("id")
     *          6.Execute limitAs (-1, -1)
     */
    it('testLimit0007', 0, async function (done) {
        console.log(TAG + "************* testLimit0007 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.limitAs(-1);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        predicates.clear();

        predicates.limitAs(1, 1);
        result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        predicates.clear();

        predicates.limitAs(0, -1);
        result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        predicates.clear();

        predicates.like("stringValue", "ABCDEFGHIJKLMN")
        predicates.orderByAsc("id");
        predicates.limitAs(-1, -1);
        result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        expect(" WHERE stringValue LIKE ?  ORDER BY id ASC  LIMIT -1 OFFSET -1").assertEqual(predicates.statement);
        expect("ABCDEFGHIJKLMN").assertEqual(predicates.bindArgs[0]);
        expect(true).assertEqual(result.goToFirstRow())
        expect(1).assertEqual(result.getLong(0));
        expect(2147483647).assertEqual(result.getLong(1));
        expect(DOUBLE_MAX).assertEqual(result.getDouble(2));
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0007 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0200
     * @tc.name Normal test case of predicates, test "offsetAs" '1'
     * @tc.desc 1.Execute offsetAs
     *          2.Query data
     */
    it('testOffset0001', 0, async function (done) {
        console.log(TAG + "************* testOffset0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testOffset0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0201
     * @tc.name Normal test case of predicates, test "offsetAs" '0'
     * @tc.desc 1.Execute offsetAs
     *          2.Query data
     */
    it('testOffset0002', 0, async function (done) {
        console.log(TAG + "************* testOffset0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(0);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testOffset0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0202
     * @tc.name Normal test case of predicates, test "offsetAs" '5'
     * @tc.desc 1.Execute offsetAs
     *          2.Query data
     */
    it('testOffset0003', 0, async function (done) {
        console.log(TAG + "************* testOffset0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(5);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testOffset0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0203
     * @tc.name Normal test case of predicates, test "offsetAs" "-1"
     * @tc.desc 1.Execute offsetAs
     *          2.Query data
     */
    it('testOffset0004', 0, async function (done) {
        console.log(TAG + "************* testOffset0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(-1);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testOffset0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0210
     * @tc.name Normal test case of predicates, test "in" for boundary value of doubleValue
     * @tc.desc 1.Execute in ("doubleValue", Number.MIN_VALUE.toString())
     *          2.Query data
     */
    it('testIn0001', 0, async function (done) {
        console.log(TAG + "************* testIn0001 start *************");
        var values = [Number.MIN_VALUE.toString()];
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.in("doubleValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testIn0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0211
     * @tc.name Normal test case of predicates, test "in" for doubleValue
     * @tc.desc 1.Execute in ("doubleValue", "1.0")
     *          2.Query data
     */
    it('testIn0002', 0, async function (done) {
        console.log(TAG + "************* testIn0002 start *************");
        var values = ["1.0"];
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.in("doubleValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testIn0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0212
     * @tc.name Normal test case of predicates, test "in" for boundary value of doubleValue
     * @tc.desc 1.Execute in ("doubleValue", DOUBLE_MAX.toString())
     *          2.Query data
     */
    it('testIn0003', 0, async function (done) {
        console.log(TAG + "************* testIn0003 start *************");
        var values = [DOUBLE_MAX.toString()];
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.in("doubleValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testIn0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0213
     * @tc.desc Normal test case of predicates, test "in" for boundary value of doubleValue
     * @tc.desc 1.Execute in ("doubleValue", Number.MIN_VALUE.toString(), "1.0", DOUBLE_MAX.toString())
     *          2.Query data
     */
    it('testIn0004', 0, async function (done) {
        console.log(TAG + "************* testIn0004 start *************");
        var values = [Number.MIN_VALUE.toString(), "1.0", DOUBLE_MAX.toString()];
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.in("doubleValue", values);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testIn0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0220
     * @tc.name Normal test case of predicates, test "notIn" for boundary value of integerValue
     * @tc.desc 1.Execute notIn ("integerValue", [1, -2147483648])
     *          2.Query data
     */
    it('testNotIn0001', 0, async function (done) {
        console.log(TAG + "************* testNotIn0001 start *************");
        var values = [1, -2147483648];
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notIn("integerValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testNotIn0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0221
     * @tc.name Normal test case of predicates, test "notIn" for boundary value of integerValue
     * @tc.desc 1.Execute notIn ("integerValue", [1, 2147483647])
     *          2.Query data
     */
    it('testNotIn0002', 0, async function (done) {
        console.log(TAG + "************* testNotIn0002 start *************");
        let values = [1, 2147483647];
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notIn("integerValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testNotIn0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0222
     * @tc.name Normal test case of predicates, test "notIn" for boundary value of integerValue
     * @tc.desc 1.Execute notIn ("integerValue", [-2147483648, 2147483647])
     *          2.Query data
     */
    it('testNotIn0003', 0, async function (done) {
        console.log(TAG + "************* testNotIn0003 start *************");
        var values = [-2147483648, 2147483647];
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notIn("integerValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testNotIn0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0230
     * @tc.name Normal test case of predicates, test "RdbPredicates"
     * @tc.desc 1.Execute RdbPredicates ("AllDataType")
     *          2.Query data
     */
    it('testCreate0001', 0, async function (done) {
        console.log(TAG + "************* testCreate0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testCreate0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0231
     * @tc.name Abnormal test case of predicates, test "RdbPredicates" for creat new table
     * @tc.desc 1.Execute RdbPredicates ("test")
     *          2.Query data
     */
    it('testCreate0002', 0, async function (done) {
        console.log(TAG + "************* testCreate0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("test");
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testCreate0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0240
     * @tc.name Normal test case of predicates, test "groupBy" for character value
     * @tc.desc 1.Execute groupBy (["characterValue"])
     *          2.Query data
     */
    it('testGroupBy0001', 0, async function (done) {
        console.log(TAG + "************* testGroupBy0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").groupBy(["characterValue"]);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testGroupBy0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0241
     * @tc.name Abnormal test case of predicates, test "groupBy" for invalid param
     * @tc.desc 1.Execute groupBy (["characterValueX"])
     *          2.Query data
     */
    it('testGroupBy0002', 0, async function (done) {
        console.log(TAG + "************* testGroupBy0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").groupBy(["characterValueX"]);
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testGroupBy0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0250
     * @tc.name Abnormal test case of predicates, test "indexedBy" for character value
     * @tc.desc 1.Execute indexedBy ("characterValue")
     *          2.Query data
     */
    it('testIndexedBy0001', 0, async function (done) {
        console.log(TAG + "************* testIndexedBy0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").indexedBy("characterValue");
        let result = await rdbStore.query(predicates);
        //test table have no indexe column, so return -1
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIndexedBy0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0251
     * @tc.name Abnormal test case of predicates, test "indexedBy" for invalid param
     * @tc.desc 1.Execute indexedBy (["characterValueX"])
     *          2.Query data
     */
    it('testIndexedBy0002', 0, async function (done) {
        console.log(TAG + "************* testIndexedBy0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        try {
            predicates.like("stringValue", "ABCDEFGHIJKLMN").indexedBy(["characterValueX"]);
            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result.close()
            result = null
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
        }
        done();
        console.log(TAG + "************* testIndexedBy0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0260
     * @tc.name Abnormal test case of predicates, call system api
     * @tc.desc 1.Configure predicates
     *          2.Query data
     */
    it('testQueryPermissionDenied0001', 0, async function (done) {
        console.log(TAG + "************* testQueryPermissionDenied0001 start *************");
        try {
            var predicate = new dataSharePredicates.DataSharePredicates();
            await rdbStore.query("test", predicate);
            expect(null).assertFail();
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("202").assertEqual(err.code)
            done()
        }
        console.log(TAG + "************* testQueryPermissionDenied0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0261
     * @tc.name Normal test case of predicates, test "notLike" for string value
     * @tc.desc 1.Execute notLike ("stringValue", "ABCDEFGHIJKLMN")
     *          2.Query data
     */
    it('testNotLike0001', 0, async function (done) {
        console.log(TAG + "************* testNotLike0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notLike("stringValue", "ABCDEFGHIJKLMN");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testNotLike0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0262
     * @tc.name Normal test case of predicates, test "notLike" for string value
     * @tc.desc 1.Execute notLike ("stringValue", "LMNX")
     *          2.Query data
     */
    it('testNotLike0002', 0, async function (done) {
        console.log(TAG + "************* testNotLike0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notLike("stringValue", "LMNX");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testNotLike0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0263
     * @tc.name Normal test case of predicates, test "notLike" for Chinese character value
     * @tc.desc 1.Execute notLike ("characterValue", "%中%")
     *          2.Query data
     */
    it('testNotLike0003', 0, async function (done) {
        console.log(TAG + "************* testNotLike0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notLike("characterValue", "%中%");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testNotLike0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0264
     * @tc.name Normal test case of predicates, test "notLike" for character value
     * @tc.desc 1.Execute notLike ("characterValue", "#")
     *          2.Query data
     */
    it('testNotLike0004', 0, async function (done) {
        console.log(TAG + "************* testNotLike0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notLike("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testNotLike0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0265
     * @tc.name Abnormal test case of predicates, test "notLike" for character value
     * @tc.desc 1.Execute notLike ("characterValue", null)
     *          2.Query data
     *          3.Execute notLike ("characterValue", undefined)
     *          4.Query data
     */
    it('testNotLike0005', 0, async function (done) {
        console.info(TAG, `************* testNotLike0005 start *************`);
        try {
            let predicates = new data_relationalStore.RdbPredicates("AllDataType");
            predicates.notLike("characterValue", null);
            expect(null).assertFail();
            done();
        } catch (err) {
            console.error(TAG, `predicates.notLike failed: err code=${err.code}, message=${err.message}`);
            expect("401").assertEqual(err.code);
        }

        try {
            let predicates = new data_relationalStore.RdbPredicates("AllDataType");
            predicates.notLike("characterValue", undefined);
            expect(null).assertEqual();
            done();
        } catch (err) {
            console.error(TAG, `predicates.notLike failed: err code=${err.code}, message=${err.message}`);
            expect("401").assertEqual(err.code);
            done();
        }
        console.info(TAG, `************* testNotLike0005 end *************`);
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0266
     * @tc.name Normal test case of predicates, test "notLike" for character value
     * @tc.desc 1.Execute notLike ("characterValue", "#")
     *          2.Query data
     *          3.close result
     *          4.insert data
     *          5.Execute notLike ("characterValue", "#")
     *          6.Query data
     */
    it('testNotLike0006', 0, async function (done) {
        console.log(TAG + "************* testNotLike0006 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notLike("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "integerValue": -2147483648,
            "doubleValue": Number.MIN_VALUE,
            "booleanValue": false,
            "floatValue": 0.1234567,
            "longValue": -9223372036854775808,
            "shortValue": -32768,
            "characterValue": '#',
            "stringValue": "OPQRST",
            "blobValue": u8,
            "byteValue": -128,
        }
        await rdbStore.insert("AllDataType", valueBucket)
        let predicatesInsert = new data_relationalStore.RdbPredicates("AllDataType");
        predicatesInsert.notLike("characterValue", "#");
        result = await rdbStore.query(predicatesInsert);
        expect(2).assertEqual(result.rowCount);
        result.close();
        result = null;
        let predicatesBefore = new data_relationalStore.RdbPredicates("AllDataType");
        predicatesBefore.equalTo("stringValue", "OPQRST");
        await rdbStore.delete(predicatesBefore);
        done();
        console.log(TAG + "************* testNotLike0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0267
     * @tc.name Normal test case of predicates, test "notLike" for character value
     * @tc.desc 1.Execute notLike ("characterValue", "#")
     *          2.Query data
     *          3.close result
     *          4.updata data
     *          5.Execute notLike ("characterValue", "#")
     *          6.Query data
     */
    it('testNotLike0007', 0, async function (done) {
        console.log(TAG + "************* testNotLike0007 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notLike("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "integerValue": -2147483648,
            "doubleValue": Number.MIN_VALUE,
            "booleanValue": false,
            "floatValue": 0.1234567,
            "longValue": -9223372036854775808,
            "shortValue": -32768,
            "characterValue": '#',
            "stringValue": "OPQRST",
            "blobValue": u8,
            "byteValue": -128,
        }
        predicates.equalTo("characterValue", "中");
        await rdbStore.update(valueBucket, predicates);
        let predicatesUpdate = new data_relationalStore.RdbPredicates("AllDataType");
        predicatesUpdate.notLike("characterValue", "#");
        result = await rdbStore.query(predicatesUpdate);
        expect(1).assertEqual(result.rowCount);
        const valueBucketBefore = {
            "integerValue": 1,
            "doubleValue": 1.0,
            "booleanValue": false,
            "floatValue": 1.0,
            "longValue": 1,
            "shortValue": 1,
            "characterValue": '中',
            "stringValue": "ABCDEFGHIJKLMN",
            "blobValue": u8,
            "byteValue": 1,
        }
        result.close();
        result = null;
        let predicatesBefore = new data_relationalStore.RdbPredicates("AllDataType");
        predicatesBefore.equalTo("stringValue", "OPQRST");
        await rdbStore.update(valueBucketBefore, predicatesBefore);
        done();
        console.log(TAG + "************* testNotLike0007 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0268
     * @tc.name Normal test case of predicates, test "notLike" for character value
     * @tc.desc 1.Execute notLike ("characterValue", "#")
     *          2.Query data
     *          3.close result
     *          4.delete data
     *          5.Execute notLike ("characterValue", "#")
     *          6.Query data
     */
    it('testNotLike0008', 0, async function (done) {
        console.log(TAG + "************* testNotLike0008 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notLike("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close();
        result = null;
        predicates.equalTo("characterValue", "中");
        await rdbStore.delete(predicates);
        let predicatesDelete = new data_relationalStore.RdbPredicates("AllDataType");
        predicatesDelete.notLike("characterValue", "#");
        result = await rdbStore.query(predicatesDelete);
        expect(1).assertEqual(result.rowCount);
        result.close();
        result = null;
        var u8 = new Uint8Array([1, 2, 3]);
        const valueBucketBefore = {
            "integerValue": 1,
            "doubleValue": 1.0,
            "booleanValue": false,
            "floatValue": 1.0,
            "longValue": 1,
            "shortValue": 1,
            "characterValue": '中',
            "stringValue": "ABCDEFGHIJKLMN",
            "blobValue": u8,
            "byteValue": 1,
        }
        await rdbStore.insert("AllDataType", valueBucketBefore);
        done();
        console.log(TAG + "************* testNotLike0008 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0269
     * @tc.name Normal test case of predicates, test "notContains" for string value
     * @tc.desc 1.Execute notContains ("stringValue", "ABC")
     *          2.Query data
     */
    it('testNotContains0001', 0, async function (done) {
        console.log(TAG + "************* testNotContains0001 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notContains("stringValue", "ABC");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testNotContains0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0270
     * @tc.name Normal test case of predicates, test "notContains" for string value
     * @tc.desc 1.Execute notContains ("stringValue", "ABCX")
     *          2.Query data
     */
    it('testNotContains0002', 0, async function (done) {
        console.log(TAG + "************* testNotContains0002 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notContains("stringValue", "ABCX");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testNotContains0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0271
     * @tc.name Normal test case of predicates, test "notContains" for  Chinese character value
     * @tc.desc 1.Execute notContains ("characterValue", "中")
     *          2.Query data
     */
    it('testNotContains0003', 0, async function (done) {
        console.log(TAG + "************* testNotContains0003 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notContains("characterValue", "中");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testNotContains0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0272
     * @tc.name Normal test case of predicates, test "notContains" for character value
     * @tc.desc 1.Execute notContains ("characterValue", "#")
     *          2.Query data
     */
    it('testNotContains0004', 0, async function (done) {
        console.log(TAG + "************* testNotContains0004 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notContains("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testNotContains0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0273
     * @tc.name Abnormal test case of predicates, test "notContains" for character value
     * @tc.desc 1.Execute notContains ("characterValue", null)
     *          2.Query data
     *          3.Execute notContains ("characterValue", undefined)
     *          4.Query data
     */
    it('testNotContains0005', 0, async function (done) {
        console.info(TAG, `************* testNotContains0005 start *************`);
        try {
            let predicates = new data_relationalStore.RdbPredicates("AllDataType");
            predicates.notContains("characterValue", null);
            expect(null).assertFail();
            done();
        } catch (err) {
            console.error(TAG, `predicates.notContains failed: err code=${err.code}, message=${err.message}`);
            expect("401").assertEqual(err.code);
        }

        try {
            let predicates = new data_relationalStore.RdbPredicates("AllDataType");
            predicates.notContains("characterValue", undefined);
            expect(null).assertFail();
            done();
        } catch (err) {
            console.error(TAG, `predicates.notContains failed: err code=${err.code}, message=${err.message}`);
            expect("401").assertEqual(err.code);
            done();
        }
        console.info(TAG, `************* testNotContains0005 end *************`);
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0274
     * @tc.name Normal test case of predicates, test "notContains" for character value
     * @tc.desc 1.Execute notContains ("characterValue", "#")
     *          2.Query data
     *          3.close result
     *          4.insert data
     *          5.Execute notContains ("characterValue", "#")
     *          6.Query data
     */
    it('testNotContains0006', 0, async function (done) {
        console.log(TAG + "************* testNotContains0006 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notContains("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "integerValue": -2147483648,
            "doubleValue": Number.MIN_VALUE,
            "booleanValue": false,
            "floatValue": 0.1234567,
            "longValue": -9223372036854775808,
            "shortValue": -32768,
            "characterValue": '#',
            "stringValue": "OPQRST",
            "blobValue": u8,
            "byteValue": -128,
        }
        await rdbStore.insert("AllDataType", valueBucket)
        let predicatesInsert = new data_relationalStore.RdbPredicates("AllDataType");
        predicatesInsert.notContains("characterValue", "#");
        result = await rdbStore.query(predicatesInsert);
        expect(2).assertEqual(result.rowCount);
        result.close();
        result = null;
        let predicatesBefore = new data_relationalStore.RdbPredicates("AllDataType");
        predicatesBefore.equalTo("stringValue", "OPQRST");
        await rdbStore.delete(predicatesBefore);
        done();
        console.log(TAG + "************* testNotContains0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0275
     * @tc.name Normal test case of predicates, test "notContains" for character value
     * @tc.desc 1.Execute notContains ("characterValue", "#")
     *          2.Query data
     *          3.close result
     *          4.updata data
     *          5.Execute notContains ("characterValue", "#")
     *          6.Query data
     */
    it('testNotContains0007', 0, async function (done) {
        console.log(TAG + "************* testNotContains0007 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notContains("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close();
        result = null;
        var u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "integerValue": -2147483648,
            "doubleValue": Number.MIN_VALUE,
            "booleanValue": false,
            "floatValue": 0.1234567,
            "longValue": -9223372036854775808,
            "shortValue": -32768,
            "characterValue": '#',
            "stringValue": "OPQRST",
            "blobValue": u8,
            "byteValue": -128,
        }
        predicates.equalTo("characterValue", "中")
        await rdbStore.update(valueBucket, predicates)
        let predicatesUpdate = new data_relationalStore.RdbPredicates("AllDataType");
        predicatesUpdate.notContains("characterValue", "#");
        result = await rdbStore.query(predicatesUpdate);
        expect(1).assertEqual(result.rowCount);
        result.close();
        result = null;
        const valueBucketBefore = {
            "integerValue": 1,
            "doubleValue": 1.0,
            "booleanValue": false,
            "floatValue": 1.0,
            "longValue": 1,
            "shortValue": 1,
            "characterValue": '中',
            "stringValue": "ABCDEFGHIJKLMN",
            "blobValue": u8,
            "byteValue": 1,
        }
        let predicatesBefore = new data_relationalStore.RdbPredicates("AllDataType");
        predicatesBefore.equalTo("stringValue", "OPQRST");
        await rdbStore.update(valueBucketBefore, predicatesBefore);
        done();
        console.log(TAG + "************* testNotContains0007 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0276
     * @tc.name Normal test case of predicates, test "notContains" for character value
     * @tc.desc 1.Execute notContains ("characterValue", "#")
     *          2.Query data
     *          3.close result
     *          4.delete data
     *          5.Execute notContains ("characterValue", "#")
     *          6.Query data
     */
    it('testNotContains0008', 0, async function (done) {
        console.log(TAG + "************* testNotContains0008 start *************");
        let predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notContains("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        predicates.equalTo("characterValue", "中")
        await rdbStore.delete(predicates)
        predicates = new data_relationalStore.RdbPredicates("AllDataType");
        predicates.notContains("characterValue", "#");
        result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        result = null;
        var u8 = new Uint8Array([1, 2, 3]);
        const valueBucketBefore = {
            "integerValue": 1,
            "doubleValue": 1.0,
            "booleanValue": false,
            "floatValue": 1.0,
            "longValue": 1,
            "shortValue": 1,
            "characterValue": '中',
            "stringValue": "ABCDEFGHIJKLMN",
            "blobValue": u8,
            "byteValue": 1,
        }
        await rdbStore.insert("AllDataType", valueBucketBefore);
        done();
        console.log(TAG + "************* testNotContains0008 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})