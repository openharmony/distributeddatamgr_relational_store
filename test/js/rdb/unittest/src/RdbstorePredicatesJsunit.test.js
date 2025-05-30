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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import dataRdb from '@ohos.data.rdb';

const TAG = "[RDB_JSKITS _TEST]"
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
}
var rdbStore = undefined;
var DOUBLE_MAX = 9223372036854775807;
describe('rdbPredicatesTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await dataRdb.getRdbStore(STORE_CONFIG, 1);
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
        await dataRdb.deleteRdbStore("Predicates.db");
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
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0010
     * @tc.desc predicates equalTo normal test
     */
    it('testEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");

        predicates.equalTo("booleanValue", true);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0001 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0011
     * @tc.desc predicates equalTo normal test
     */
    it('testEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.equalTo("byteValue", -128).or().equalTo("byteValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0002 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0012
     * @tc.desc predicates equalTo normal test
     */
    it('testEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0003 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0013
     * @tc.desc predicates equalTo normal test
     */
    it('testEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.equalTo("doubleValue", DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0004 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0014
     * @tc.desc predicates equalTo normal test
     */
    it('testEqualTo0005', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0005 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.equalTo("shortValue", -32768.0);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testEqualTo0005 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0015
     * @tc.desc predicates equalTo normal test
     */
    it('testEqualTo0006', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0006 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.equalTo("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(true).assertEqual(result.goToFirstRow());
        expect(2).assertEqual(result.getLong(0));
        result.close()

        done();
        console.log(TAG + "************* testEqualTo0006 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0016
     * @tc.desc predicates equalTo normal test
     */
    it('testEqualTo0007', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0007 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.equalTo("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(true).assertEqual(result.goToFirstRow());
        expect(2).assertEqual(result.getLong(0))
        result.close()

        done();
        console.log(TAG + "************* testEqualTo0007 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0017
     * @tc.desc predicates equalTo normal test
     */
    it('testEqualTo0008', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0008 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.number   SUB_DDM_AppDataFWK_JSRDB_Predicates_0018
     * @tc.name     predicates equalTo test
     * @tc.desc     1.equalTo normal test
     *              2.equalTo abnormal test
     */
    it('testEqualTo0009', 0, async function (done) {
        console.log(TAG + "************* testEqualTo0009 start *************");

        let predicates1 = new dataRdb.RdbPredicates("AllDataType");
        predicates1.equalTo('1', 1);
        let result1 = await rdbStore.query(predicates1);
        expect(true).assertEqual(result1.goToFirstRow());
        expect(3).assertEqual(result1.rowCount)
        result1.close()
        result1 = null

        let predicates2 = new dataRdb.RdbPredicates("AllDataType");
        predicates2.equalTo('1', Number.NaN);
        let result2 = await rdbStore.query(predicates2);
        expect(0).assertEqual(result2.rowCount)
        result2.close()
        result2 = null

        done();
        console.log(TAG + "************* testEqualTo0009 end   *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0020
     * @tc.desc predicates notEqualTo normal test
     */
    it('testNotEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notEqualTo("booleanValue", true);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0001 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0021
     * @tc.desc predicates notEqualTo normal test
     */
    it('testNotEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0022
     * @tc.desc predicates notEqualTo normal test
     */
    it('testNotEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notEqualTo("stringValue", "ABCDEFGHIJKLMN");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0003 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0023
     * @tc.desc predicates notEqualTo normal test
     */
    it('testNotEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notEqualTo("doubleValue", DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0004 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0024
     * @tc.desc predicates notEqualTo normal test
     */
    it('testNotEqualTo0005', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0005 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notEqualTo("shortValue", -32768);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0005 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0025
     * @tc.desc predicates notEqualTo normal test
     */
    it('testNotEqualTo0006', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0006 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notEqualTo("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0006 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0026
     * @tc.desc predicates notEqualTo normal test
     */
    it('testNotEqualTo0007', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0007 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notEqualTo("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0007 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0027
     * @tc.desc predicates notEqualTo normal test
     */
    it('testNotEqualTo0008', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0008 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notEqualTo("floatValue", -0.123);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testNotEqualTo0008 end *************");
    })

    /**
     * @tc.number   SUB_DDM_AppDataFWK_JSRDB_Predicates_0028
     * @tc.name     predicates not equalTo test
     * @tc.desc     1.predicates not equalTo normal test
     *              2.predicates not equalTo abnormal test
     */
    it('testNotEqualTo0009', 0, async function (done) {
        console.log(TAG + "************* testNotEqualTo0009 start *************");

        let predicates1 = new dataRdb.RdbPredicates("AllDataType");
        predicates1.notEqualTo('1', 1);
        let result1 = await rdbStore.query(predicates1);
        expect(0).assertEqual(result1.rowCount)
        result1.close()
        result1 = null

        let predicates2 = new dataRdb.RdbPredicates("AllDataType");
        predicates2.notEqualTo('1', Number.NaN);
        let result2 = await rdbStore.query(predicates2);
        expect(0).assertEqual(result2.rowCount)
        result2.close()
        result2 = null

        done();
        console.log(TAG + "************* testNotEqualTo0009 end   *************");
    })

    /**
     * @tc.name predicates isNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0030
     * @tc.desc predicates isNull normal test
     */
    it('testIsNull0001', 0, async function (done) {
        console.log(TAG + "************* testIsNull001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.isNull("primLongValue");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNull0001 end *************");
    })

    /**
     * @tc.name predicates isNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0031
     * @tc.desc predicates isNull normal test
     */
    it('testIsNull0002', 0, async function (done) {
        console.log(TAG + "************* testIsNull0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.isNull("longValue");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNull0002 end *************");
    })

    /**
     * @tc.name predicates isNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0032
     * @tc.desc predicates isNull normal test
     */
    it('testIsNull0003', 0, async function (done) {
        console.log(TAG + "************* testIsNull0003 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.isNull("stringValue");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNull0003 end *************");
    })

    /**
     * @tc.name predicates isNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0033
     * @tc.desc predicates isNull normal test
     */
    it('testIsNull0004', 0, async function (done) {
        console.log(TAG + "************* testIsNull0004 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.isNull("stringValueX");
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNull0004 end *************");
    })

    /**
     * @tc.name predicates isNotNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0040
     * @tc.desc predicates isNotNull normal test
     */
    it('testIsNotNull0001', 0, async function (done) {
        console.log(TAG + "************* testIsNotNull0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.isNotNull("primLongValue");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNotNull0001 end *************");
    })

    /**
     * @tc.name predicates isNotNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0041
     * @tc.desc predicates isNotNull normal test
     */
    it('testIsNotNull0002', 0, async function (done) {
        console.log(TAG + "************* testIsNotNull0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.isNotNull("longValue");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNotNull0002 end *************");
    })

    /**
     * @tc.name predicates isNotNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0042
     * @tc.desc predicates isNotNull normal test
     */
    it('testIsNotNull0003', 0, async function (done) {
        console.log(TAG + "************* testIsNotNull0003 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.isNotNull("stringValue");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNotNull0003 end *************");
    })

    /**
     * @tc.name predicates isNotNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0043
     * @tc.desc predicates isNotNull normal test
     */
    it('testIsNotNull0004', 0, async function (done) {
        console.log(TAG + "************* testIsNotNull0004 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.isNotNull("stringValueX");
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testIsNotNull0004 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0050
     * @tc.desc predicates greaterThan normal test
     */
    it('testGreaterThan0001', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThan("stringValue", "ABC");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0001 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0051
     * @tc.desc predicates greaterThan normal test
     */
    it('testGreaterThan0002', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThan("doubleValue", 0.0);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0002 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0052
     * @tc.desc predicates greaterThan normal test
     */
    it('testGreaterThan0003', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThan("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0003 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0053
     * @tc.desc predicates greaterThan normal test
     */
    it('testGreaterThan0004', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThan("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0004 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0054
     * @tc.desc predicates greaterThan normal test
     */
    it('testGreaterThan0005', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0005 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThan("stringValue", "ZZZ");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0005 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0055
     * @tc.desc predicates greaterThan normal test
     */
    it('testGreaterThan0006', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0006 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThan("doubleValue", 999.0);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0006 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0056
     * @tc.desc predicates greaterThan normal test
     */
    it('testGreaterThan0007', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0007 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThan("integerValue", -999);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0007 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0057
     * @tc.desc predicates greaterThan normal test
     */
    it('testGreaterThan0008', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0008 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThan("longValue", -999);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThan0008 end *************");
    })

    /**
     * @tc.number   SUB_DDM_AppDataFWK_JSRDB_Predicates_0058
     * @tc.name     predicates greaterThan abnormal test
     * @tc.desc     1.predicates greaterThan abnormal "Number.NaN" test
     *              2.predicates greaterThan abnormal "Number.NEGATIVE_INFINITY" test
     *              3.predicates greaterThan abnormal "Number.POSITIVE_INFINITY" test
     *              4.predicates greaterThan abnormal "Number.MIN_SAFE_INTEGER" test
     *              5.predicates greaterThan abnormal "Number.MAX_SAFE_INTEGER" test
     */
    it('testGreaterThan0009', 0, async function (done) {
        console.log(TAG + "************* testGreaterThan0009 start *************");

        let predicates1 = new dataRdb.RdbPredicates("AllDataType");
        predicates1.greaterThan("longValue", Number.NaN);
        let result1 = await rdbStore.query(predicates1);
        expect(0).assertEqual(result1.rowCount);
        result1.close()
        result1 = null

        let predicates2 = new dataRdb.RdbPredicates("AllDataType");
        predicates2.greaterThan("longValue", Number.NEGATIVE_INFINITY);
        let result2 = await rdbStore.query(predicates2);
        expect(3).assertEqual(result2.rowCount);
        result2.close()
        result2 = null

        let predicates3 = new dataRdb.RdbPredicates("AllDataType");
        predicates3.greaterThan("longValue", Number.POSITIVE_INFINITY);
        let result3 = await rdbStore.query(predicates3);
        expect(0).assertEqual(result3.rowCount);
        result3.close()
        result3 = null

        let predicates4 = new dataRdb.RdbPredicates("AllDataType");
        predicates4.greaterThan("longValue", Number.MIN_SAFE_INTEGER);
        let result4 = await rdbStore.query(predicates4);
        expect(2).assertEqual(result4.rowCount);
        result4.close()
        result4 = null

        let predicates5 = new dataRdb.RdbPredicates("AllDataType");
        predicates5.greaterThan("longValue", Number.MAX_SAFE_INTEGER);
        let result5 = await rdbStore.query(predicates5);
        expect(1).assertEqual(result5.rowCount);
        result5.close()
        result5 = null

        done();
        console.log(TAG + "************* testGreaterThan0009 end *************");
    })

    /**
     * @tc.name predicates greaterThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0060
     * @tc.desc predicates greaterThanOrEqualTo normal test
     */
    it('testGreaterThanOrEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testGreaterThanOrEqualTo0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThanOrEqualTo("stringValue", "ABC");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThanOrEqualTo0001 end *************");
    })

    /**
     * @tc.name predicates greaterThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0061
     * @tc.desc predicates greaterThanOrEqualTo normal test
     */
    it('testGreaterThanOrEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testGreaterThanOrEqualTo0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThanOrEqualTo("doubleValue", 0.0);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThanOrEqualTo0002 end *************");
    })

    /**
     * @tc.name predicates greaterThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0062
     * @tc.desc predicates greaterThanOrEqualTo normal test
     */
    it('testGreaterThanOrEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testGreaterThanOrEqualTo0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThanOrEqualTo("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThanOrEqualTo0003 end *************");
    })

    /**
     * @tc.name predicates greaterThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0063
     * @tc.desc predicates greaterThanOrEqualTo normal test
     */
    it('testGreaterThanOrEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testGreaterThanOrEqualTo0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.greaterThanOrEqualTo("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testGreaterThanOrEqualTo0004 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0070
     * @tc.desc predicates lessThan normal test
     */
    it('testLessThan0001', 0, async function (done) {
        console.log(TAG + "************* testLessThan0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThan("stringValue", "ABD");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0001 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0071
     * @tc.desc predicates lessThan normal test
     */
    it('testLessThan0002', 0, async function (done) {
        console.log(TAG + "************* testLessThan0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThan("doubleValue", 0.0);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0002 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0072
     * @tc.desc predicates lessThan normal test
     */
    it('testLessThan0003', 0, async function (done) {
        console.log(TAG + "************* testLessThan0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThan("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0003 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0073
     * @tc.desc predicates lessThan normal test
     */
    it('testLessThan0004', 0, async function (done) {
        console.log(TAG + "************* testLessThan0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThan("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0004 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0074
     * @tc.desc predicates lessThan normal test
     */
    it('testLessThan0005', 0, async function (done) {
        console.log(TAG + "************* testLessThan0005 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThan("stringValue", "ABD");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0005 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0075
     * @tc.desc predicates lessThan normal test
     */
    it('testLessThan0006', 0, async function (done) {
        console.log(TAG + "************* testLessThan0006 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThan("doubleValue", 1.0);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0006 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0076
     * @tc.desc predicates lessThan normal test
     */
    it('testLessThan0007', 0, async function (done) {
        console.log(TAG + "************* testLessThan0007 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThan("integerValue", -2147483648);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0007 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0077
     * @tc.desc predicates lessThan normal test
     */
    it('testLessThan0008', 0, async function (done) {
        console.log(TAG + "************* testLessThan0008 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThan("longValue", -9223372036854775808);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThan0008 end *************");
    })

    /**
     * @tc.name predicates lessThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0080
     * @tc.desc predicates lessThanOrEqualTo normal test
     */
    it('testLessThanOrEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThanOrEqualTo("stringValue", "ABD");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0001 end *************");
    })

    /**
     * @tc.name predicates lessThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0081
     * @tc.desc predicates lessThanOrEqualTo normal test
     */
    it('testLessThanOrEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThanOrEqualTo("doubleValue", 0.0);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0002 end *************");
    })

    /**
     * @tc.name predicates lessThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0082
     * @tc.desc predicates lessThanOrEqualTo normal test
     */
    it('testLessThanOrEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThanOrEqualTo("integerValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0003 end *************");
    })

    /**
     * @tc.name predicates lessThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0083
     * @tc.desc predicates lessThanOrEqualTo normal test
     */
    it('testLessThanOrEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.lessThanOrEqualTo("longValue", 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0004 end *************");
    })

    /**
     * @tc.number   SUB_DDM_AppDataFWK_JSRDB_Predicates_0084
     * @tc.name     predicates lessThanOrEqualTo abnormal test
     * @tc.desc     1.predicates lessThanOrEqualTo abnormal "Number.NaN" test
     *              2.predicates lessThanOrEqualTo abnormal "Number.NEGATIVE_INFINITY" test
     *              3.predicates lessThanOrEqualTo abnormal "Number.POSITIVE_INFINITY" test
     *              4.predicates lessThanOrEqualTo abnormal "Number.MAX_VALUE" test
     *              5.predicates lessThanOrEqualTo abnormal "Number.MIN_VALUE" test
     */
    it('testLessThanOrEqualTo0005', 0, async function (done) {
        console.log(TAG + "************* testLessThanOrEqualTo0005 start *************");

        let predicates1 = new dataRdb.RdbPredicates("AllDataType");
        predicates1.lessThanOrEqualTo("longValue", Number.NaN);
        let result1 = await rdbStore.query(predicates1);
        expect(0).assertEqual(result1.rowCount);
        result1.close()
        result1 = null

        let predicates2 = new dataRdb.RdbPredicates("AllDataType");
        predicates2.lessThanOrEqualTo("longValue", Number.NEGATIVE_INFINITY);
        let result2 = await rdbStore.query(predicates2);
        expect(0).assertEqual(result2.rowCount);
        result2.close()
        result2 = null

        let predicates3 = new dataRdb.RdbPredicates("AllDataType");
        predicates3.lessThanOrEqualTo("longValue", Number.POSITIVE_INFINITY);
        let result3 = await rdbStore.query(predicates3);
        expect(3).assertEqual(result3.rowCount);
        result3.close()
        result3 = null

        let predicates4 = new dataRdb.RdbPredicates("AllDataType");
        predicates4.lessThanOrEqualTo("longValue", Number.MAX_VALUE);
        let result4 = await rdbStore.query(predicates4);
        expect(3).assertEqual(result4.rowCount);
        result4.close()
        result4 = null

        let predicates5 = new dataRdb.RdbPredicates("AllDataType");
        predicates5.lessThanOrEqualTo("longValue", Number.MIN_VALUE);
        let result5 = await rdbStore.query(predicates5);
        expect(1).assertEqual(result5.rowCount);
        result5.close()
        result5 = null

        done();
        console.log(TAG + "************* testLessThanOrEqualTo0005 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0090
     * @tc.desc predicates between normal test
     */
    it('testBetween0001', 0, async function (done) {
        console.log(TAG + "************* testBetween0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.between("stringValue", "ABB", "ABD");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0001 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0091
     * @tc.desc predicates between normal test
     */
    it('testBetween0002', 0, async function (done) {
        console.log(TAG + "************* testBetween0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.between("doubleValue", 0.0, DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0002 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0092
     * @tc.desc predicates between normal test
     */
    it('testBetween0003', 0, async function (done) {
        console.log(TAG + "************* testBetween0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.between("integerValue", 0, 1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0003 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0093
     * @tc.desc predicates between normal test
     */
    it('testBetween0004', 0, async function (done) {
        console.log(TAG + "************* testBetween0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.between("longValue", 0, 2);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0004 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0094
     * @tc.desc predicates between normal test
     */
    it('testBetween0005', 0, async function (done) {
        console.log(TAG + "************* testBetween0005 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.between("stringValue", "ABB", "ABB");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0005 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0095
     * @tc.desc predicates between normal test
     */
    it('testBetween0006', 0, async function (done) {
        console.log(TAG + "************* testBetween0006 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.between("doubleValue", DOUBLE_MAX, DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0006 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0096
     * @tc.desc predicates between normal test
     */
    it('testBetween0007', 0, async function (done) {
        console.log(TAG + "************* testBetween0007 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.between("integerValue", 1, 0);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0007 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0097
     * @tc.desc predicates between normal test
     */
    it('testBetween0008', 0, async function (done) {
        console.log(TAG + "************* testBetween0008 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.between("longValue", 2, -1);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testBetween0008 end *************");
    })

    /**
     * @tc.number   SUB_DDM_AppDataFWK_JSRDB_Predicates_0098
     * @tc.name     predicates between abnormal test
     * @tc.desc     1.predicates between abnormal "Number.POSITIVE_INFINITY" test
     *              2.predicates between abnormal "Number.NEGATIVE_INFINITY" test
     *              3.predicates between abnormal "Number.NaN" test
     *              4.predicates between abnormal "Number.NaN" test
     *              5.predicates between abnormal "Number.MIN_VALUE" test
     *              6.predicates between abnormal "Number.MAX_VALUE" test
     */
    it('testBetween0009', 0, async function (done) {
        console.log(TAG + "************* testBetween0009 start *************");

        let predicates1 = new dataRdb.RdbPredicates("AllDataType");
        predicates1.between("longValue", 0, Number.POSITIVE_INFINITY);
        let result1 = await rdbStore.query(predicates1);
        expect(2).assertEqual(result1.rowCount);
        result1.close();
        result1 = null

        let predicates2 = new dataRdb.RdbPredicates("AllDataType");
        predicates2.between("longValue", Number.NEGATIVE_INFINITY, 0);
        let result2 = await rdbStore.query(predicates2);
        expect(1).assertEqual(result2.rowCount);
        result2.close();
        result2 = null

        let predicates3 = new dataRdb.RdbPredicates("AllDataType");
        predicates3.between("longValue", Number.NaN, 0);
        let result3 = await rdbStore.query(predicates3);
        expect(0).assertEqual(result3.rowCount);
        result3.close();
        result3 = null

        let predicates4 = new dataRdb.RdbPredicates("AllDataType");
        predicates4.between("longValue", 0, Number.NaN);
        let result4 = await rdbStore.query(predicates4);
        expect(0).assertEqual(result4.rowCount);
        result4.close();
        result4 = null

        let predicates5 = new dataRdb.RdbPredicates("AllDataType");
        predicates5.between("longValue", Number.MIN_VALUE, 0);
        let result5 = await rdbStore.query(predicates5);
        expect(0).assertEqual(result5.rowCount);
        result5.close();
        result5 = null

        let predicates6 = new dataRdb.RdbPredicates("AllDataType");
        predicates6.between("longValue", 0, Number.MAX_VALUE);
        let result6 = await rdbStore.query(predicates6);
        expect(2).assertEqual(result6.rowCount);
        result6.close();
        result6 = null

        done();
        console.log(TAG + "************* testBetween0009 end *************");
    })

    /**
     * @tc.name testNotBetween0001
     * @tc.number I4JWCV
     * @tc.desc test string value with notBetween.
     */
    it('testNotBetween0001', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notBetween("stringValue", "ABB", "ABD");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0001 end *************");
    })

    /**
     * @tc.name testNotBetween0002
     * @tc.number I4JWCV
     * @tc.desc test double value with notBetween.
     */
    it('testNotBetween0002', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notBetween("doubleValue", 0.0, DOUBLE_MAX);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0002 end *************");
    })

    /**
     * @tc.name testNotBetween0003
     * @tc.number I4JWCV
     * @tc.desc test integer value with notBetween.
     */
    it('testNotBetween0003', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notBetween("integerValue", 0, 1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0003 end *************");
    })

    /**
     * @tc.name testNotBetween0004
     * @tc.number I4JWCV
     * @tc.desc test long value with notBetween.
     */
    it('testNotBetween0004', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notBetween("longValue", 0, 2);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0004 end *************");
    })


    /**
     * @tc.number   testNotBetween0005
     * @tc.name     test long value with notBetween.
     * @tc.desc     1.predicates between abnormal "Number.NaN" test
     *              2.predicates between abnormal "Number.NaN" test
     *              3.predicates between abnormal "Number.MIN_VALUE" test
     *              4.predicates between abnormal "Number.MAX_VALUE" test
     *              5.predicates between abnormal "Number.NEGATIVE_INFINITY" test
     *              6.predicates between abnormal "Number.POSITIVE_INFINITY" test
     */
    it('testNotBetween0005', 0, async function (done) {
        console.log(TAG + "************* testNotBetween0005 start *************");

        let predicates1 = new dataRdb.RdbPredicates("AllDataType");
        predicates1.notBetween("longValue", 0, Number.NaN);
        let result = await rdbStore.query(predicates1);
        expect(1).assertEqual(result.rowCount);
        result.close();

        let predicates2 = new dataRdb.RdbPredicates("AllDataType");
        predicates2.notBetween("longValue", Number.NaN, 0);
        result = await rdbStore.query(predicates2);
        expect(2).assertEqual(result.rowCount);
        result.close();

        let predicates3 = new dataRdb.RdbPredicates("AllDataType");
        predicates3.notBetween("longValue", Number.MIN_VALUE, 0);
        result = await rdbStore.query(predicates3);
        expect(3).assertEqual(result.rowCount);
        result.close();

        let predicates4 = new dataRdb.RdbPredicates("AllDataType");
        predicates4.notBetween("longValue", 0, Number.MAX_VALUE);
        result = await rdbStore.query(predicates4);
        expect(1).assertEqual(result.rowCount);
        result.close();

        let predicates5 = new dataRdb.RdbPredicates("AllDataType");
        predicates5.notBetween("longValue", Number.NEGATIVE_INFINITY, 0);
        result = await rdbStore.query(predicates5);
        expect(2).assertEqual(result.rowCount);
        result.close();

        let predicates6 = new dataRdb.RdbPredicates("AllDataType");
        predicates6.notBetween("longValue", 0, Number.POSITIVE_INFINITY);
        result = await rdbStore.query(predicates6);
        expect(1).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testNotBetween0005 end *************");
    })

    /**
     * @tc.name testGlob0001
     * @tc.number I4JWCV
     * @tc.desc end with ? by glob.
     */
    it('testGlob0001', 0, async function (done) {
        console.log(TAG + "************* testGlob0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "ABC*");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0001 end *************");
    })

    /**
     * @tc.name testGlob0002
     * @tc.number I4JWCV
     * @tc.desc begin with * by glob.
     */
    it('testGlob0002', 0, async function (done) {
        console.log(TAG + "************* testGlob0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "*LMN");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0002 end *************");
    })

    /**
     * @tc.name testGlob0003
     * @tc.number I4JWCV
     * @tc.desc end with ? by glob.
     */
    it('testGlob0003', 0, async function (done) {
        console.log(TAG + "************* testGlob0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "ABCDEFGHIJKLM?");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0003 end *************");
    })

    /**
     * @tc.name testGlob0004
     * @tc.number I4JWCV
     * @tc.desc begin with ? by glob.
     */
    it('testGlob0004', 0, async function (done) {
        console.log(TAG + "************* testGlob0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "?BCDEFGHIJKLMN");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0004 end *************");
    })

    /**
     * @tc.name testGlob0005
     * @tc.number I4JWCV
     * @tc.desc begin and end with * by glob.
     */
    it('testGlob0005', 0, async function (done) {
        console.log(TAG + "************* testGlob0005 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "*FGHI*");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0005 end *************");
    })

    /**
     * @tc.name testGlob0006
     * @tc.number I4JWCV
     * @tc.desc begin and end with ? by glob.
     */
    it('testGlob0006', 0, async function (done) {
        console.log(TAG + "************* testGlob0006 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.glob("stringValue", "?BCDEFGHIJKLM?");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        result = null

        done();
        console.log(TAG + "************* testGlob0006 end *************");
    })

    /**
     * @tc.name predicates contains normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0100
     * @tc.desc predicates contains normal test
     */
    it('testContains0001', 0, async function (done) {
        console.log(TAG + "************* testContains0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.contains("stringValue", "DEF");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testContains0001 end *************");
    })

    /**
     * @tc.name predicates contains normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0101
     * @tc.desc predicates contains normal test
     */
    it('testContains0002', 0, async function (done) {
        console.log(TAG + "************* testContains0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.contains("stringValue", "DEFX");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testContains0002 end *************");
    })

    /**
     * @tc.name predicates contains normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0102
     * @tc.desc predicates contains normal test
     */
    it('testContains0003', 0, async function (done) {
        console.log(TAG + "************* testContains0003 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.contains("characterValue", "中");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testContains0003 end *************");
    })

    /**
     * @tc.name predicates contains normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0103
     * @tc.desc predicates contains normal test
     */
    it('testContains0004', 0, async function (done) {
        console.log(TAG + "************* testContains0004 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.contains("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testContains0004 end *************");
    })

    /**
     * @tc.number   SUB_DDM_AppDataFWK_JSRDB_Predicates_0104
     * @tc.name     predicates contains abnormal test
     * @tc.desc     1.predicates contains abnormal "null" test
     *              2.predicates contains abnormal "undefined" test
     */
    it('testContains0005', 0, async function (done) {
        console.log(TAG + "************* testContains0005 start *************");

        let predicates1 = new dataRdb.RdbPredicates("AllDataType");
        predicates1.contains("characterValue", null);
        let result1 = await rdbStore.query(predicates1);
        expect(3).assertEqual(result1.rowCount);
        result1.close()
        result1 = null


        let predicates2 = new dataRdb.RdbPredicates("AllDataType");
        predicates2.contains("characterValue", undefined);
        let result2 = await rdbStore.query(predicates2);
        expect(3).assertEqual(result2.rowCount);
        result2.close()
        result2 = null

        done();
        console.log(TAG + "************* testContains0005 end *************");
    })

    /**
     * @tc.name predicates beginsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0110
     * @tc.desc predicates beginsWith normal test
     */
    it('testBeginsWith0001', 0, async function (done) {
        console.log(TAG + "************* testBeginsWith0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.beginsWith("stringValue", "ABC");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testBeginsWith0001 end *************");
    })

    /**
     * @tc.name predicates beginsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0111
     * @tc.desc predicates beginsWith normal test
     */
    it('testBeginsWith0002', 0, async function (done) {
        console.log(TAG + "************* testBeginsWith0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.beginsWith("stringValue", "ABCX");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testBeginsWith0002 end *************");
    })

    /**
     * @tc.name predicates beginsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0112
     * @tc.desc predicates beginsWith normal test
     */
    it('testBeginsWith0003', 0, async function (done) {
        console.log(TAG + "************* testBeginsWith0003 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.beginsWith("characterValue", "中");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testBeginsWith0003 end *************");
    })

    /**
     * @tc.name predicates beginsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0113
     * @tc.desc predicates beginsWith normal test
     */
    it('testBeginsWith0004', 0, async function (done) {
        console.log(TAG + "************* testBeginsWith0004 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.beginsWith("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testBeginsWith0004 end *************");
    })

    /**
     * @tc.name predicates endsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0120
     * @tc.desc predicates endsWith normal test
     */
    it('testEndsWith0001', 0, async function (done) {
        console.log(TAG + "************* testEndsWith0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.endsWith("stringValue", "LMN");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testEndsWith0001 end *************");
    })

    /**
     * @tc.name predicates endsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0121
     * @tc.desc predicates endsWith normal test
     */
    it('testEndsWith0002', 0, async function (done) {
        console.log(TAG + "************* testEndsWith0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.endsWith("stringValue", "LMNX");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testEndsWith0002 end *************");
    })

    /**
     * @tc.name predicates endsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0122
     * @tc.desc predicates endsWith normal test
     */
    it('testEndsWith0003', 0, async function (done) {
        console.log(TAG + "************* testEndsWith0003 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.endsWith("characterValue", "中");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testEndsWith0003 end *************");
    })

    /**
     * @tc.name predicates endsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0123
     * @tc.desc predicates endsWith normal test
     */
    it('testEndsWith0004', 0, async function (done) {
        console.log(TAG + "************* testEndsWith0004 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.endsWith("characterValue", "#");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testEndsWith0004 end *************");
    })

    /**
     * @tc.name predicates like normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0130
     * @tc.desc predicates like normal test
     */
    it('testLike0001', 0, async function (done) {
        console.log(TAG + "************* testLike0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "%LMN%");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLike0001 end *************");
    })

    /**
     * @tc.name predicates like normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0130
     * @tc.desc predicates like normal test
     */
    it('testLike0002', 0, async function (done) {
        console.log(TAG + "************* testLike0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "%LMNX%");
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLike0002 end *************");
    })

    /**
     * @tc.name predicates like normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0132
     * @tc.desc predicates like normal test
     */
    it('testLike0003', 0, async function (done) {
        console.log(TAG + "************* testLike0003 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("characterValue", "%中%");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLike0003 end *************");
    })

    /**
     * @tc.name predicates like normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0133
     * @tc.desc predicates like normal test
     */
    it('testLike0004', 0, async function (done) {
        console.log(TAG + "************* testLike0004 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("characterValue", "%#%");
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLike0004 end *************");
    })

    /**
     * @tc.number   SUB_DDM_AppDataFWK_JSRDB_Predicates_0133
     * @tc.name     predicates like abnormal test
     * @tc.desc     1.predicates like abnormal "null" test
     *              2.predicates like abnormal "undefined" test
     */
    it('testLike0005', 0, async function (done) {
        console.log(TAG + "************* testLike0005 start *************");

        let predicates1 = new dataRdb.RdbPredicates("AllDataType");
        predicates1.like("characterValue", null);
        let result1 = await rdbStore.query(predicates1);
        expect(3).assertEqual(result1.rowCount);
        result1.close()
        result1 = null

        let predicates2 = new dataRdb.RdbPredicates("AllDataType");
        predicates2.like("characterValue", undefined);
        let result2 = await rdbStore.query(predicates2);
        expect(3).assertEqual(result2.rowCount);
        result2.close()
        result2 = null

        done();
        console.log(TAG + "************* testLike0005 end *************");
    })


    /**
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0140
     * @tc.desc predicates beginWrap normal test
     */
    it('testBeginWrap0001', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0141
     * @tc.desc predicates beginWrap normal test
     */
    it('testBeginWrap0002', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0142
     * @tc.desc predicates beginWrap normal test
     */
    it('testBeginWrap0003', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0143
     * @tc.desc predicates beginWrap normal test
     */
    it('testBeginWrap0004', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0144
     * @tc.desc predicates beginWrap normal test
     */
    it('testBeginWrap0005', 0, async function (done) {
        console.log(TAG + "************* testBeginWrap0005 start *************");
        {
            let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates and normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0150
     * @tc.desc predicates and normal test
     */
    it('testAnd0001', 0, async function (done) {
        console.log(TAG + "************* testAnd0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates or normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0151
     * @tc.desc predicates or normal test
     */
    it('testAnd0002', 0, async function (done) {
        console.log(TAG + "************* testAnd0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates and normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0152
     * @tc.desc predicates and normal test
     */
    it('testAnd0003', 0, async function (done) {
        console.log(TAG + "************* testAnd0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN").or().and().equalTo("integerValue", 1);
        console.log(TAG + "you should not start a request" + " with \"and\" or use or() before this function");

        done();
        console.log(TAG + "************* testAnd0003 end *************");
    })

    /**
     * @tc.name predicates order normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0160
     * @tc.desc predicates order normal test
     */
    it('testOrder0001', 0, async function (done) {
        console.log(TAG + "************* testOrder0001 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates order normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0161
     * @tc.desc predicates order normal test
     */
    it('testOrder0002', 0, async function (done) {
        console.log(TAG + "************* testOrder0002 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates order normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0162
     * @tc.desc predicates order normal test
     */
    it('testOrder0003', 0, async function (done) {
        console.log(TAG + "************* testOrder0003 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByDesc("integerValueX").distinct();
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testOrder0003 end *************");
    })

    /**
     * @tc.name predicates order normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0163
     * @tc.desc predicates order normal test
     */
    it('testOrder0004', 0, async function (done) {
        console.log(TAG + "************* testOrder0004 start *************");

        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByAsc("integerValueX").distinct();
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null

        done();
        console.log(TAG + "************* testOrder0004 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0170
     * @tc.desc predicates limit normal test
     */
    it('testLimit0001', 0, async function (done) {
        console.log(TAG + "************* testLimit0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(1);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0001 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0171
     * @tc.desc predicates limit normal test
     */
    it('testLimit0002', 0, async function (done) {
        console.log(TAG + "************* testLimit0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0002 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0172
     * @tc.desc predicates limit normal test
     */
    it('testLimit0003', 0, async function (done) {
        console.log(TAG + "************* testLimit0003 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(100);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0003 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0173
     * @tc.desc predicates limit normal test
     */
    it('testLimit0004', 0, async function (done) {
        console.log(TAG + "************* testLimit0004 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "中").limitAs(1);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0004 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0174
     * @tc.desc predicates limit normal test
     */
    it('testLimit0005', 0, async function (done) {
        console.log(TAG + "************* testLimit0005 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(0);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0005 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0175
     * @tc.desc predicates limit normal test
     */
    it('testLimit0006', 0, async function (done) {
        console.log(TAG + "************* testLimit0006 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(-1);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testLimit0006 end *************");
    })

    /**
     * @tc.name predicates offset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0180
     * @tc.desc predicates offset normal test
     */
    it('testOffset0001', 0, async function (done) {
        console.log(TAG + "************* testOffset0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(1);
        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testOffset0001 end *************");
    })

    /**
     * @tc.name predicates offset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0181
     * @tc.desc predicates offset normal test
     */
    it('testOffset0002', 0, async function (done) {
        console.log(TAG + "************* testOffset0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(0);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testOffset0002 end *************");
    })

    /**
     * @tc.name predicates offset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0182
     * @tc.desc predicates offset normal test
     */
    it('testOffset0003', 0, async function (done) {
        console.log(TAG + "************* testOffset0003 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(5);
        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testOffset0003 end *************");
    })

    /**
     * @tc.name predicates offset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0183
     * @tc.desc predicates offset normal test
     */
    it('testOffset0004', 0, async function (done) {
        console.log(TAG + "************* testOffset0004 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(-1);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testOffset0004 end *************");
    })

    /**
     * @tc.name predicates in normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0190
     * @tc.desc predicates in normal test
     */
    it('testIn0001', 0, async function (done) {
        console.log(TAG + "************* testIn0001 start *************");
        var values = [Number.MIN_VALUE.toString()];
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.in("doubleValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testIn0001 end *************");
    })

    /**
     * @tc.name predicates in normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0191
     * @tc.desc predicates in normal test
     */
    it('testIn0002', 0, async function (done) {
        console.log(TAG + "************* testIn0002 start *************");
        var values = ["1.0"];
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.in("doubleValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testIn0002 end *************");
    })

    /**
     * @tc.name predicates in normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0192
     * @tc.desc predicates in normal test
     */
    it('testIn0003', 0, async function (done) {
        console.log(TAG + "************* testIn0003 start *************");
        var values = [DOUBLE_MAX.toString()];
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.in("doubleValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testIn0003 end *************");
    })

    /**
     * @tc.name predicates in normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0193
     * @tc.desc predicates in normal test
     */
    it('testIn0004', 0, async function (done) {
        console.log(TAG + "************* testIn0004 start *************");
        var values = [Number.MIN_VALUE.toString(), "1.0", DOUBLE_MAX.toString()];
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.in("doubleValue", values);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testIn0004 end *************");
    })

    /**
     * @tc.name predicates in normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0194
     * @tc.desc predicates in normal test
     */
    it('testIn0005', 0, async function (done) {
        console.log(TAG + "************* testIn0005 start *************");
        var values = [];
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.in("doubleValue", values);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testIn0005 end *************");
    })

    /**
     * @tc.name testNotIn0001
     * @tc.number I4JWCV
     * @tc.desc the common and min value test with notin.
     */
    it('testNotIn0001', 0, async function (done) {
        console.log(TAG + "************* testNotIn0001 start *************");
        var values = [1, -2147483648];
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notIn("integerValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testNotIn0001 end *************");
    })

    /**
     * @tc.name testNotIn0002
     * @tc.number I4JWCV
     * @tc.desc the common and max value test with notin.
     */
    it('testNotIn0002', 0, async function (done) {
        console.log(TAG + "************* testNotIn0002 start *************");
        let values = [1, 2147483647];
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notIn("integerValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testNotIn0002 end *************");
    })

    /**
     * @tc.name testNotIn0003
     * @tc.number I4JWCV
     * @tc.desc the min and max value test with notin.
     */
    it('testNotIn0003', 0, async function (done) {
        console.log(TAG + "************* testNotIn0003 start *************");
        var values = [-2147483648, 2147483647];
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notIn("integerValue", values);
        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testNotIn0003 end *************");
    })

    /**
     * @tc.name testNotIn0004
     * @tc.number I4JWCV
     * @tc.desc the min and max value test with notin.
     */
    it('testNotIn0004', 0, async function (done) {
        console.log(TAG + "************* testNotIn0004 start *************");
        var values = [];
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.notIn("integerValue", values);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testNotIn0004 end *************");
    })

    /**
     * @tc.name predicates constructor test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0200
     * @tc.desc predicates constructor test
     */
    it('testCreate0001', 0, async function (done) {
        console.log(TAG + "************* testCreate0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testCreate0001 end *************");
    })

    /**
     * @tc.name predicates constructor test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0201
     * @tc.desc predicates constructor test
     */
    it('testCreate0002', 0, async function (done) {
        console.log(TAG + "************* testCreate0002 start *************");
        let predicates = new dataRdb.RdbPredicates("test");
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        done();
        console.log(TAG + "************* testCreate0002 end *************");
    })

    /**
     * @tc.name predicates groupBy test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0210
     * @tc.desc predicates groupBy test
     */
    it('testGroupBy0001', 0, async function (done) {
        console.log(TAG + "************* testGroupBy0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").groupBy(["characterValue"]);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testGroupBy0001 end *************");
    })

    /**
     * @tc.name predicates groupBy test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0211
     * @tc.desc predicates groupBy test
     */
    it('testGroupBy0002', 0, async function (done) {
        console.log(TAG + "************* testGroupBy0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
        predicates.like("stringValue", "ABCDEFGHIJKLMN").groupBy(["characterValueX"]);
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result.close()
        result = null
        done();
        console.log(TAG + "************* testGroupBy0002 end *************");
    })

    /**
     * @tc.name predicates indexedBy test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0220
     * @tc.desc predicates indexedBy test
     */
    it('testIndexedBy0001', 0, async function (done) {
        console.log(TAG + "************* testIndexedBy0001 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
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
     * @tc.name predicates indexedBy test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_0221
     * @tc.desc predicates indexedBy test
     */
    it('testIndexedBy0002', 0, async function (done) {
        console.log(TAG + "************* testIndexedBy0002 start *************");
        let predicates = new dataRdb.RdbPredicates("AllDataType");
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

    console.log(TAG + "*************Unit Test End*************");
})