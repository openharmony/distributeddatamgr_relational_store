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
import dataAbility from '@ohos.data.dataAbility';

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

describe('dataAbilityPredicatesTest', function () {
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

    function resultSize(resultSet) {
        if (!resultSet.goToFirstRow()) {
            return 0;
        }
        let count = 1;
        while (resultSet.goToNextRow()) {
            count++;
        }
        return count;
    }

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
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0010
     * @tc.desc predicates equalTo normal test
     */
    it('testDataAbilityDataAbilityEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityDataAbilityEqualTo0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("booleanValue", true);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityDataAbilityEqualTo0001 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0011
     * @tc.desc predicates equalTo normal test
     */
    it('testDataAbilityDataAbilityEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityDataAbilityEqualTo0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("byteValue", -128).or().equalTo("byteValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityEqualTo0002 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0012
     * @tc.desc predicates equalTo normal test
     */
    it('testDataAbilityDataAbilityEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEqualTo0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityEqualTo0003 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0013
     * @tc.desc predicates equalTo normal test
     */
    it('testDataAbilityDataAbilityEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEqualTo0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("doubleValue", DOUBLE_MAX);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityEqualTo0004 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0014
     * @tc.desc predicates equalTo normal test
     */
    it('testDataAbilityDataAbilityEqualTo0005', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEqualTo0005 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("shortValue", -32768.0);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityEqualTo0005 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0015
     * @tc.desc predicates equalTo normal test
     */
    it('testDataAbilityDataAbilityEqualTo0006', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEqualTo0006 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("integerValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(true).assertEqual(result.goToFirstRow());
            expect(2).assertEqual(result.getLong(0));
        }
        done();
        console.log(TAG + "************* testDataAbilityEqualTo0006 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0016
     * @tc.desc predicates equalTo normal test
     */
    it('testDataAbilityDataAbilityEqualTo0007', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEqualTo0007 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("longValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(true).assertEqual(result.goToFirstRow());
            expect(2).assertEqual(result.getLong(0))
        }
        done();
        console.log(TAG + "************* testDataAbilityEqualTo0007 end   *************");
    })

    /**
     * @tc.name predicates equalTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0017
     * @tc.desc predicates equalTo normal test
     */
    it('testDataAbilityEqualTo0008', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEqualTo0008 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("floatValue", -0.123);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(true).assertEqual(result.goToFirstRow());
            expect(1).assertEqual(result.getLong(0))
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityEqualTo0008 end   *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0020
     * @tc.desc predicates notEqualTo normal test
     */
    it('testDataAbilityNotEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotEqualTo0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notEqualTo("booleanValue", true);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotEqualTo0001 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0021
     * @tc.desc predicates notEqualTo normal test
     */
    it('testDataAbilityNotEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotEqualTo0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notEqualTo("byteValue", -128);
            dataAbilityPredicates.notEqualTo("byteValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotEqualTo0002 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0022
     * @tc.desc predicates notEqualTo normal test
     */
    it('testDataAbilityNotEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotEqualTo0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notEqualTo("stringValue", "ABCDEFGHIJKLMN");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotEqualTo0003 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0023
     * @tc.desc predicates notEqualTo normal test
     */
    it('testDataAbilityNotEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotEqualTo0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notEqualTo("doubleValue", DOUBLE_MAX);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotEqualTo0004 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0024
     * @tc.desc predicates notEqualTo normal test
     */
    it('testDataAbilityNotEqualTo0005', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotEqualTo0005 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notEqualTo("shortValue", -32768);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotEqualTo0005 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0025
     * @tc.desc predicates notEqualTo normal test
     */
    it('testDataAbilityNotEqualTo0006', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotEqualTo0006 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notEqualTo("integerValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotEqualTo0006 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0026
     * @tc.desc predicates notEqualTo normal test
     */
    it('testDataAbilityNotEqualTo0007', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotEqualTo0007 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notEqualTo("longValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotEqualTo0007 end *************");
    })

    /**
     * @tc.name predicates notEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0027
     * @tc.desc predicates notEqualTo normal test
     */
    it('testDataAbilityNotEqualTo0008', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotEqualTo0008 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notEqualTo("floatValue", -0.123);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotEqualTo0008 end *************");
    })

    /**
     * @tc.name resultSet isNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0030
     * @tc.desc resultSet isNull normal test
     */
    it('testDataAbilityIsNull0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIsNull001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.isNull("primLongValue");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIsNull0001 end *************");
    })

    /**
     * @tc.name predicates isNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0031
     * @tc.desc predicates isNull normal test
     */
    it('testDataAbilityIsNull0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIsNull0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.isNull("longValue");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIsNull0002 end *************");
    })

    /**
     * @tc.name predicates isNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0032
     * @tc.desc predicates isNull normal test
     */
    it('testDataAbilityIsNull0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIsNull0003 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.isNull("stringValue");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIsNull0003 end *************");
    })

    /**
     * @tc.name predicates isNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0033
     * @tc.desc predicates isNull normal test
     */
    it('testDataAbilityIsNull0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIsNull0004 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.isNull("stringValueX");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIsNull0004 end *************");
    })

    /**
     * @tc.name predicates isNotNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0040
     * @tc.desc predicates isNotNull normal test
     */
    it('testDataAbilityIsNotNull0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIsNotNull0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.isNotNull("primLongValue");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIsNotNull0001 end *************");
    })

    /**
     * @tc.name predicates isNotNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0041
     * @tc.desc predicates isNotNull normal test
     */
    it('testDataAbilityIsNotNull0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIsNotNull0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.isNotNull("longValue");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIsNotNull0002 end *************");
    })

    /**
     * @tc.name predicates isNotNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0042
     * @tc.desc predicates isNotNull normal test
     */
    it('testDataAbilityIsNotNull0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIsNotNull0003 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.isNotNull("stringValue");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIsNotNull0003 end *************");
    })

    /**
     * @tc.name predicates isNotNull normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0043
     * @tc.desc predicates isNotNull normal test
     */
    it('testDataAbilityIsNotNull0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIsNotNull0004 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.isNotNull("stringValueX");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIsNotNull0004 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0050
     * @tc.desc predicates greaterThan normal test
     */
    it('testDataAbilityGreaterThan0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThan0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThan("stringValue", "ABC");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThan0001 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0051
     * @tc.desc predicates greaterThan normal test
     */
    it('testDataAbilityGreaterThan0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThan0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThan("doubleValue", 0.0);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThan0002 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0052
     * @tc.desc predicates greaterThan normal test
     */
    it('testDataAbilityGreaterThan0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThan0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThan("integerValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThan0003 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0053
     * @tc.desc predicates greaterThan normal test
     */
    it('testDataAbilityGreaterThan0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThan0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThan("longValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThan0004 end *************");
    })


    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0054
     * @tc.desc predicates greaterThan normal test
     */
    it('testDataAbilityGreaterThan0005', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThan0005 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThan("stringValue", "ZZZ");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThan0005 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0055
     * @tc.desc predicates greaterThan normal test
     */
    it('testDataAbilityGreaterThan0006', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThan0006 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThan("doubleValue", 999.0);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThan0006 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0056
     * @tc.desc predicates greaterThan normal test
     */
    it('testDataAbilityGreaterThan0007', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThan0007 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThan("integerValue", -999);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThan0007 end *************");
    })

    /**
     * @tc.name predicates greaterThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0057
     * @tc.desc predicates greaterThan normal test
     */
    it('testDataAbilityGreaterThan0008', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThan0008 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThan("longValue", -999);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThan0008 end *************");
    })

    /**
     * @tc.name predicates greaterThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0060
     * @tc.desc predicates greaterThanOrEqualTo normal test
     */
    it('testDataAbilityGreaterThanOrEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThanOrEqualTo0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThanOrEqualTo("stringValue", "ABC");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThanOrEqualTo0001 end *************");
    })

    /**
     * @tc.name predicates greaterThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0061
     * @tc.desc predicates greaterThanOrEqualTo normal test
     */
    it('testDataAbilityGreaterThanOrEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThanOrEqualTo0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThanOrEqualTo("doubleValue", 0.0);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThanOrEqualTo0002 end *************");
    })

    /**
     * @tc.name predicates greaterThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0062
     * @tc.desc predicates greaterThanOrEqualTo normal test
     */
    it('testDataAbilityGreaterThanOrEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThanOrEqualTo0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThanOrEqualTo("integerValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThanOrEqualTo0003 end *************");
    })

    /**
     * @tc.name predicates greaterThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0063
     * @tc.desc predicates greaterThanOrEqualTo normal test
     */
    it('testDataAbilityGreaterThanOrEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGreaterThanOrEqualTo0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.greaterThanOrEqualTo("longValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGreaterThanOrEqualTo0004 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0070
     * @tc.desc predicates lessThan normal test
     */
    it('testDataAbilityLessThan0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThan0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThan("stringValue", "ABD");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThan0001 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0071
     * @tc.desc predicates lessThan normal test
     */
    it('testDataAbilityLessThan0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThan0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThan("doubleValue", 0.0);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThan0002 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0072
     * @tc.desc predicates lessThan normal test
     */
    it('testDataAbilityLessThan0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThan0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThan("integerValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThan0003 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0073
     * @tc.desc predicates lessThan normal test
     */
    it('testDataAbilityLessThan0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThan0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThan("longValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThan0004 end *************");
    })


    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0074
     * @tc.desc predicates lessThan normal test
     */
    it('testDataAbilityLessThan0005', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThan0005 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThan("stringValue", "ABD");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThan0005 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0075
     * @tc.desc predicates lessThan normal test
     */
    it('testDataAbilityLessThan0006', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThan0006 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThan("doubleValue", 1.0);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThan0006 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0076
     * @tc.desc predicates lessThan normal test
     */
    it('testDataAbilityLessThan0007', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThan0007 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThan("integerValue", -2147483648);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThan0007 end *************");
    })

    /**
     * @tc.name predicates lessThan normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0077
     * @tc.desc predicates lessThan normal test
     */
    it('testDataAbilityLessThan0008', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThan0008 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThan("longValue", -9223372036854775808);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThan0008 end *************");
    })


    /**
     * @tc.name predicates lessThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0080
     * @tc.desc predicates lessThanOrEqualTo normal test
     */
    it('testDataAbilityLessThanOrEqualTo0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThanOrEqualTo0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThanOrEqualTo("stringValue", "ABD");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThanOrEqualTo0001 end *************");
    })

    /**
     * @tc.name predicates lessThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0081
     * @tc.desc predicates lessThanOrEqualTo normal test
     */
    it('testDataAbilityLessThanOrEqualTo0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThanOrEqualTo0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThanOrEqualTo("doubleValue", 0.0);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThanOrEqualTo0002 end *************");
    })

    /**
     * @tc.name predicates lessThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0082
     * @tc.desc predicates lessThanOrEqualTo normal test
     */
    it('testDataAbilityLessThanOrEqualTo0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThanOrEqualTo0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThanOrEqualTo("integerValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThanOrEqualTo0003 end *************");
    })

    /**
     * @tc.name predicates lessThanOrEqualTo normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0083
     * @tc.desc predicates lessThanOrEqualTo normal test
     */
    it('testDataAbilityLessThanOrEqualTo0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLessThanOrEqualTo0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.lessThanOrEqualTo("longValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityLessThanOrEqualTo0004 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0090
     * @tc.desc predicates between normal test
     */
    it('testDataAbilityBetween0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBetween0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.between("stringValue", "ABB", "ABD");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBetween0001 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0091
     * @tc.desc predicates between normal test
     */
    it('testDataAbilityBetween0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBetween0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.between("doubleValue", 0.0, DOUBLE_MAX);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBetween0002 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0092
     * @tc.desc predicates between normal test
     */
    it('testDataAbilityBetween0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBetween0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.between("integerValue", 0, 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBetween0003 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0093
     * @tc.desc predicates between normal test
     */
    it('testDataAbilityBetween0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBetween0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.between("longValue", 0, 2);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBetween0004 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0094
     * @tc.desc predicates between normal test
     */
    it('testDataAbilityBetween0005', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBetween0005 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.between("stringValue", "ABB", "ABB");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBetween0005 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0095
     * @tc.desc predicates between normal test
     */
    it('testDataAbilityBetween0006', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBetween0006 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.between("doubleValue", DOUBLE_MAX, DOUBLE_MAX);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBetween0006 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0096
     * @tc.desc predicates between normal test
     */
    it('testDataAbilityBetween0007', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBetween0007 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.between("integerValue", 1, 0);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBetween0007 end *************");
    })

    /**
     * @tc.name predicates between normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0097
     * @tc.desc predicates between normal test
     */
    it('testDataAbilityBetween0008', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBetween0008 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.between("longValue", 2, -1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBetween0008 end *************");
    })

    /**
     * @tc.name testNotBetween0001
     * @tc.number I4JWCV
     * @tc.desc test string value with notBetween.
     */
    it('testDataAbilityNotBetween0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotBetween0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notBetween("stringValue", "ABB", "ABD");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotBetween0001 end *************");
    })

    /**
     * @tc.name testNotBetween0002
     * @tc.number I4JWCV
     * @tc.desc test double value with notBetween.
     */
    it('testDataAbilityNotBetween0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotBetween0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notBetween("doubleValue", 0.0, DOUBLE_MAX);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(0).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotBetween0002 end *************");
    })

    /**
     * @tc.name testNotBetween0003
     * @tc.number I4JWCV
     * @tc.desc test integer value with notBetween.
     */
    it('testDataAbilityNotBetween0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotBetween0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notBetween("integerValue", 0, 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotBetween0003 end *************");
    })

    /**
     * @tc.name testNotBetween0004
     * @tc.number I4JWCV
     * @tc.desc test long value with notBetween.
     */
    it('testDataAbilityNotBetween0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotBetween0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.notBetween("longValue", 0, 2);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityNotBetween0004 end *************");
    })

    /**
     * @tc.name testGlob0001
     * @tc.number I4JWCV
     * @tc.desc end with ? by glob.
     */
    it('testDataAbilityGlob0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGlob0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.glob("stringValue", "ABC*");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGlob0001 end *************");
    })

    /**
     * @tc.name testGlob0002
     * @tc.number I4JWCV
     * @tc.desc begin with * by glob.
     */
    it('testDataAbilityGlob0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGlob0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.glob("stringValue", "*LMN");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGlob0002 end *************");
    })

    /**
     * @tc.name testGlob0003
     * @tc.number I4JWCV
     * @tc.desc end with ? by glob.
     */
    it('testDataAbilityGlob0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGlob0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.glob("stringValue", "ABCDEFGHIJKLM?");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGlob0003 end *************");
    })

    /**
     * @tc.name testGlob0004
     * @tc.number I4JWCV
     * @tc.desc begin with ? by glob.
     */
    it('testDataAbilityGlob0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGlob0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.glob("stringValue", "?BCDEFGHIJKLMN");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGlob0004 end *************");
    })

    /**
     * @tc.name testGlob0005
     * @tc.number I4JWCV
     * @tc.desc begin and end with * by glob.
     */
    it('testDataAbilityGlob0005', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGlob0005 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.glob("stringValue", "*FGHI*");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGlob0005 end *************");
    })

    /**
     * @tc.name testGlob0006
     * @tc.number I4JWCV
     * @tc.desc begin and end with ? by glob.
     */
    it('testDataAbilityGlob0006', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGlob0006 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.glob("stringValue", "?BCDEFGHIJKLM?");
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            result.close();
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityGlob0006 end *************");
    })

    /**
     * @tc.name predicates contains normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0100
     * @tc.desc predicates contains normal test
     */
    it('testDataAbilityContains0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityContains0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.contains("stringValue", "DEF");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityContains0001 end *************");
    })

    /**
     * @tc.name predicates contains normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0101
     * @tc.desc predicates contains normal test
     */
    it('testDataAbilityContains0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityContains0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.contains("stringValue", "DEFX");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityContains0002 end *************");
    })

    /**
     * @tc.name predicates contains normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0102
     * @tc.desc predicates contains normal test
     */
    it('testDataAbilityContains0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityContains0003 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.contains("characterValue", "中");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityContains0003 end *************");
    })

    /**
     * @tc.name predicates contains normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0103
     * @tc.desc predicates contains normal test
     */
    it('testDataAbilityContains0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityContains0004 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.contains("characterValue", "#");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityContains0004 end *************");
    })

    /**
     * @tc.name predicates beginsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0110
     * @tc.desc predicates beginsWith normal test
     */
    it('testDataAbilityBeginsWith0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBeginsWith0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.beginsWith("stringValue", "ABC");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityBeginsWith0001 end *************");
    })

    /**
     * @tc.name predicates beginsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0111
     * @tc.desc predicates beginsWith normal test
     */
    it('testDataAbilityBeginsWith0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBeginsWith0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.beginsWith("stringValue", "ABCX");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityBeginsWith0002 end *************");
    })

    /**
     * @tc.name predicates beginsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0112
     * @tc.desc predicates beginsWith normal test
     */
    it('testDataAbilityBeginsWith0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBeginsWith0003 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.beginsWith("characterValue", "中");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityBeginsWith0003 end *************");
    })

    /**
     * @tc.name predicates beginsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0113
     * @tc.desc predicates beginsWith normal test
     */
    it('testDataAbilityBeginsWith0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBeginsWith0004 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.beginsWith("characterValue", "#");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityBeginsWith0004 end *************");
    })

    /**
     * @tc.name predicates endsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0120
     * @tc.desc predicates endsWith normal test
     */
    it('testDataAbilityEndsWith0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEndsWith0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.endsWith("stringValue", "LMN");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityEndsWith0001 end *************");
    })

    /**
     * @tc.name predicates endsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0121
     * @tc.desc predicates endsWith normal test
     */
    it('testDataAbilityEndsWith0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEndsWith0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.endsWith("stringValue", "LMNX");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityEndsWith0002 end *************");
    })

    /**
     * @tc.name predicates endsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0122
     * @tc.desc predicates endsWith normal test
     */
    it('testDataAbilityEndsWith0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEndsWith0003 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.endsWith("characterValue", "中");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityEndsWith0003 end *************");
    })

    /**
     * @tc.name predicates endsWith normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0123
     * @tc.desc predicates endsWith normal test
     */
    it('testDataAbilityEndsWith0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityEndsWith0004 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.endsWith("characterValue", "#");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityEndsWith0004 end *************");
    })

    /**
     * @tc.name predicates like normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0130
     * @tc.desc predicates like normal test
     */
    it('testDataAbilityLike0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLike0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "%LMN%");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLike0001 end *************");
    })

    /**
     * @tc.name predicates like normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0130
     * @tc.desc predicates like normal test
     */
    it('testDataAbilityLike0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLike0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "%LMNX%");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLike0002 end *************");
    })

    /**
     * @tc.name predicates like normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0132
     * @tc.desc predicates like normal test
     */
    it('testDataAbilityLike0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLike0003 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("characterValue", "%中%");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLike0003 end *************");
    })

    /**
     * @tc.name predicates like normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0133
     * @tc.desc predicates like normal test
     */
    it('testDataAbilityLike0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLike0004 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("characterValue", "%#%");
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLike0004 end *************");
    })

    /**
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0140
     * @tc.desc predicates beginWrap normal test
     */
    it('testDataAbilityBeginWrap0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBeginWrap0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
                .beginWrap()
                .equalTo("integerValue", 1)
                .or()
                .equalTo("integerValue", 2147483647)
                .endWrap();
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBeginWrap0001 end *************");
    })

    /**
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0141
     * @tc.desc predicates beginWrap normal test
     */
    it('testDataAbilityBeginWrap0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBeginWrap0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
                .beginWrap()
                .equalTo("characterValue", ' ')
                .endWrap();
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBeginWrap0002 end *************");
    })

    /**
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0142
     * @tc.desc predicates beginWrap normal test
     */
    it('testDataAbilityBeginWrap0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBeginWrap0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
                .beginWrap()
                .equalTo("characterValue", '中')
                .endWrap();
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBeginWrap0003 end *************");
    })

    /**
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0143
     * @tc.desc predicates beginWrap normal test
     */
    it('testDataAbilityBeginWrap0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBeginWrap0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
                .equalTo("characterValue", '中')
                .endWrap();
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(-1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBeginWrap0004 end *************");
    })

    /**
     * @tc.name predicates beginWrap normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0144
     * @tc.desc predicates beginWrap normal test
     */
    it('testDataAbilityBeginWrap0005', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityBeginWrap0005 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
                .beginWrap()
                .equalTo("characterValue", '中');
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(-1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityBeginWrap0005 end *************");
    })

    /**
     * @tc.name predicates and normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0150
     * @tc.desc predicates and normal test
     */
    it('testDataAbilityAnd0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityAnd0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
                .and()
                .equalTo("integerValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityAnd0001 end *************");
    })

    /**
     * @tc.name predicates or normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0151
     * @tc.desc predicates or normal test
     */
    it('testDataAbilityAnd0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityAnd0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN")
                .beginWrap()
                .equalTo("integerValue", 1)
                .or()
                .equalTo("integerValue", 2147483647)
                .endWrap();
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(2).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityAnd0002 end *************");
    })

    /**
     * @tc.name predicates and normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0152
     * @tc.desc predicates and normal test
     */
    it('testDataAbilityAnd0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityAnd0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN").or().and().equalTo("integerValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            console.log(TAG + "you should not start a request" + " with \"and\" or use or() before this function");
        }
        done();
        console.log(TAG + "************* testDataAbilityAnd0003 end *************");
    })

    /**
     * @tc.name predicates and normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0153
     * @tc.desc predicates and normal test
     */
    it('testDataAbilityAnd0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityAnd0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN").or().or().equalTo("integerValue", 1);
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            console.log(TAG + "you are starting a sql request with predicate or or,"
            + "using function or() immediately after another or(). that is ridiculous.");
        }
        done();
        console.log(TAG + "************* testDataAbilityAnd0004 end *************");
    })

    /**
     * @tc.name predicates order normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0160
     * @tc.desc predicates order normal test
     */
    it('testDataAbilityOrder0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityOrder0001 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByAsc("integerValue").distinct();
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            expect(true).assertEqual(result.goToFirstRow())
            expect(3).assertEqual(result.getLong(0));
            expect(true).assertEqual(result.goToNextRow())
            expect(2).assertEqual(result.getLong(0));
            expect(true).assertEqual(result.goToNextRow())
            expect(1).assertEqual(result.getLong(0));
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityOrder0001 end *************");
    })

    /**
     * @tc.name predicates order normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0161
     * @tc.desc predicates order normal test
     */
    it('testDataAbilityOrder0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityOrder0002 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByDesc("integerValue").distinct();
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(3).assertEqual(result.rowCount);
            expect(true).assertEqual(result.goToFirstRow())
            expect(1).assertEqual(result.getLong(0));
            expect(true).assertEqual(result.goToNextRow())
            expect(2).assertEqual(result.getLong(0));
            expect(true).assertEqual(result.goToNextRow())
            expect(3).assertEqual(result.getLong(0));
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityOrder0002 end *************");
    })

    /**
     * @tc.name predicates order normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0162
     * @tc.desc predicates order normal test
     */
    it('testDataAbilityOrder0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityOrder0003 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByDesc("integerValueX").distinct();
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(-1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityOrder0003 end *************");
    })

    /**
     * @tc.name predicates order normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0163
     * @tc.desc predicates order normal test
     */
    it('testDataAbilityOrder0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityOrder0004 start *************");
        {
            let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
            dataAbilityPredicates.equalTo("stringValue", "ABCDEFGHIJKLMN").orderByAsc("integerValueX").distinct();
            let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

            let result = await rdbStore.query(predicates);
            expect(-1).assertEqual(result.rowCount);
            result = null
        }
        done();
        console.log(TAG + "************* testDataAbilityOrder0004 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0170
     * @tc.desc predicates limit normal test
     */
    it('testDataAbilityLimit0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLimit0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(1);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLimit0001 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0171
     * @tc.desc predicates limit normal test
     */
    it('testDataAbilityLimit0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLimit0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLimit0002 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0172
     * @tc.desc predicates limit normal test
     */
    it('testDataAbilityLimit0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLimit0003 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(100);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLimit0003 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0173
     * @tc.desc predicates limit normal test
     */
    it('testDataAbilityLimit0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLimit0004 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "中").limitAs(1);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLimit0004 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0174
     * @tc.desc predicates limit normal test
     */
    it('testDataAbilityLimit0005', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLimit0005 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(0);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLimit0005 end *************");
    })

    /**
     * @tc.name predicates limit normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0175
     * @tc.desc predicates limit normal test
     */
    it('testDataAbilityLimit0006', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityLimit0006 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(-1);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityLimit0006 end *************");
    })

    /**
     * @tc.name predicates offset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0180
     * @tc.desc predicates offset normal test
     */
    it('testDataAbilityOffset0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityOffset0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(1);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(2).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityOffset0001 end *************");
    })

    /**
     * @tc.name predicates offset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0181
     * @tc.desc predicates offset normal test
     */
    it('testDataAbilityOffset0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityOffset0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(0);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityOffset0002 end *************");
    })

    /**
     * @tc.name predicates offset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0182
     * @tc.desc predicates offset normal test
     */
    it('testDataAbilityOffset0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityOffset0003 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(5);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(0).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityOffset0003 end *************");
    })

    /**
     * @tc.name predicates offset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0183
     * @tc.desc predicates offset normal test
     */
    it('testDataAbilityOffset0004', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityOffset0004 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").limitAs(3).offsetAs(-1);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityOffset0004 end *************");
    })

    /**
     * @tc.name predicates constructor test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0200
     * @tc.desc predicates constructor test
     */
    it('testDataAbilityCreate0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityCreate0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        done();
        console.log(TAG + "************* testDataAbilityCreate0001 end *************");
    })

    /**
     * @tc.name predicates constructor test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0201
     * @tc.desc predicates constructor test
     */
    it('testDataAbilityCreate0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityCreate0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        let predicates = dataAbility.createRdbPredicates("test", dataAbilityPredicates);
        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        done();
        console.log(TAG + "************* testDataAbilityCreate0002 end *************");
    })


    /**
     * @tc.name predicates groupBy test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0210
     * @tc.desc predicates groupBy test
     */
    it('testDataAbilityGroupBy0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGroupBy0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").groupBy(["characterValue"]);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityGroupBy0001 end *************");
    })

    /**
     * @tc.name predicates groupBy test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0211
     * @tc.desc predicates groupBy test
     */
    it('testDataAbilityGroupBy0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityGroupBy0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").groupBy(["characterValueX"]);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(-1).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityGroupBy0002 end *************");
    })

    /**
     * @tc.name predicates indexedBy test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0220
     * @tc.desc predicates indexedBy test
     */
    it('testDataAbilityIndexedBy0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIndexedBy0001 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").indexedBy(["characterValue"]);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIndexedBy0001 end *************");
    })

    /**
     * @tc.name predicates indexedBy test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_DataAbilityPredicates_0221
     * @tc.desc predicates indexedBy test
     */
    it('testDataAbilityIndexedBy0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityIndexedBy0002 start *************");
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.like("stringValue", "ABCDEFGHIJKLMN").indexedBy(["characterValueX"]);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);
        let result = await rdbStore.query(predicates);
        expect(3).assertEqual(result.rowCount);
        result = null
        done();
        console.log(TAG + "************* testDataAbilityIndexedBy0002 end *************");
    })

    /**
     * @tc.name testNotIn0001
     * @tc.number I4JWCV
     * @tc.desc the common and min value test with notin.
     */
    it('testDataAbilityNotIn0001', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotIn0001 start *************");
        var values = [1, -2147483648];
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.notIn("integerValue", values);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testDataAbilityNotIn0001 end *************");
    })

    /**
     * @tc.name testNotIn0002
     * @tc.number I4JWCV
     * @tc.desc the common and max value test with notin.
     */
    it('testDataAbilityNotIn0002', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotIn0002 start *************");
        let values = [1, 2147483647];
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.notIn("integerValue", values);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testDataAbilityNotIn0002 end *************");
    })

    /**
     * @tc.name testNotIn0003
     * @tc.number I4JWCV
     * @tc.desc the min and max value test with notin.
     */
    it('testDataAbilityNotIn0003', 0, async function (done) {
        console.log(TAG + "************* testDataAbilityNotIn0003 start *************");
        var values = [-2147483648, 2147483647];
        let dataAbilityPredicates = await new dataAbility.DataAbilityPredicates();
        dataAbilityPredicates.notIn("integerValue", values);
        let predicates = dataAbility.createRdbPredicates("AllDataType", dataAbilityPredicates);

        let result = await rdbStore.query(predicates);
        expect(1).assertEqual(result.rowCount);
        result.close();
        done();
        console.log(TAG + "************* testDataAbilityNotIn0003 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");
})