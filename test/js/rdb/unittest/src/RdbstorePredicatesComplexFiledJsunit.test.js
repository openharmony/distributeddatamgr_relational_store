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
import dataRdb from '@ohos.data.rdb';

const TAG = "[RDB_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " + "name TEXT, " + "age INTEGER, " + "salary REAL, " + "adddate DATE)";
const STORE_CONFIG = {
    name: "PredicatesComplexFiledJsunit.db",
}
var rdbStore = undefined;

describe('rdbStorePredicatesComplexFiledTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await dataRdb.getRdbStore(STORE_CONFIG, 1);
        await generateTable();
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
        await dataRdb.deleteRdbStore("PredicatesComplexFiledJsunit.db");
    })

    async function generateTable() {
        console.info(TAG + 'generateTable')
        await rdbStore.executeSql(CREATE_TABLE_TEST);
        const valueBucket1 = { id: 1, name: "ZhangSan", age: 20, salary: 100.51, adddate: '2022-09-01' }
        await rdbStore.insert("test", valueBucket1)
        const valueBucket2 = { id: 2, name: "LiSi", age: 21, salary: 120.61, adddate: '2022-09-01' }
        await rdbStore.insert("test", valueBucket2)
        const valueBucket3 = { id: 3, name: "WangWu", age: 22, salary: 130.71, adddate: '2022-09-02' }
        await rdbStore.insert("test", valueBucket3)
        const valueBucket4 = { id: 4, name: "SunLiu", age: 23, salary: 160.81, adddate: '2022-09-02' }
        await rdbStore.insert("test", valueBucket4)
        const valueBucket5 = { id: 5, name: "MaQi", age: 24, salary: 170.91, adddate: '2022-09-02' }
        await rdbStore.insert("test", valueBucket5)
        console.info(TAG + 'generateTable end')
    }

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_ComplexFiled_0001
     * @tc.desc resultSet Update test
     */
    it('testRdbPredicatesComplexFiled0001', 0, async function (done) {
        console.log(TAG + "************* testRdbPredicatesComplexFiled0001 start *************");

        let predicates = await new dataRdb.RdbPredicates("test")
        predicates.groupBy(["DATE(test.adddate)"]).orderByAsc("COUNT(*)")
        let resultSet = await rdbStore.query(predicates, ["COUNT(*) AS 'num count'", "DATE(test.adddate) as birthday"])
        expect(true).assertEqual(resultSet.goToFirstRow())
        let count = await resultSet.getLong(resultSet.getColumnIndex("num count"))
        let birthday = await resultSet.getString(resultSet.getColumnIndex("birthday"))
        expect(2).assertEqual(count);
        await expect("2022-09-01").assertEqual(birthday)
        expect(true).assertEqual(resultSet.goToNextRow())
        count = await resultSet.getLong(resultSet.getColumnIndex("num count"))
        birthday = await resultSet.getString(resultSet.getColumnIndex("birthday"))
        expect(3).assertEqual(count);
        await expect("2022-09-02").assertEqual(birthday)
        expect(false).assertEqual(resultSet.goToNextRow())
        done();
        console.log(TAG + "************* testRdbPredicatesComplexFiled0001 end   *************");
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Predicates_ComplexFiled_0002
     * @tc.desc resultSet Update test
     */
    it('testRdbPredicatesComplexFiled0002', 0, async function (done) {
        console.log(TAG + "************* testRdbPredicatesComplexFiled0002 start *************");

        let predicates = await new dataRdb.RdbPredicates("test")
        predicates.groupBy(["DATE(test.adddate)"]).orderByDesc("COUNT(*)")
        let resultSet = await rdbStore.query(predicates, ["COUNT(*) AS numcount", "DATE(test.adddate) as birthday"])
        expect(true).assertEqual(resultSet.goToFirstRow())
        let count = await resultSet.getLong(resultSet.getColumnIndex("numcount"))
        let birthday = await resultSet.getString(resultSet.getColumnIndex("birthday"))
        expect(3).assertEqual(count);
        await expect("2022-09-02").assertEqual(birthday)
        expect(true).assertEqual(resultSet.goToNextRow())
        count = await resultSet.getLong(resultSet.getColumnIndex("numcount"))
        birthday = await resultSet.getString(resultSet.getColumnIndex("birthday"))
        expect(2).assertEqual(count);
        await expect("2022-09-01").assertEqual(birthday)
        expect(false).assertEqual(resultSet.goToNextRow())
        done();
        console.log(TAG + "************* testRdbPredicatesComplexFiled0002 end   *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})
