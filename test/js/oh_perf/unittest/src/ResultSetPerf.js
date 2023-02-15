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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, Assert } from '@ohos/hypium';
import dataRdb from '@ohos.data.rdb';
import featureAbility from '@ohos.ability.featureAbility';
import deviceInfo from '@ohos.deviceInfo';

const TAG = "[RDB_RESULTSET_PERF]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
+ "name TEXT, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const dbName = "resultsetperf.db"
const STORE_CONFIG = {
    name: dbName,
}
let context = featureAbility.getContext();
var rdbStore = undefined;

const base_count = 2000 // loop times
const base_line_tablet = 500 // callback tablet base line
const base_line_phone = 1000 // callback phone base line
let baseLineCallback


export default function resultSetPerf() {
    describe('resultSetPerf', function () {
        beforeAll(async function () {
            console.info(TAG + 'beforeAll')
            if (deviceInfo.deviceType == "tablet") {
                baseLineCallback = base_line_tablet
            } else {
                baseLineCallback = base_line_phone
            }
            rdbStore = await dataRdb.getRdbStore(context, STORE_CONFIG, 1);
        })
        beforeEach(async function () {
            console.info(TAG + 'beforeEach')
            await rdbStore.executeSql(CREATE_TABLE_TEST, null);
            await prepareTestData();
        })
        afterEach(async function () {
            console.info(TAG + 'afterEach')
            await rdbStore.executeSql("delete from test");
        })
        afterAll(async function () {
            console.info(TAG + 'afterAll')
            rdbStore = null
            await dataRdb.deleteRdbStore(context, dbName);
        })

        async function prepareTestData() {
            console.info(TAG + "prepare for query performance test")
            var u8 = new Uint8Array([1,2,3])
            var valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType" : u8,
            }
            for (let i=0; i<base_count; i++) {
                valueBucket.age += i;
                let num = await rdbStore.insert("test", valueBucket);
                console.info(TAG + " average time prepare data number is : " + num)
            }
        }


        console.log(TAG + "*************Unit Test Begin*************");

        it('SUB_DDM_PERF_RDB_ResultSet_GetColumnIndex_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.getColumnIndex("id");
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GetColumnIndex average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GetColumnName_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.getColumnName(0);
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GetColumnName average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GoTo_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.goTo(1);
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GoTo average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GoToRow_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.goToRow(1);
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GoToRow average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GoToFirstRow_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.goToFirstRow();
                console.info(TAG + " the rowCount average time is: " + resultSet.rowCount)
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GoToFirstRow average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GoToLastRow_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.goToLastRow();
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GoToLastRow average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GoToNextRow_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.goToNextRow();
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GoToNextRow average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GoToNextRow_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            resultSet.goToLastRow();
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.goToPreviousRow();
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GoToNextRow average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GetBlob_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let columnIndex = resultSet.getColumnIndex("blobType");
            resultSet.goToFirstRow();
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.getBlob(columnIndex);
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GetBlob average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GetString_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let columnIndex = resultSet.getColumnIndex("name");
            resultSet.goToFirstRow();
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.getString(columnIndex);
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GetString average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GetLong_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let columnIndex = resultSet.getColumnIndex("age");
            resultSet.goToFirstRow();
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.getLong(columnIndex);
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GetLong average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_GetDouble_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let columnIndex = resultSet.getColumnIndex("salary");
            resultSet.goToFirstRow();
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.getDouble(columnIndex);
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_GetDouble average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_IsColumnNull_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let columnIndex = resultSet.getColumnIndex("salary");
            resultSet.goToFirstRow();
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.IsColumnNull(columnIndex);
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_IsColumnNull average time is: " + averageTime + " μs")
            resultSet.close();
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        it('SUB_DDM_PERF_RDB_ResultSet_Close_001', 0, async function (done) {
            let predicates = new dataRdb.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates);
            let startTime = new Date().getTime()
            for (let index=0; index<base_count; index++) {
                resultSet.close();
            }
            let endTime = new Date().getTime();
            let averageTime = ((endTime - startTime) * 1000) / base_count
            console.info(TAG + " the ResultSet_Close average time is: " + averageTime + " μs")
            expect(averageTime < baseLineCallback).assertTrue()
            done()
        })

        console.info(TAG + "*************Unit Test End*************")
    })
}