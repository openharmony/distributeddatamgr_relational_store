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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, Assert } from 'deccjsunit/index';
import dataRdb from '@ohos.data.rdb';
import featureAbility from '@ohos.ability.featureAbility';
import deviceInfo from '@ohos.deviceInfo';

const TAG = "[RDB_QUERY_CALLBACK]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
+ "name TEXT, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const dbName = "rdbquerycallback.db"
const STORE_CONFIG = {
    name: dbName,
}
let context = featureAbility.getContext();
var rdbStore = undefined;

const base_count = 1000 // loop times
const base_line_tablet = 1800 // callback tablet base line
const base_line_phone = 7000 // callback phone base line
let baseLineCallback


    describe('queryCallback', function () {
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
            await rdbStore.insert("test", valueBucket);
        }

        console.log(TAG + "*************Unit Test Begin*************");

        it('SUB_DDM_PERF_RDB_query_Callback_001', 0, async function (done) {
            let averageTime = 0;
            let predicates = new dataRdb.RdbPredicates("test")
            predicates.equalTo("age", 10);
            QueryPromisePerTest(0)

            async function QueryPromisePerTest(index) {
                let startTime = new Date().getTime()
                rdbStore.query(predicates, [], function (err, resultSet) {
                    resultSet.goToFirstRow()
                    let endTime = new Date().getTime()
                    averageTime += (endTime - startTime)
                    if (index < base_count) {
                        QueryPromisePerTest(index + 1)
                    } else {
                        averageTime = (averageTime * 1000) / base_count
                        console.info(TAG + " the query_Callback average time is: " + averageTime + " μs")
                        expect(averageTime < baseLineCallback).assertTrue()
                        console.info(TAG + "*************Unit Test End*************")
                        done()
                    }
                })
            }
        })

        it('SUB_DDM_PERF_RDB_insert_Callback_001', 0, async function (done) {
            let averageTime = 0;
            var uBlob = new Uint8Array([1,2,3])
            var insertValueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType" : uBlob,
            }
            let predicates = new dataRdb.RdbPredicates("test")
            predicates.equalTo("age", 10);
            InsertCallbackTest(0)

            async function InsertCallbackTest(index) {
                let startTime = new Date().getTime()
                rdbStore.insert("test", insertValueBucket, function (err, data) {
                    let endTime = new Date().getTime()
                    averageTime += (endTime - startTime)
                    if (index < 100) {
                        InsertCallbackTest(index + 1)
                    } else {
                        averageTime = (averageTime * 1000) / 100
                        console.info(TAG + " the insert_Callback average time is: " + averageTime + " μs")
                        expect(averageTime < baseLineCallback).assertTrue()
                        done()
                    }
                })
            }
        })
    })