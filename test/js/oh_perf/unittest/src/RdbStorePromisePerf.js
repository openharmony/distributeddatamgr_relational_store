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

const TAG = "[RDB_QUERY_PROMISE]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
+ "name TEXT, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const dbName = "rdbquerypromise.db"
const STORE_CONFIG = {
    name: dbName,
}
let context = featureAbility.getContext();
var rdbStore = undefined;

const base_count = 1000 // loop times
const base_line_tablet = 1800 // callback tablet base line
const base_line_phone = 2200 // callback phone base line
let baseLineCallback


describe('queryPromise', function () {
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
        var u8 = new Uint8Array([1, 2, 3])
        var valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await dataRdb.insert("test", valueBucket);
    }

    console.log(TAG + "*************Unit Test Begin*************");

    it('SUB_DDM_PERF_RDB_query_Promise_001', 0, async function (done) {
        let averageTime = 0;
        let predicates = new dataRdb.RdbPredicates("test")
        predicates.equalTo("age", 10);

        for (var i = 0; i < base_count; i++) {
            let startTime = new Date().getTime()
            await rdbStore.query(predicates, [])
            let endTime = new Date().getTime()
            averageTime += (endTime - startTime)
        }
        averageTime = (averageTime * 1000) / base_count
        console.info(TAG + " the average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        console.info(TAG + "*************Unit Test End*************")
        done()
    })
})
