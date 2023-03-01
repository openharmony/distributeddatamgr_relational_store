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

const TAG = "[RDB_GETRDBSTORE_PROMISE]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
+ "name TEXT, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const dbName = "rdbcallback.db"
const STORE_CONFIG = {
    name: dbName,
}
let context = featureAbility.getContext();
var rdbStore = undefined;

const base_count = 1000 // loop times
const base_line_tablet = 2500 // callback tablet base line
const base_line_phone = 3000 // callback phone base line
let baseLineCallback


    describe('getRdbStoreCallback', function () {
        beforeAll(async function () {
            console.info(TAG + 'beforeAll')
            if (deviceInfo.deviceType == "tablet") {
                baseLineCallback = base_line_tablet
            } else {
                baseLineCallback = base_line_phone
            }
        })
        beforeEach(async function () {
            console.info(TAG + 'beforeEach')
        })
        afterEach(async function () {
            console.info(TAG + 'afterEach')
        })
        afterAll(async function () {
            console.info(TAG + 'afterAll')
            rdbStore = null
            await dataRdb.deleteRdbStore(context, dbName);
        })

        console.log(TAG + "*************Unit Test Begin*************");

        it('SUB_DDM_PERF_RDB_getRdbStore_Callback_001', 0, async function (done) {
            let averageTime = 0;
            await GetRdbStoreCallBackPerfTest(0);

            async function GetRdbStoreCallBackPerfTest(index) {
                let startTime = new Date().getTime()
                dataRdb.getRdbStore(context, STORE_CONFIG, 1, function (err, rdbStore) {
                    let endTime = new Date().getTime();
                    averageTime += (endTime - startTime)
                    if (index < base_count) {
                        GetRdbStoreCallBackPerfTest(index + 1);
                    } else {
                        averageTime = (averageTime * 1000) / base_count
                        console.info(TAG + " the average time is: " + averageTime + " μs")
                        expect(averageTime < baseLineCallback).assertTrue()
                        done()
                    }
                })
            }
        })

        it('SUB_DDM_PERF_RDB_deleteRdbStore_Callback_001', 0, async function (done) {
            let averageTime = 0;
            await GetRdbStoreCallBackPerfTest(0);

            async function GetRdbStoreCallBackPerfTest(index) {
                let startTime = new Date().getTime()
                dataRdb.deleteRdbStore(context, dbName, function (err, data) {
                    let endTime = new Date().getTime();
                    averageTime += (endTime - startTime)
                    if (index < base_count) {
                        GetRdbStoreCallBackPerfTest(index + 1);
                    } else {
                        averageTime = (averageTime * 1000) / base_count
                        console.info(TAG + " the deleteRdbStore_Callback average time is: " + averageTime + " μs")
                        expect(averageTime < baseLineCallback).assertTrue()
                        done()
                    }
                })
            }
        })
    })