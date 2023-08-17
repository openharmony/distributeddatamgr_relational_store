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

const TAG = "[RDBHELPER_CALLBACK]";

const DB_NAME = "rdbCallback.db";
const STORE_CONFIG = {
    name: DB_NAME,
}
let context = featureAbility.getContext();
var rdbStore = undefined;
const BASE_COUNT = 2000; // loop times
const BASE_LINE_TABLE = 2500; // callback tablet base line
const BASE_LINE_PHONE = 3000; // callback phone base line
const BASE_LINE = (deviceInfo.deviceType == "tablet" || deviceInfo.deviceType == "2in1") ? BASE_LINE_TABLE : BASE_LINE_PHONE;

describe('rdbHelperCallbackPerf', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll');
    })
    beforeEach(async function () {
        console.info(TAG + 'beforeEach');
    })
    afterEach(async function () {
        console.info(TAG + 'afterEach');
    })
    afterAll(async function () {
        console.info(TAG + 'afterAll');
        rdbStore = null
        await dataRdb.deleteRdbStore(context, DB_NAME);
    })

    console.log(TAG + "*************Unit Test Begin*************");

    it('SUB_DDM_PERF_RDB_getRdbStore_Callback_001', 0, async function (done) {
        let averageTime = 0;

        async function getRdbStoreCallBackPerf(index) {
            dataRdb.getRdbStore(context, STORE_CONFIG, 1, function (err, rdbStore) {
                if (index < BASE_COUNT) {
                    getRdbStoreCallBackPerf(index + 1);
                } else {
                    let endTime = new Date().getTime();
                    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
                    console.info(TAG + " the getRdbStore_Callback average time is: " + averageTime + " μs");
                    expect(averageTime < BASE_LINE).assertTrue();
                    done();
                }
            })
        }

        let startTime = new Date().getTime();
        await getRdbStoreCallBackPerf(0);
    })

    it('SUB_DDM_PERF_RDB_deleteRdbStore_Callback_001', 0, async function (done) {
        let averageTime = 0;

        async function deleteRdbStoreCallBackPerf(index) {
            dataRdb.deleteRdbStore(context, DB_NAME, function (err, data) {
                if (index < BASE_COUNT) {
                    deleteRdbStoreCallBackPerf(index + 1);
                } else {
                    let endTime = new Date().getTime();
                    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
                    console.info(TAG + " the deleteRdbStore_Callback average time is: " + averageTime + " μs");
                    expect(averageTime < BASE_LINE).assertTrue();
                    done();
                }
            })
        }

        let startTime = new Date().getTime();
        await deleteRdbStoreCallBackPerf(0);
    })
})