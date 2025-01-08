/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
import graphStore from '@ohos.data.graphStore';
import featureAbility from '@ohos.ability.featureAbility';
import deviceInfo from '@ohos.deviceInfo';

const TAG = "[GDBHELPER_PROMISE]";
const DB_NAME = "gdbPromise";
const STORE_CONFIG = {
    name: DB_NAME,
    securityLevel: graphStore.SecurityLevel.S1
}
let context = featureAbility.getContext();
let store;
const BASE_COUNT = 2000; // loop times
const BASE_LINE_TABLE = 2500; // callback tablet base line
const BASE_LINE_PHONE = 3000; // callback phone base line
const BASE_LINE = (deviceInfo.deviceType == "tablet") ? BASE_LINE_TABLE : BASE_LINE_PHONE;

describe('gdbHelperPromisePerf', () => {
    beforeAll(async () => {
        console.info(TAG + 'beforeAll');
    })
    beforeEach(async () => {
        console.info(TAG + 'beforeEach');
    })
    afterEach(async () => {
        console.info(TAG + 'afterEach');
    })
    afterAll(async () => {
        console.info(TAG + 'afterAll');
        await store.close();
        await graphStore.deleteStore(context, STORE_CONFIG);
    })

    console.log(TAG + "*************Unit Test Begin*************");

    it('Perf_Gdb_GetStore_Promise_001', 0, async () => {
        let averageTime = 0;
        let startTime = new Date().getTime();
        for (let i = 0; i < BASE_COUNT; i++) {
            await graphStore.getStore(context, STORE_CONFIG);
        }
        let endTime = new Date().getTime();
        averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(TAG + " the getStore_Promise average time is: " + averageTime + " μs");
        expect(averageTime < BASE_LINE).assertTrue();
    })

    it('Perf_Gdb_DeleteStore_Promise_001', 0, async () => {
        let averageTime = 0;
        let startTime = new Date().getTime();
        for (let i = 0; i < BASE_COUNT; i++) {
            await graphStore.deleteStore(context, STORE_CONFIG);
        }
        let endTime = new Date().getTime();
        averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(TAG + " the deleteStore_Promise average time is: " + averageTime + " μs");
        expect(averageTime < BASE_LINE).assertTrue();
        console.info(TAG + "*************Unit Test End*************")
    })
})