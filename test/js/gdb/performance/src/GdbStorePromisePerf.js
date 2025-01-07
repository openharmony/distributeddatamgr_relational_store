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

const TAG = "[GDBSTORE_PROMISE]";
const CREATE_GRAPH_TEST =
    "CREATE GRAPH test {(person:Person {name STRING, age INT}), (person) -[:FRIEND]-> (person)};";
const DB_NAME = "gdbStorePromise";
const STORE_CONFIG = {
    name: DB_NAME,
    securityLevel: graphStore.SecurityLevel.S1
}
let context = featureAbility.getContext();
let store;
const BASE_COUNT = 1000; // loop times
const BASE_LINE_TABLE = 2500; // callback tablet base line
const BASE_LINE_PHONE = 3000; // callback phone base line
const BASE_LINE = (deviceInfo.deviceType == "tablet") ? BASE_LINE_TABLE : BASE_LINE_PHONE;

describe('gdbStorePromisePerf', () => {
    beforeAll(async () => {
        console.info(TAG + 'beforeAll');
        await graphStore.deleteStore(context, STORE_CONFIG);
        store = await graphStore.getStore(context, STORE_CONFIG);
    })
    beforeEach(async () => {
        console.info(TAG + 'beforeEach');
        await store.write(CREATE_GRAPH_TEST);
    })
    afterEach(async () => {
        console.info(TAG + 'afterEach');
        await store.write("DROP GRAPH test");
    })
    afterAll(async () => {
        console.info(TAG + 'afterAll');
        store.close();
        await graphStore.deleteStore(context, STORE_CONFIG);
    })

    console.log(TAG + "*************Unit Test Begin*************");

    it('SUB_DDM_PERF_GDB_write_Promise_001', 0, async () => {
        console.info(TAG + "************* testPerfGdbWritePromise001 start *************");
        let averageTime = 0;
        let startTime = new Date().getTime();
        for (let i = 0; i < BASE_COUNT; i++) {
            let INSERT = "INSERT (:Person {name: 'name_" + (i + 1) + "', age:" + (i + 1) + "});";
            await store.write(INSERT);
        }
        let endTime = new Date().getTime();
        averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(TAG + " the write_INSERT_Promise average time is: " + averageTime + " μs");
        expect(averageTime < BASE_LINE).assertTrue();
        console.info(TAG + "************* testPerfGdbWritePromise001 end *************");
    })

    it('SUB_DDM_PERF_GDB_write_Promise_002', 0, async () => {
        console.info(TAG + "************* testPerfGdbWritePromise002 start *************");
        for (let i = 0; i < BASE_COUNT; i++) {
            let INSERT = "INSERT (:Person {name: 'name_" + (i + 1) + "', age:" + (i + 1) + "});";
            await store.write(INSERT);
        }
        let averageTime = 0;
        let startTime = new Date().getTime();
        for (let i = 0; i < BASE_COUNT; i++) {
            let UPDATE = "MATCH (:Person {name: 'name_" + (i + 1) + "' }) SET n.age = " + (i + 2) + ";";
            await store.write(UPDATE);
        }
        let endTime = new Date().getTime();
        averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(TAG + " the write_MATCH_SET_Promise average time is: " + averageTime + " μs");
        expect(averageTime < BASE_LINE).assertTrue();
        console.info(TAG + "************* testPerfGdbWritePromise002 end *************");
    })

    it('SUB_DDM_PERF_GDB_write_Promise_003', 0, async () => {
        console.info(TAG + "************* testPerfGdbWritePromise003 start *************");
        for (let i = 0; i < BASE_COUNT; i++) {
            let INSERT = "INSERT (:Person {name: 'name_" + (i + 1) + "', age:" + (i + 1) + "});";
            await store.write(INSERT);
        }
        let averageTime = 0;
        let startTime = new Date().getTime();
        for (let i = 0; i < BASE_COUNT; i++) {
            let DELETE = "MATCH (n:Person {name: 'name_" + (i + 1) + "' }) DETACH DELETE n;";
            await store.write(DELETE);
        }
        let endTime = new Date().getTime();
        averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(TAG + " the write_MATCH_DELETE_Promise average time is: " + averageTime + " μs");
        expect(averageTime < BASE_LINE).assertTrue();
        console.info(TAG + "************* testPerfGdbWritePromise003 end *************");
    })

    it('SUB_DDM_PERF_GDB_read_Promise_001', 0, async () => {
        console.info(TAG + "************* testPerfGdbReadPromise001 start *************");
        for (let i = 0; i < BASE_COUNT; i++) {
            let INSERT = "INSERT (:Person {name: 'name_" + (i + 1) + "', age:" + (i + 1) + "});";
            await store.write(INSERT);
        }
        let averageTime = 0;
        let startTime = new Date().getTime();
        for (let i = 0; i < BASE_COUNT; i++) {
            let QUERY = "MATCH (n:Person {name: 'name_" + (i + 1) + "' }) RETURN n;";
            await store.read(QUERY);
        }
        let endTime = new Date().getTime();
        averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(TAG + " the read_Query_Vertex_Promise average time is: " + averageTime + " μs");
        expect(averageTime < BASE_LINE).assertTrue();
        console.info(TAG + "************* testPerfGdbReadPromise001 end *************");
    })
    console.info(TAG + "*************Unit Test End*************")
})