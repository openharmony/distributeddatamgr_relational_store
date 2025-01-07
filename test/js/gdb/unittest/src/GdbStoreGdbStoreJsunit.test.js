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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import graphStore from '@ohos.data.graphStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[GRAPH_STORE_JSKITS_TEST]";
const context = ability_featureAbility.getContext();
const CREATE_GRAPH_TEST = "CREATE GRAPH test {(person:Person {name STRING, age INT}), (person) -[:Friend]-> (person)};"
const STORE_CONFIG = {
    name: "graphstore",
    securityLevel: graphStore.SecurityLevel.S1,
};

describe('graphStoreTest', () => {
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
        await graphStore.deleteStore(context, STORE_CONFIG);
    })

    console.info(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0001
     * @tc.desc graph store getStore test
     */
    it('testGraphStore0001', 0, async () => {
        console.info(TAG + "************* testGraphStore0001 start *************");
        try {
            let store = await graphStore.getStore(context, STORE_CONFIG);
            await store.close();
            await graphStore.deleteStore(context, STORE_CONFIG);
        } catch (e) {
            console.error(TAG + "graphStore test_1 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStore0001 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0002
     * @tc.desc graph store getStore and write
     */
    it('testGraphStore0002', 0, async () => {
        console.info(TAG + "************* testGraphStore0002 start *************");
        try {
            let store = await graphStore.getStore(context, STORE_CONFIG);
            await store.write(CREATE_GRAPH_TEST);
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("DROP GRAPH test");
            await store.close();
            await graphStore.deleteStore(context, STORE_CONFIG);
        } catch (e) {
            console.error(TAG + "graphStore test_2 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStore0002 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0003
     * @tc.desc graph store getStore with wrong storeConfig name
     */
    it('testGraphStore0003', 0, async () => {
        console.info(TAG + "************* testGraphStore0003 start *************");
        let storeConfig = {
            name: "/wrong/graphstore",
            securityLevel: graphStore.SecurityLevel.S1,
        };
        try {
            let store = await graphStore.getStore(context, storeConfig);
            await store.write(CREATE_GRAPH_TEST);
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("DROP GRAPH test");
            await store.close();
            await graphStore.deleteStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            expect('401').assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStore0003 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0004
     * @tc.desc graph store getStore with securityLevel
     */
    it('testGraphStore0004', 0, async () => {
        console.info(TAG + "************* testGraphStore0004 start *************");
        let storeConfig = {
            name: "secure",
            securityLevel: graphStore.SecurityLevel.S3,
        };
        try {
            let store = await graphStore.getStore(context, storeConfig);
            await store.write(CREATE_GRAPH_TEST);
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("DROP GRAPH test");
            await store.close();
            await graphStore.deleteStore(context, storeConfig);
        } catch (e) {
            console.error(TAG + "graphStore test_4 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStore0004 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0005
     * @tc.desc graph store getStore with invalid securityLevel
     */
    it('testGraphStore0005', 0, async () => {
        console.info(TAG + "************* testGraphStore0005 start *************");
        let storeConfig = {
            name: "secure",
            securityLevel: 0,
        };
        try {
            //expect getStore failed
            let store = await graphStore.getStore(context, storeConfig);
            await store.write(CREATE_GRAPH_TEST);
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("DROP GRAPH test");
            await store.close();
            await graphStore.deleteStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            expect(401).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStore0005 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0006
     * @tc.desc graph store getStore with 1 param
     */
    it('testGraphStore0006', 0, async () => {
        console.info(TAG + "************* testGraphStore0006 start *************");
        try {
            //expect getStore failed
            let store = await graphStore.getStore(STORE_CONFIG);
            expect().assertFail();
        } catch (e) {
            expect(401).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStore0006 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0007
     * @tc.desc graph store getStore name has db Suffix
     */
    it('testGraphStore0007', 0, async () => {
        console.info(TAG + "************* testGraphStore0007 start *************");
        let storeConfig = {
            name: "suffix.db",
            securityLevel: graphStore.SecurityLevel.S1,
        }
        try {
            // expect get store failed
            let store = await graphStore.getStore(context, storeConfig);
            await store.write(CREATE_GRAPH_TEST);
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("DROP GRAPH test");
            await store.close();
            await graphStore.deleteStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            expect(31300000).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStore0007 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0008
     * @tc.desc graph store getStore with null storeConfig name
     */
    it('testGraphStore0008', 0, async () => {
        console.info(TAG + "************* testGraphStore0008 start *************");
        let storeConfig = {
            securityLevel: graphStore.SecurityLevel.S1,
        }
        try {
            // expect get store failed
            let store = await graphStore.getStore(context, storeConfig);
            await store.write(CREATE_GRAPH_TEST);
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("DROP GRAPH test");
            await store.close();
            await graphStore.deleteStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            expect(401).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStore0008 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0009
     * @tc.desc graph store getStore name has special characters
     */
    it('testGraphStore0009', 0, async () => {
        console.info(TAG + "************* testGraphStore0009 start *************");
        let storeConfig = {
            name: "char*@#!(.&",
            securityLevel: graphStore.SecurityLevel.S1,
        }
        try {
            // expect get store failed
            let store = await graphStore.getStore(context, storeConfig);
            await store.write(CREATE_GRAPH_TEST);
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("DROP GRAPH test");
            await store.close();
            await graphStore.deleteStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            expect(31300000).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStore0009 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0010
     * @tc.desc graph store getStore SecurityLevel S2->S1
     */
    it('testGraphStore0010', 0, async () => {
        console.info(TAG + "************* testGraphStore0010 start *************");
        let storeConfig = {
            name: "graphstore",
            securityLevel: graphStore.SecurityLevel.S2,
        }
        try {
            let store = await graphStore.getStore(context, storeConfig);
            await store.close();
            store = await graphStore.getStore(context, STORE_CONFIG);
            expect().assertFail();
        } catch (e) {
            expect(401).assertEqual(e.code);
        }
        await graphStore.deleteStore(context, storeConfig);
        console.info(TAG + "************* testGraphStore0010 end *************");
    })

    /**
     * @tc.name graph store getStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0011
     * @tc.desc graph store getStore SecurityLevel S1->S2
     */
    it('testGraphStore0011', 0, async () => {
        console.info(TAG + "************* testGraphStore0011 start *************");
        let storeConfig = {
            name: "graphstore",
            securityLevel: graphStore.SecurityLevel.S2,
        }
        try {
            let store = await graphStore.getStore(context, STORE_CONFIG);
            await store.close();
            store = await graphStore.getStore(context, storeConfig);
            await store.close();
            await graphStore.deleteStore(context, storeConfig);
        } catch (e) {
            console.error(TAG + "graphStore test_11 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStore0011 end *************");
    })

    /**
     * @tc.name graph store deleteStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0012
     * @tc.desc graph store deleteStore test
     */
    it('testGraphStore0012', 0, async () => {
        console.info(TAG + "************* testGraphStore0012 start *************");
        let store = await graphStore.getStore(context, STORE_CONFIG);
        await store.write(CREATE_GRAPH_TEST);
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("DROP GRAPH test");
        await store.close();
        try {
            await graphStore.deleteStore(context, STORE_CONFIG);
        } catch (e) {
            console.error(TAG + "graphStore test_12 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStore0012 end *************");
    })

    /**
     * @tc.name graph store deleteStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0013
     * @tc.desc graph store deleteStore with wrong store name
     */
    it('testGraphStore0013', 0, async () => {
        console.info(TAG + "************* testGraphStore0013 start *************");
        let storeConfig = {
            name: "/wrong/graphstore",
            securityLevel: graphStore.SecurityLevel.S1,
        }
        let store = await graphStore.getStore(context, STORE_CONFIG);
        await store.write(CREATE_GRAPH_TEST);
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("DROP GRAPH test");
        await store.close();
        try {
            await graphStore.deleteStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            expect('401').assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStore0013 end *************");
    })

    /**
     * @tc.name graph store deleteStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0014
     * @tc.desc graph store deleteStore with different store name
     */
    it('testGraphStore0014', 0, async () => {
        console.info(TAG + "************* testGraphStore0014 start *************");
        let storeConfig = {
            name: "teststore",
            securityLevel: graphStore.SecurityLevel.S1,
        }
        let store = await graphStore.getStore(context, STORE_CONFIG);
        await store.write(CREATE_GRAPH_TEST);
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("DROP GRAPH test");
        await store.close();
        try {
            // delete success
            await graphStore.deleteStore(context, storeConfig);
        } catch (e) {
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStore0014 end *************");
    })

    /**
     * @tc.name graph store deleteStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0015
     * @tc.desc graph store deleteStore with different securityLevel
     */
    it('testGraphStore0015', 0, async () => {
        console.info(TAG + "************* testGraphStore0015 start *************");
        let storeConfig = {
            name: "graphstore",
            securityLevel: graphStore.SecurityLevel.S4,
        }
        let store = await graphStore.getStore(context, STORE_CONFIG);
        await store.write(CREATE_GRAPH_TEST);
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("DROP GRAPH test");
        await store.close();
        try {
            // delete success
            await graphStore.deleteStore(context, storeConfig);
        } catch (e) {
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStore0015 end *************");
    })

    /**
     * @tc.name graph store deleteStore test
     * @tc.number GdbStoreGdbStoreJsunitTest0016
     * @tc.desc graph store deleteStore with 1 param
     */
    it('testGraphStore0016', 0, async () => {
        console.info(TAG + "************* testGraphStore0016 start *************");
        let store = await graphStore.getStore(context, STORE_CONFIG);
        await store.write(CREATE_GRAPH_TEST);
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("DROP GRAPH test");
        await store.close();
        try {
            await graphStore.deleteStore(context);
            expect().assertFail();
        } catch (e) {
            expect(401).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStore0016 end *************");
    })

    console.info(TAG + "*************Unit Test End*************");
})
