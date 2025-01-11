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
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"

var storeConfig = {
    name: "PluginLibsTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    pluginLibs: []
}

var rdbStore = undefined;

describe('rdbStorePluginLibsTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "PluginLibsTest.db");
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
    })

    /**
     * @tc.name TEST_PLUGIN_LIBS_0001
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_plugin_Libs_0001
     * @tc.desc Test pluginLibs are empty
     */
    it('testPluginLibs0001', 0, async function () {
        console.log(TAG + "************* testPluginLibs0001 start *************");
        try {
            storeConfig.pluginLibs = ["", ""]
            rdbStore = await data_relationalStore.getRdbStore(context, storeConfig);
        } catch (e) {
            console.log("getRdbStore err: failed, err: code=" + e.code + " message=" + e.message)
            expect().assertFail();
        }
        console.log(TAG + "************* testPluginLibs0001 end   *************");
    })

    /**
     * @tc.name TEST_PLUGIN_LIBS_0002
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_plugin_Libs_0002
     * @tc.desc Test pluginLib is current path
     */
    it('testPluginLibs0002', 0, async function () {
        console.log(TAG + "************* testPluginLibs0002 start *************");
        try {
            storeConfig.pluginLibs = ["./"]
            rdbStore = await data_relationalStore.getRdbStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            console.log("getRdbStore err: failed, err: code=" + e.code + " message=" + e.message)
            expect(14800021).assertEqual(e.code);
        }
        console.log(TAG + "************* testPluginLibs0002 end   *************");
    })

    /**
     * @tc.name TEST_PLUGIN_LIBS_0003
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_plugin_Libs_0003
     * @tc.desc Test pluginLib is no exist
     */
    it('testPluginLibs0003', 0, async function () {
        console.log(TAG + "************* testPluginLibs0003 start *************");
        try {
            storeConfig.pluginLibs = ["/data/errPath/err.so"]
            rdbStore = await data_relationalStore.getRdbStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            console.log("getRdbStore err: failed, err: code=" + e.code + " message=" + e.message)
            expect(14800010).assertEqual(e.code);
        }
        console.log(TAG + "************* testPluginLibs0003 end   *************");
    })

    /**
     * @tc.name TEST_PLUGIN_LIBS_0004
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_plugin_Libs_0004
     * @tc.desc Test pluginLib as other app path
     */
    it('testPluginLibs0004', 0, async function () {
        console.log(TAG + "************* testPluginLibs0004 start *************");
        try {
            storeConfig.pluginLibs = ["/data/app/el1/bundle/public/"]
            rdbStore = await data_relationalStore.getRdbStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            console.log("getRdbStore err: failed, err: code=" + e.code + " message=" + e.message)
            expect(14800010).assertEqual(e.code);
        }
        console.log(TAG + "************* testPluginLibs0004 end   *************");
    })

    /**
     * @tc.name TEST_PLUGIN_LIBS_0005
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_plugin_Libs_0005
     * @tc.desc Test pluginLib as current app dir
     */
    it('testPluginLibs0005', 0, async function () {
        console.log(TAG + "************* testPluginLibs0005 start *************");
        try {
            let path = await context.getFilesDir();
            storeConfig.pluginLibs = [String(path)]
            rdbStore = await data_relationalStore.getRdbStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            console.log("getRdbStore err: failed, err: code=" + e.code + " message=" + e.message)
            expect(14800021).assertEqual(e.code);
        }
        console.log(TAG + "************* testPluginLibs0005 end   *************");
    })

    /**
     * @tc.name TEST_PLUGIN_LIBS_0006
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_plugin_Libs_0006
     * @tc.desc Test plugin libs count exceeds 16
     */
    it('testPluginLibs0006', 0, async function () {
        console.log(TAG + "************* testPluginLibs0006 start *************");
        try {
            let path = new Array(17).fill("").map((_, index) => `dir${index + 1}`)
            storeConfig.pluginLibs = path
            rdbStore = await data_relationalStore.getRdbStore(context, storeConfig);
            expect().assertFail();
        } catch (e) {
            console.log("getRdbStore err: failed, err: code=" + e.code + " message=" + e.message)
            expect(14800000).assertEqual(e.code);
        }
        console.log(TAG + "************* testPluginLibs0006 end   *************");
    })
    console.log(TAG + "*************Unit Test End*************");
})