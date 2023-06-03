/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "data1 text," + "data2 long, " + "data3 double," + "data4 blob, " + "data5 asset, " + "data6 assets )";

const CREATE_TABLE_TEST1 = "CREATE TABLE IF NOT EXISTS test1 (" + "data6 assets )";

const STORE_CONFIG = {
    name: "Asset.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined;

describe('rdbResultSetTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        if (rdbStore == undefined) {
            console.error("beforeall get rdbstore error is undefined")
        } else {
            console.error("beforeall get rdbstore success")
        }
        await rdbStore.executeSql(CREATE_TABLE_TEST);
        await createTest();
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
        await data_relationalStore.deleteRdbStore(context, "Asset.db");
    })

    // insert data
    async function createTest() {
        console.log(TAG + "createTest data start");
        {
            console.error("create test 1 start")
            var u8 = new Uint8Array([1, 2, 3])
            const asset = {
                version: 1,
                name: "name1",
                uri: "uri1",
                createTime: "createTime1",
                modifyTime: "modifyTime1",
                size: "size1",
                hash: "hash1",
            }
            const assets = []
            assets.push(asset)
            const valueBucket = {
                "data1": "hello",
                "data2": 10,
                "data3": 1.0,
                "data4": u8,
                "data5": asset,
                "data6": assets,
            }
            await rdbStore.insert("test", valueBucket)
            console.error("create test 1 end")
        }
        {
            console.error("create test 2 start")
            var u8 = new Uint8Array([3, 4, 5])
            const asset1 = {
                version: 1,
                name: "name1",
                uri: "uri1",
                createTime: "createTime1",
                modifyTime: "modifyTime1",
                size: "size1",
                hash: "hash1",
            }
            const asset2 = {
                version: 2,
                name: "name2",
                uri: "uri2",
                createTime: "createTime2",
                modifyTime: "modifyTime2",
                size: "size2",
                hash: "hash2",
            }
            const assets = []
            assets.push(asset1)
            assets.push(asset2)
            const valueBucket = {
                "data1": "2",
                "data2": -5,
                "data3": 2.5,
                "data4": u8,
                "data5": asset2,
                "data6": assets,
            }
            await rdbStore.insert("test", valueBucket)
            console.error("create test 2 end")
        }
        {
            console.error("create test 3 start")
            var u8 = new Uint8Array(0)
            const valueBucket = {
                "data1": "hello world",
                "data2": 3,
                "data3": 1.8,
                "data4": u8,
            }
            await rdbStore.insert("test", valueBucket)
            console.error("create test 3 end")
        }
        console.log(TAG + "createTest data end");
    }

    /**
     * @tc.name resultSet getAsset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0010
     * @tc.desc resultSet getAsset normal test
     */
    it('testGetAsset0001', 0, async function (done) {
        console.log(TAG + "************* testGetAsset0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data5 = resultSet.getAsset(resultSet.getColumnIndex("data5"))
            console.log(TAG + "id=" + id + ", data5=" + data5);
            expect(1).assertEqual(data5.version);
            expect("name1").assertEqual(data5.name);
            expect("uri1").assertEqual(data5.uri);
            expect("createTime1").assertEqual(data5.createTime);
            expect("modifyTime1").assertEqual(data5.modifyTime);
            expect("size1").assertEqual(data5.size);
            expect("hash1").assertEqual(data5.hash);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testGetAsset0001 end *************");
    })

    /**
     * @tc.name resultSet getAsset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0020
     * @tc.desc resultSet getAsset normal test
     */
    it('testGetAsset0002', 0, async function (done) {
        console.log(TAG + "************* testGetAsset0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data5 = resultSet.getAsset(resultSet.getColumnIndex("data5"))
            console.log(TAG + "id=" + id + ", data5=" + data5);
            expect(2).assertEqual(data5.version);
            expect("name2").assertEqual(data5.name);
            expect("uri2").assertEqual(data5.uri);
            expect("createTime2").assertEqual(data5.createTime);
            expect("modifyTime2").assertEqual(data5.modifyTime);
            expect("size2").assertEqual(data5.size);
            expect("hash2").assertEqual(data5.hash);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testGetAsset0002 end *************");
    })

    /**
     * @tc.name resultSet getAsset normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0030
     * @tc.desc resultSet getAsset normal test
     */
    it('testGetAsset0003', 0, async function (done) {
        console.log(TAG + "************* testGetAsset0003 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data5 = resultSet.getAsset(resultSet.getColumnIndex("data5"))
            console.log(TAG + "id=" + id + ", data5=" + data5);
            expect(0).assertEqual(data5.version);
            expect("").assertEqual(data5.name);
            expect("").assertEqual(data5.uri);
            expect("").assertEqual(data5.createTime);
            expect("").assertEqual(data5.modifyTime);
            expect("").assertEqual(data5.size);
            expect("").assertEqual(data5.hash);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testGetAsset0003 end *************");
    })

    /**
     * @tc.name resultSet getAssets normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0010
     * @tc.desc resultSet getAssets normal test
     */
    it('testGetAssets0001', 0, async function (done) {
        console.log(TAG + "************* testGetAssets0001 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data6 = resultSet.getAssets(resultSet.getColumnIndex("data6"))
            console.log(TAG + "id=" + id + ", data6=" + data6);
            expect(2).assertEqual(data6.length);
            let asset = data6[0];
            expect(1).assertEqual(asset.version);
            expect("name1").assertEqual(asset.name);
            expect("uri1").assertEqual(asset.uri);
            expect("createTime1").assertEqual(asset.createTime);
            expect("modifyTime1").assertEqual(asset.modifyTime);
            expect("size1").assertEqual(asset.size);
            expect("hash1").assertEqual(asset.hash);

            asset = data6[1];
            expect(2).assertEqual(asset.version);
            expect("name2").assertEqual(asset.name);
            expect("uri2").assertEqual(asset.uri);
            expect("createTime2").assertEqual(asset.createTime);
            expect("modifyTime2").assertEqual(asset.modifyTime);
            expect("size2").assertEqual(asset.size);
            expect("hash2").assertEqual(asset.hash);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testGetAssets0001 end *************");
    })

    /**
     * @tc.name resultSet getAssets normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0020
     * @tc.desc resultSet getAssets normal test
     */
    it('testGetAssets0002', 0, async function (done) {
        console.log(TAG + "************* testGetAssets0002 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data6 = resultSet.getAssets(resultSet.getColumnIndex("data6"))
            console.log(TAG + "id=" + id + ", data6=" + data6);
            expect(0).assertEqual(data6.length);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testGetAssets0002 end *************");
    })
})
