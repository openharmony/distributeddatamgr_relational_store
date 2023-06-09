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
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "data1 asset, " + "data2 asset, " + "data3 assets )";
const DROP_TABLE_TEST = "DROP TABLE IF EXISTS test";

const STORE_CONFIG = {
    name: "Asset.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined;

describe('rdbResultSetTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);

    })

    beforeEach(async function () {
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
        console.info(TAG + 'beforeEach');
        await createTest();
    })

    afterEach(async function () {
        await rdbStore.executeSql(DROP_TABLE_TEST, null);
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
        const asset3 = {
            version: 3,
            name: "name3",
            uri: "uri3",
            createTime: "createTime3",
            modifyTime: "modifyTime3",
            size: "size3",
            hash: "hash3",
        }
        const assets1 = [asset1];
        const assets2 = [asset1, asset2, asset3];
        const assets3 = [];
        let valuesBucket = {
            "data1": asset1,
            "data2": asset2,
            "data3": assets1,
        }
        await rdbStore.insert("test", valuesBucket)
        valuesBucket = {
            "data1": asset2,
            "data2": asset3,
            "data3": assets2,
        }
        await rdbStore.insert("test", valuesBucket)
        valuesBucket = {
            "data1": asset1,
            "data3": assets3,
        }
        await rdbStore.insert("test", valuesBucket)
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
            const data1 = resultSet.getAsset(resultSet.getColumnIndex("data1"))
            console.log(TAG + "id=" + id + ", data1=" + data1);
            expect(1).assertEqual(data1.version);
            expect("name1").assertEqual(data1.name);
            expect("uri1").assertEqual(data1.uri);
            expect("createTime1").assertEqual(data1.createTime);
            expect("modifyTime1").assertEqual(data1.modifyTime);
            expect("size1").assertEqual(data1.size);
            expect("hash1").assertEqual(data1.hash);

            const data2 = resultSet.getAsset(resultSet.getColumnIndex("data2"))
            console.log(TAG + "id=" + id + ", data2=" + data2);
            expect(2).assertEqual(data2.version);
            expect("name2").assertEqual(data2.name);
            expect("uri2").assertEqual(data2.uri);
            expect("createTime2").assertEqual(data2.createTime);
            expect("modifyTime2").assertEqual(data2.modifyTime);
            expect("size2").assertEqual(data2.size);
            expect("hash2").assertEqual(data2.hash);

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
            const data1 = resultSet.getAsset(resultSet.getColumnIndex("data1"))
            console.log(TAG + "id=" + id + ", data1=" + data1);
            expect(2).assertEqual(data1.version);
            expect("name2").assertEqual(data1.name);
            expect("uri2").assertEqual(data1.uri);
            expect("createTime2").assertEqual(data1.createTime);
            expect("modifyTime2").assertEqual(data1.modifyTime);
            expect("size2").assertEqual(data1.size);
            expect("hash2").assertEqual(data1.hash);

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
            const data2 = resultSet.getAsset(resultSet.getColumnIndex("data2"))
            console.log(TAG + "id=" + id + ", data2=" + data2);
            expect(0).assertEqual(data2.version);
            expect("").assertEqual(data2.name);
            expect("").assertEqual(data2.uri);
            expect("").assertEqual(data2.createTime);
            expect("").assertEqual(data2.modifyTime);
            expect("").assertEqual(data2.size);
            expect("").assertEqual(data2.hash);

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
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data3 = resultSet.getAssets(resultSet.getColumnIndex("data3"))
            console.log(TAG + "id=" + id + ", data3=" + data3);
            expect(1).assertEqual(data3.length);
            let asset = data3[0];
            expect(1).assertEqual(asset.version);
            expect("name1").assertEqual(asset.name);
            expect("uri1").assertEqual(asset.uri);
            expect("createTime1").assertEqual(asset.createTime);
            expect("modifyTime1").assertEqual(asset.modifyTime);
            expect("size1").assertEqual(asset.size);
            expect("hash1").assertEqual(asset.hash);

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
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data3 = resultSet.getAssets(resultSet.getColumnIndex("data3"))
            console.log(TAG + "id=" + id + ", data3=" + data3);
            expect(3).assertEqual(data3.length);
            let asset = data3[0];
            expect(1).assertEqual(asset.version);
            expect("name1").assertEqual(asset.name);
            expect("uri1").assertEqual(asset.uri);
            expect("createTime1").assertEqual(asset.createTime);
            expect("modifyTime1").assertEqual(asset.modifyTime);
            expect("size1").assertEqual(asset.size);
            expect("hash1").assertEqual(asset.hash);

            asset = data3[1];
            expect(2).assertEqual(asset.version);
            expect("name2").assertEqual(asset.name);
            expect("uri2").assertEqual(asset.uri);
            expect("createTime2").assertEqual(asset.createTime);
            expect("modifyTime2").assertEqual(asset.modifyTime);
            expect("size2").assertEqual(asset.size);
            expect("hash2").assertEqual(asset.hash);

            asset = data3[2];
            expect(3).assertEqual(asset.version);
            expect("name3").assertEqual(asset.name);
            expect("uri3").assertEqual(asset.uri);
            expect("createTime3").assertEqual(asset.createTime);
            expect("modifyTime3").assertEqual(asset.modifyTime);
            expect("size3").assertEqual(asset.size);
            expect("hash3").assertEqual(asset.hash);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            console.error("error happened" + e.message);
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testGetAssets0002 end *************");
    })

    /**
     * @tc.name resultSet getAssets normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ResultSet_0030
     * @tc.desc resultSet getAssets normal test
     */
    it('testGetAssets0003', 0, async function (done) {
        console.log(TAG + "************* testGetAssets0003 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        try {
            expect(true).assertEqual(resultSet.goToFirstRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            expect(true).assertEqual(resultSet.goToNextRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const data3 = resultSet.getAssets(resultSet.getColumnIndex("data3"))
            console.log(TAG + "id=" + id + ", data3=" + data3);
            expect(0).assertEqual(data3.length);

            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed)
        } catch (e) {
            expect(null).assertFail();
        }
        resultSet = null
        done();
        console.log(TAG + "************* testGetAssets0003 end *************");
    })
})
