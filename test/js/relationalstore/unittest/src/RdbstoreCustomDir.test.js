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
import data_relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility';

const TAG = "[RELATIONAL_STORE_CUSTOMDIR_TEST]"

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB, data1 asset, data2 assets)";

const STORE_CONFIG1 = {
    name: "RdbCustomDir1.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    customDir: "custom1/subCustom1",
};

const STORE_CONFIG2 = {
    name: "RdbCustomDir2.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    customDir: "custom2/subCustom2",
};

const STORE_CONFIG3 = {
    name: "RdbCustomDir3.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    customDir: "custom",
};

const STORE_CONFIG4 = {
    name: "RdbCustomDir4.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    customDir: "custom".repeat(30), // customDir length exceeds 128 bytes
};

const STORE_CONFIG5 = {
    name: "RdbCustomDir5.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    customDir: "/custom", // customDir must be a relative directory
};

const STORE_CONFIG6 = {
    name: "RdbCustomDir6".repeat(80) + ".db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    customDir: "custom", // database path exceeds 1024 bytes
};

const asset1 = {
    name: "name1",
    uri: "uri1",
    createTime: "createTime1",
    modifyTime: "modifyTime1",
    size: "size1",
    path: "path1",
    status: data_relationalStore.AssetStatus.ASSET_NORMAL,
}

const asset2 = {
    name: "name2",
    uri: "uri2",
    createTime: "createTime2",
    modifyTime: "modifyTime2",
    size: "size2",
    path: "path2",
    status: data_relationalStore.AssetStatus.ASSET_NORMAL,
}

let context = ability_featureAbility.getContext();

let store = null;

describe('rdbStoreCustomTest', function () {
    beforeAll(function () {
        console.info(TAG, 'beforeAll')
    })

    beforeEach(async function () {
        console.info(TAG, 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG, 'afterEach')
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG1);
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG2);
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG3);
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG4);
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG5);
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG6);
        store = null;
    })

    afterAll(async function () {
        console.info(TAG, 'afterAll')
    })

    async function InsertTest() {
        console.info(TAG,  "insertTest data start");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets1 = [asset1, asset2];
        let valuesBucket1 = {
            "id": 1,
            "name": "lisi",
            "age": 15,
            "salary": 153.3,
            "blobType": u8,
            "data1": asset1,
            "data2": assets1,
        }
        await store.insert("test", valuesBucket1);
        let valuesBucket2 = {
            "id": 2,
            "name": "tom",
            "age": 16,
            "salary": 1503.3,
        }
        await store.insert("test", valuesBucket2);
        console.info(TAG,  "insertTest data end");
    }

    async function UpdateTest() {
        console.info(TAG,  "updateTest data start");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets1 = [asset2];
        let valuesBucket = {
            "id": 1,
            "name": "tim",
            "age": 18,
            "salary": 1563.3,
            "blobType": u8,
            "data1": asset2,
            "data2": assets1,
        }
        let predicates = new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("id", "1")
        await store.update(valuesBucket, predicates);
        console.info(TAG,  "updateTest data end");
    }

    console.info(TAG,  "*************Unit Test Begin*************");

    /**
     * @tc.number testRdbStoreCustomDirTest0001
     * @tc.name Normal test case of getRdbStore, test single-layer directory
     * @tc.desc 1.Configure customDir
     *          2.Execute getRdbStore
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0001', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0001 start *************");
        try {
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG3);
            expect(store != null).assertTrue();
            done();
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0001 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0002
     * @tc.name Normal test case of deleteRdbStore, test create and delete database
     * @tc.desc 1.Configure customDir
     *          2.Execute getRdbStore
     *          3.Execute deleteRdbStore by StoreConfig
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0002', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0002 start *************");
        try {
            let store1 = await data_relationalStore.getRdbStore(context, STORE_CONFIG1);
            expect(store1 != null).assertTrue();
            store1 = null;
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }

        try {
            await data_relationalStore.deleteRdbStore(context, STORE_CONFIG1);
            done();
        } catch(err) {
            console.error(TAG, "catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0002 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0003
     * @tc.name Normal test case of getRdbStore, test multi-layer directory and create two stores
     * @tc.desc 1.Configure database name and securityLevel and customDir
     *          2.Execute getRdbStore1
     *          3.Execute getRdbStore2
     *          4.Execute deleteRdbStore1
     *          5.Execute deleteRdbStore2
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0003', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0003 start *************");
        try {
            let store1 = await data_relationalStore.getRdbStore(context, STORE_CONFIG1);
            expect(store1 != null).assertTrue();
            store1 = null;
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore1 failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }

        try {
            let store2 = await data_relationalStore.getRdbStore(context, STORE_CONFIG2);
            expect(store2 != null).assertTrue();
            store2 = null;
            done();
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore2 failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0003 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0004
     * @tc.name Normal test case of getRdbStore, test insert and query data
     * @tc.desc 1.Configure database name and securityLevel and customDir
     *          2.Execute getRdbStore
     *          3.Execute insert data
     *          4.Execute query data
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0004', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0004 start *************");
        try {
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG1);
            expect(store != null).assertTrue();
            await store.executeSql(CREATE_TABLE_TEST,)
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore2 failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }

        try {
            await InsertTest();
        } catch(err) {
            console.error(TAG, "catch err: Insert data failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }

        try {
            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await store.query(predicates);
            expect(2).assertEqual(resultSet.rowCount);
            done();
        } catch(err) {
            console.error(TAG, "catch err: query data failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0004 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0005
     * @tc.name Normal test case of getRdbStore, test update and query data
     * @tc.desc 1.Configure database name and securityLevel and customDir
     *          2.Execute getRdbStore
     *          3.Execute insert data
     *          4.Execute update data
     *          5.Execute query data
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0005', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0005 start *************");
        try {
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG1);
            expect(store != null).assertTrue();
            await store.executeSql(CREATE_TABLE_TEST,)
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }

        try {
            await InsertTest();
            await UpdateTest();
        } catch(err) {
            console.error(TAG, "catch err: Insert and update data failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }

        try {
            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await store.query(predicates);
            expect(2).assertEqual(resultSet.rowCount);
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect("tim").assertEqual(resultSet.getString(resultSet.getColumnIndex("name")));
            done();
        } catch(err) {
            console.error(TAG, "catch err: query data failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0005 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0006
     * @tc.name Normal test case of getRdbStore, if customDir is ""
     * @tc.desc 1.Configure customDir as ""
     *          2.Execute getRdbStore
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0006', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0006 start *************");
        try {
            const STORE_CONFIG = {
                name: "RdbCustom1.db",
                securityLevel: data_relationalStore.SecurityLevel.S1,
                customDir: "",
            };
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
            expect(store != null).assertTrue();
            done();
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }

        console.info(TAG, "************* testRdbStoreCustomDirTest0006 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0007
     * @tc.name Normal test case of deleteRdbStore, if customDir is null
     * @tc.desc 1.Configure customDir as null
     *          2.Execute getRdbStore
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0007', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0007 start *************");
        try {
            const STORE_CONFIG = {
                name: "RdbCustom1.db",
                securityLevel: data_relationalStore.SecurityLevel.S1,
                customDir: null,
            };
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
            expect(store != null).assertTrue();
            done();
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0007 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0008
     * @tc.name Normal test case of deleteRdbStore, if customDir is undefined
     * @tc.desc 1.Configure customDir as undefined
     *          2.Execute getRdbStore
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0008', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0008 start *************");
        try {
            const STORE_CONFIG = {
                name: "RdbCustom1.db",
                securityLevel: data_relationalStore.SecurityLevel.S1,
                customDir: undefined,
            };
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
            expect(store != null).assertTrue();
            done();
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0008 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0009
     * @tc.name Normal test case of getRdbStore, test get store after getting store
     * @tc.desc 1.Configure customDir
     *          2.Execute getRdbStore
     *          3.Execute getRdbStore
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0009', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0009 start *************");
        try {
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG3);
            expect(store != null).assertTrue();
        } catch (err) {
            console.error(TAG, "catch err: Get RdbStore1 failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }

        try {
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG3);
            expect(store != null).assertTrue();
            done();
        } catch (err) {
            console.error(TAG, "catch err: Get RdbStore2 failed, err: code=" + err.code + " message=" + err.message);
            expect(false).assertTrue();
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0009 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0010
     * @tc.name Abnormal test case of getRdbStore, if customDir length exceeds 128 bytes
     * @tc.desc 1.Configure customDir
     *          2.Execute getRdbStore
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0010', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0010 start *************");
        try {
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG4);
            expect(false).assertTrue();
        } catch (err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect("401").assertEqual(err.code);
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0010 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0011
     * @tc.name Abnormal test case of getRdbStore, if customDir is a absolute directory
     * @tc.desc 1.Configure customDir
     *          2.Execute getRdbStore
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0011', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0011 start *************");
        try {
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG5);
            expect(false).assertTrue();
        } catch (err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect("401").assertEqual(err.code);
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0011 end *************")
    })

    /**
     * @tc.number testRdbStoreCustomDirTest0012
     * @tc.name Abnormal test case of getRdbStore, if database path exceeds 1024 bytes
     * @tc.desc 1.Configure customDir
     *          2.Execute getRdbStore
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreCustomDirTest0012', 0, async function (done) {
        console.info(TAG, "************* testRdbStoreCustomDirTest0012 start *************");
        try {
            store = await data_relationalStore.getRdbStore(context, STORE_CONFIG6);
            expect(false).assertTrue();
        } catch (err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message);
            expect("401").assertEqual(err.code);
            done();
        }
        console.info(TAG, "************* testRdbStoreCustomDirTest0012 end *************")
    })
    console.info(TAG, "*************Unit Test End*************");
})
