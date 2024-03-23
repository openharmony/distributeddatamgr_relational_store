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

import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'


var context = ability_featureAbility.getContext();

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
"name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const CREATE_TABLE_TEST1 = "CREATE TABLE IF NOT EXISTS test1 (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
"name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";


const STORE_CONFIG = {
    name: "rdbstore.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}

const STORE_CONFIG1 = {
    name: "rdbstore1.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}

const STORE_CONFIG2 = {
    name: "rdbstore2.db",
    encrypt: true,
    securityLevel: data_relationalStore.SecurityLevel.S1,
}

const STORE_CONFIG3 = {
    name: "rdbstore3.db",
    encrypt: true,
    securityLevel: data_relationalStore.SecurityLevel.S1,
}

describe('ActsRdbStoreAttachTest', function () {
beforeAll(async function () {
    console.info(TAG + 'beforeAll');
})

beforeEach(async function () {
    console.info(TAG + 'beforeEach');
    let attachStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG1);
    await attachStore.executeSql(CREATE_TABLE_TEST1);
    let attachStore1 = await data_relationalStore.getRdbStore(context, STORE_CONFIG2);
    await attachStore1.executeSql(CREATE_TABLE_TEST1);
})

afterEach(async function () {
    console.info(TAG + 'afterEach')
    await data_relationalStore.deleteRdbStore(context, "rdbstore.db");
    await data_relationalStore.deleteRdbStore(context, "rdbstore1.db");
    await data_relationalStore.deleteRdbStore(context, "rdbstore2.db");
    await data_relationalStore.deleteRdbStore(context, "rdbstore3.db");
})

afterAll(async function () {
    console.info(TAG + 'afterAll');
})


async function attachInsert(store, tableName) {
    var u8 = new Uint8Array([1, 2, 3])
    const valueBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
    };
    await store.insert(tableName, valueBucket);
}

async function attachBatchInsert(store, tableName) {
    var u8 = new Uint8Array([1, 2, 3])
    const valueBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
    };
    let valueBucketArray = new Array();
    for (let i = 0; i < 10; i++) {
        valueBucketArray.push(valueBucket);
    }
    await store.batchInsert(tableName, valueBucketArray);
}

async function insertCheck(store, tableName, ret) {
    let predicates = new data_relationalStore.RdbPredicates(tableName);
    let resultSet = await store.query(predicates);
    let count = resultSet.rowCount;
    expect(ret).assertEqual(count);
    resultSet.close();
}

async function updateCheck(store, tableName) {
    var u8 = new Uint8Array([4, 5, 6]);
    const valueBucket = {
        "name": "lisi",
        "age": 20,
        "salary": 200.5,
        "blobType": u8,
    };
    let predicates = new data_relationalStore.RdbPredicates(tableName)
    predicates.equalTo("id", "1");
    let ret = await store.update(valueBucket, predicates);
    expect(1).assertEqual(ret);
}

async function deleteCheck(store, tableName, count) {
    let predicates = new data_relationalStore.RdbPredicates(tableName);
    let ret = await store.delete(predicates);
    expect(count).assertEqual(ret);
}

async function attachCheck(store) {
    await attachInsert(store, "test");
    await insertCheck(store, "test", 2);
    await updateCheck(store, "test");
    await attachBatchInsert(store, "test");
    await insertCheck(store, "test", 12);
    await deleteCheck(store, "test", 12);

    await attachInsert(store, "test1");
    await insertCheck(store, "test1", 1)
    await updateCheck(store, "test1");
    await attachBatchInsert(store, "test1");
    await insertCheck(store, "test1", 11);
    await deleteCheck(store, "test1", 11);
}

console.log(TAG + "*************Unit Test Begin*************");

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_001
 * @tc.desc non encrypted database attach non encrypted database
 */
it('testRdbStoreAttach0001', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach0001 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachInsert(store, "test");

    let number = await store.attach(context, STORE_CONFIG1, "attachDB");
    expect(1).assertEqual(number);

    await attachCheck(store);
    expect(0).assertEqual(await store.detach("attachDB"))
    console.log(TAG + "************* testRdbStoreAttach0001 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_002
 * @tc.desc non encrypted database attach encrypted database
 */
it('testRdbStoreAttach0002', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach0002 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachInsert(store, "test");

    let number = await store.attach(context, STORE_CONFIG2, "attachDB");
    expect(1).assertEqual(number);

    await attachCheck(store);
    expect(0).assertEqual(await store.detach("attachDB"))
    console.log(TAG + "************* testRdbStoreAttach0002 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_003
 * @tc.desc encrypted database attach encrypted database
 */
it('testRdbStoreAttach0003', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach0003 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG3);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachInsert(store, "test");

    let number = await store.attach(context, STORE_CONFIG2, "attachDB");
    expect(1).assertEqual(number);

    await attachCheck(store);
    expect(0).assertEqual(await store.detach("attachDB"));
    console.log(TAG + "************* testRdbStoreAttach0003 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_004
 * @tc.desc encrypted databases are not supported for attaching non encrypted databases
 */
it('testRdbStoreAttach0004', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach0004 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG3);
    try {
        await store.attach(context, STORE_CONFIG1, "attachDB");
        expect().assertFail();
    } catch(e) {
        console.log("attach err: failed, err: code=" + e.code + " message=" + e.message)
        expect(801).assertEqual(e.code);
    }
    console.log(TAG + "************* testRdbStoreAttach0004 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_005
 * @tc.desc non encrypted database attach non encrypted database
 */
it('testRdbStoreAttach0005', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach0005 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachInsert(store, "test");
    let number = await store.attach("/data/storage/el2/database/entry/rdb/rdbstore1.db", "attachDB");
    expect(1).assertEqual(number);
    await attachCheck(store);
    expect(0).assertEqual(await store.detach("attachDB"));
    console.log(TAG + "************* testRdbStoreAttach0005 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_006
 * @tc.desc path error for non encrypted database
 */
it('testRdbStoreAttach0006', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach0006 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachInsert(store, "test");

    let STORE_CONFIG4 = {
        name: "/wrong/rdbstore.db",
        securityLevel: data_relationalStore.SecurityLevel.S1,
    }
    try {
        await store.attach(context, STORE_CONFIG4, "attachDB");
    } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
        expect("401").assertEqual(e.code);
    }
    console.log(TAG + "************* testRdbStoreAttach0006 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_007
 * @tc.desc non encrypted database attach non encrypted database with same table name
 */
it('testRdbStoreAttach0007', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach0007 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST1);
    await attachInsert(store, "test1");

    let number = await store.attach(context, STORE_CONFIG1, "attachDB");
    expect(1).assertEqual(number);

    await attachInsert(store, "test1");
    await insertCheck(store, "test1", 2);
    await updateCheck(store, "test1");
    await attachBatchInsert(store, "test1");
    await insertCheck(store, "test1", 12);
    await deleteCheck(store, "test1", 12);

    await attachInsert(store, "attachDB.test1");
    await insertCheck(store, "attachDB.test1", 1)
    await updateCheck(store, "attachDB.test1");
    await attachBatchInsert(store, "attachDB.test1");
    await insertCheck(store, "attachDB.test1", 11);
    await deleteCheck(store, "attachDB.test1", 11);

    expect(0).assertEqual(await store.detach("attachDB"))
    console.log(TAG + "************* testRdbStoreAttach0007 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_008
 * @tc.desc resultSet occupies connection, attach failed
 */
it('testRdbStoreAttach0008', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach0008 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachBatchInsert(store, "test");

    let predicates = new data_relationalStore.RdbPredicates("test");
    let resultSet = await store.query(predicates);
    let count = resultSet.rowCount;
    expect(10).assertEqual(count);
    try {
        await store.attach("/data/storage/el2/database/entry/rdb/rdbstore1.db", "attachDB");
        expect().assertFail();
    } catch(e) {
        expect(14800015).assertEqual(e.code);
    }
    resultSet.close();
    console.log(TAG + "************* testRdbStoreAttach0008 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_009
 * @tc.desc repeat attach using the same alias
 */
it('testRdbStoreAttach0009', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach0009 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachBatchInsert(store, "test");
    let number = await store.attach(context, STORE_CONFIG1, 'attachDB');
    expect(1).assertEqual(number);
    try {
        await store.attach(context, STORE_CONFIG1, 'attachDB');
        expect().assertFail();
    } catch(e) {
        console.log("testRdbStoreAttach0009: failed, err: code=" + e.code + " message=" + e.message);
        expect(14800016).assertEqual(e.code);
    }
    expect(0).assertEqual(await store.detach("attachDB"));

    console.log(TAG + "************* testRdbStoreAttach0009 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_0010
 * @tc.desc WaitTime exceeds maximum limit
 */
it('testRdbStoreAttach00010', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach00010 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachBatchInsert(store, "test");
    let number = await store.attach(context, STORE_CONFIG1, 'attachDB', 300);
    expect(1).assertEqual(number);
    try {
        await store.attach(context, STORE_CONFIG1, 'attachDB', 301);
        expect().assertFail();
    } catch(e) {
        console.log("testRdbStoreAttach00010: failed, err: code=" + e.code + " message=" + e.message);
        expect("401").assertEqual(e.code);
    }
    expect(0).assertEqual(await store.detach("attachDB"));

    console.log(TAG + "************* testRdbStoreAttach00010 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_0011
 * @tc.desc WaitTime exceeds the minimum limit
 */
it('testRdbStoreAttach00011', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach00011 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachBatchInsert(store, "test");
    let number = await store.attach(context, STORE_CONFIG1, 'attachDB', 1);
    expect(1).assertEqual(number);
    try {
        await store.attach(context, STORE_CONFIG1, 'attachDB', -1);
        expect().assertFail();
    } catch(e) {
        console.log("testRdbStoreAttach00011: failed, err: code=" + e.code + " message=" + e.message);
        expect('401').assertEqual(e.code);
    }
    expect(0).assertEqual(await store.detach("attachDB"));

    console.log(TAG + "************* testRdbStoreAttach00011 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_0012
 * @tc.desc the alias cannot be empty
 */
it('testRdbStoreAttach00012', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach00012 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachBatchInsert(store, "test");
    try {
        await store.attach(context, STORE_CONFIG1, '');
        expect().assertFail();
    } catch(e) {
        console.log("testRdbStoreAttach00012 : failed, err: code=" + e.code + " message=" + e.message);
        expect('401').assertEqual(e.code);
    }
    console.log(TAG + "************* testRdbStoreAttach00012 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_0013
 * @tc.desc input error path
 */
it('testRdbStoreAttach00013', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach00013 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachBatchInsert(store, "test");
    try {
        await store.attach("/path/errPath/attach.db", "attachDB");
        expect().assertFail();
    } catch(e) {
        console.log("testRdbStoreAttach00013 : failed, err: code=" + e.code + " message=" + e.message);
        expect(14800010).assertEqual(e.code);
    }
    console.log(TAG + "************* testRdbStoreAttach00013 end *************");
})

/**
 * @tc.name the attach function
 * @tc.number SUB_DDM_AppDataFWK_JSRDB_RdbStore_attach_0014
 * @tc.desc input empty path
 */
it('testRdbStoreAttach00014', 0, async function () {
    console.log(TAG + "************* testRdbStoreAttach00014 start *************");
    let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    await store.executeSql(CREATE_TABLE_TEST);
    await attachBatchInsert(store, "test");
    try {
        await store.attach("", "attachDB");
        expect().assertFail();
    } catch(e) {
        console.log("testRdbStoreAttach00014 : failed, err: code=" + e.code + " message=" + e.message);
        expect('401').assertEqual(e.code);
    }
    console.log(TAG + "************* testRdbStoreAttach00014 end *************");
})

console.log(TAG + "*************Unit Test End*************");
})