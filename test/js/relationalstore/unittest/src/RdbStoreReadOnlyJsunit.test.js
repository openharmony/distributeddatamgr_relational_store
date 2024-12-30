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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index';
import relationalStore from '@ohos.data.relationalStore';
import featureAbility from '@ohos.ability.featureAbility'

let context = featureAbility.getContext();
let store = undefined;

const TAG = "[RELATIONAL_STORE_JS_READ_ONLY_TEST]";
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
"name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

let STORE_CONFIG = {
    name: "store.db",
    securityLevel: relationalStore.SecurityLevel.S1,
}
let STORE_CONFIG1 = {
    name: "test.db",
    securityLevel: relationalStore.SecurityLevel.S1,
    isReadOnly: true,
}

let STORE_CONFIG2 = {
    name: "readOnly.db",
    securityLevel: relationalStore.SecurityLevel.S1,
    isReadOnly: true,
}

const valueBucket = {
    'name': 'zhangsan',
    'age': 18,
    'salary': 25000,
    'blobType': new Uint8Array([1, 2, 3]),
};

describe('rdbStoreReadOnlyTest', function () {
    beforeAll(async function () {
        console.log(TAG + 'beforeAll');
        try {
            await relationalStore.deleteRdbStore(context, STORE_CONFIG);
            let rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);

            const CREATE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "name TEXT, age INTEGER, salary REAL, blobType BLOB)";
            await rdbStore.executeSql(CREATE_TABLE_SQL);

            await rdbStore.insert('test', valueBucket);
            await rdbStore.insert('test', valueBucket);

            await rdbStore.backup(STORE_CONFIG2.name)
            await relationalStore.deleteRdbStore(context, STORE_CONFIG);
        } catch (err) {
            console.error(TAG, `init database failed, errCode:${err.code}, message:${err.message}`);
            expect().assertFail();
        }
    })

    beforeEach(async function () {
        store = await relationalStore.getRdbStore(context, STORE_CONFIG2);
        console.info(TAG + 'beforeEach');
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll');
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
        await relationalStore.deleteRdbStore(context, STORE_CONFIG1);
        await relationalStore.deleteRdbStore(context, STORE_CONFIG2);
    })

    console.info(TAG + "*************JS Test Begin*************");

    /**
     * @tc.name open read-only database if the database is not exist
     * @tc.number readOnlyTest0001
     * @tc.desc 1. set isReadOnly as true
     *          2. open read-only database
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest0001', 0, async function () {
        console.info(TAG + "************* readOnlyTest0001 start *************");
        try {
            await relationalStore.getRdbStore(context, STORE_CONFIG1);
            expect().assertFail();
        } catch (err) {
            console.error(TAG, `open read-only database failed, errCode:${err.code}, message:${err.message}`);
            expect(err.code == 14800030).assertTrue();
        }
        console.log(TAG + "************* readOnlyTest0001 end *************");
    })

    /**
     * @tc.name insert data into read-only database
     * @tc.number readOnlyTest0002
     * @tc.desc insert data
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest0002', 0, async function () {
        console.info(TAG + "************* readOnlyTest0002 start *************");
        try {
            await store.insert('test', valueBucket);
            expect().assertFail();
        } catch (err) {
            console.error(TAG, `insert failed, errCode:${err.code}, message:${err.message}`);
            expect(err.code == 801).assertTrue();
        }
        console.info(TAG + "************* readOnlyTest0002 end *************");
    })

    /**
     * @tc.name update data in read-only database
     * @tc.number readOnlyTest0003
     * @tc.desc update data
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest0003', 0, async function () {
        console.info(TAG + "************* readOnlyTest0003 start *************");
        try {
            let predicates = new relationalStore.RdbPredicates('test')
            predicates.equalTo('id', 1)
            await store.update(valueBucket, predicates);
            expect().assertFail();
        } catch (err) {
            console.error(TAG, `update failed, errCode:${err.code}, message:${err.message}`);
            expect(err.code == 801).assertTrue();
        }
        console.info(TAG + "************* readOnlyTest0003 end *************");
    })

    /**
     * @tc.name delete data from read-only database
     * @tc.number readOnlyTest0004
     * @tc.desc delete data
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest0004', 0, async function () {
        console.info(TAG + "************* readOnlyTest0004 start *************");
        try {
            let predicates = new relationalStore.RdbPredicates('test')
            await store.delete(predicates);
            expect().assertFail();
        } catch (err) {
            console.error(TAG, `delete failed, errCode:${err.code}, message:${err.message}`);
            expect(err.code == 801).assertTrue();
        }
        console.info(TAG + "************* readOnlyTest0004 end *************");
    })

    /**
     * @tc.name execute transaction for read-only database
     * @tc.number readOnlyTest0005
     * @tc.desc begin transaction
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest0005', 0, async function () {
        console.info(TAG + "************* readOnlyTest0005 start *************");
        try {
            store.beginTransaction();
            expect().assertFail();
        } catch (err) {
            console.error(TAG, `begin transaction failed, errCode:${err.code}, message:${err.message}`);
            expect(err.code == 801).assertTrue();
        }
        console.info(TAG + "************* readOnlyTest0005 end *************");
    })

    /**
     * @tc.name get user_version from read-only database
     * @tc.number readOnlyTest0006
     * @tc.desc get user_version
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest0006', 0, async function () {
        console.info(TAG + "************* readOnlyTest0006 start *************");
        try {
            expect(store.version === 0).assertTrue();
            let resultSet = await store.querySql('PRAGMA user_version');
            resultSet.goToFirstRow();
            expect(resultSet.getValue(0) === 0).assertTrue();
        } catch (err) {
            console.error(TAG, `restore failed, errCode:${err.code}, message:${err.message}`);
            expect().assertFail();
        }
        console.info(TAG + "************* readOnlyTest0006 end *************");
    })

    /**
     * @tc.name query data from read-only database
     * @tc.number readOnlyTest0007
     * @tc.desc query data
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest0007', 0, async function () {
        console.info(TAG + "************* readOnlyTest0007 start *************");
        try {
            let predicates = await new relationalStore.RdbPredicates('test')
            let resultSet = await store.query(predicates);
            expect(resultSet.rowCount == 2).assertTrue();
        } catch (err) {
            console.error(TAG, `query failed, errCode:${err.code}, message:${err.message}`);
            expect().assertFail();
        }
        console.info(TAG + "************* readOnlyTest0007 end *************");
    })

    /**
     * @tc.name set user_version to read-only database
     * @tc.number readOnlyTest0008
     * @tc.desc test execute
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest0008', 0, async function () {
        console.info(TAG + "************* readOnlyTest0008 start *************");
        try {
            expect(store.version === 0).assertTrue();
            await store.execute('PRAGMA user_version=5');
            expect().assertFail();
        } catch (err) {
            console.error(TAG, `get user_version failed, errCode:${err.code}, message:${err.message}`);
            expect(err.code == 801).assertTrue();
        }
        console.info(TAG + "************* readOnlyTest0008 end *************");
    })

    /**
     * @tc.name set user_version to read-only database
     * @tc.number readOnlyTest009
     * @tc.desc test executeSql
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest009', 0, async function () {
        console.info(TAG + "************* readOnlyTest009 start *************");
        try {
            expect(store.version === 0).assertTrue();
            await store.executeSql('PRAGMA user_version');
            expect().assertFail();
        } catch (err) {
            console.error(TAG, `set user_version failed, errCode:${err.code}, message:${err.message}`);
            expect(err.code == 801).assertTrue();
        }
        console.info(TAG + "************* readOnlyTest009 end *************");
    })

    /**
     * @tc.name set user_version to read-only database
     * @tc.number readOnlyTest0010
     * @tc.desc set user_version by store
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('readOnlyTest010', 0, async function () {
        console.info(TAG + "************* readOnlyTest0010 start *************");
        try {
            store.version = 5;
            expect().assertFail();
        } catch (err) {
            console.error(TAG, `set user_version failed, errCode:${err.code}, message:${err.message}`);
            expect(err.code == 801).assertTrue();
        }
        console.info(TAG + "************* readOnlyTest0010 end *************");
    })

    /**
     * @tc.name isReadOnly test
     * @tc.number readOnlyTest011
     * @tc.desc create read write db first, then create readonly db test can not write
     */
    it('testRdbStore011', 0, async function (done) {
        console.log(TAG + "************* testRdbStore011 start *************");
        let rdbStore;
        let rdbStore1;
        try {
            rdbStore = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
            })
            rdbStore.executeSync(CREATE_TABLE_TEST);
            rdbStore.insertSync('test', {
                "name": "lisi",
                "age": 15,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            })

            rdbStore1 = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
                isReadOnly: true,
            })

            rdbStore1.insertSync('test', {
                "name": "lisi",
                "age": 16,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            })
            expect().assertFail();
        } catch (e) {
            await rdbStore.close();
            await rdbStore1.close();
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect(801).assertEqual(e.code);
            await relationalStore.deleteRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
            });
            console.log(TAG + "************* testRdbStore011 end *************");
            done();
        }
    })

    /**
     * @tc.name isReadOnly test
     * @tc.number readOnlyTest012
     * @tc.desc create readonly db first, then create read write db test can write
     */
    it('testRdbStore012', 0, async function (done) {
        console.log(TAG + "************* testRdbStore012 start *************");
        {
            const rdbStore = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
            })
            rdbStore.executeSync(CREATE_TABLE_TEST);
            rdbStore.close();
        }
        let rdbStore;
        let rdbStore1;
        try {
            rdbStore = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
                isReadOnly: true,
            })

            rdbStore.insertSync('test', {
                "name": "lisi",
                "age": 15,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            })
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect(801).assertEqual(e.code);
            done();
        }

        try {
            rdbStore1 = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
            })
            const rowId = rdbStore1.insertSync('test', {
                "name": "lisi",
                "age": 16,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            })
            expect(rowId).assertEqual(1);
        } catch (error) {
            expect().assertFail();
        }
        
        await rdbStore.close();
        await rdbStore1.close();
        await relationalStore.deleteRdbStore(context, {
            name: "isReadOnlyTest.db",
            securityLevel: relationalStore.SecurityLevel.S3,
        });
        console.log(TAG + "************* testRdbStore012 end *************");
        done();
    })

    /**
     * @tc.name isReadOnly test
     * @tc.number readOnlyTest013
     * @tc.desc create read write db first, then open db by rootDir config test can not write
     */
    it('testRdbStore013', 0, async function (done) {
        console.log(TAG + "************* testRdbStore013 start *************");
        let rdbStore;
        let rdbStore1;
        try {
            rdbStore = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
            })
            rdbStore.executeSync(CREATE_TABLE_TEST);
            rdbStore.insertSync('test', {
                "name": "lisi",
                "age": 15,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            })

            rdbStore1 = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
                rootDir: "/data/storage/el2/database",
                customDir: "entry/rdb"
            })

            rdbStore1.insertSync('test', {
                "name": "lisi",
                "age": 16,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            })
            expect().assertFail();
        } catch (e) {
            await rdbStore.close();
            await rdbStore1.close();
            await relationalStore.deleteRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
            });
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect(801).assertEqual(e.code);
            console.log(TAG + "************* testRdbStore013 end *************");
            done();
        }
    })

    /**
     * @tc.name isReadOnly test
     * @tc.number readOnlyTest014
     * @tc.desc create db first, then open db by rootDir and create normal db test can not write
     */
    it('testRdbStore014', 0, async function (done) {
        console.log(TAG + "************* testRdbStore014 start *************");
        {
            const rdbStore = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
            })
            rdbStore.executeSync(CREATE_TABLE_TEST);
            rdbStore.close();
        }
        let rdbStore;
        let rdbStore1;
        try {
            rdbStore = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
                rootDir: "/data/storage/el2/database",
                customDir: "entry/rdb"
            })

            rdbStore.insertSync('test', {
                "name": "lisi",
                "age": 15,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            })
            expect().assertFail();
        } catch (e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
            expect(801).assertEqual(e.code);
            done();
        }

        try {
            rdbStore1 = await relationalStore.getRdbStore(context, {
                name: "isReadOnlyTest.db",
                securityLevel: relationalStore.SecurityLevel.S3,
            })
            const rowId = rdbStore1.insertSync('test', {
                "name": "lisi",
                "age": 16,
                "salary": 153.3,
                "blobType": new Uint8Array([1, 2, 3]),
            })
            expect(rowId).assertEqual(1);
        } catch (error) {
            expect().assertFail();
        }
        
        await rdbStore.close();
        await rdbStore1.close();
        await relationalStore.deleteRdbStore(context, {
            name: "isReadOnlyTest.db",
            securityLevel: relationalStore.SecurityLevel.S3,
        });
        console.log(TAG + "************* testRdbStore014 end *************");
        done();
    })
    console.info(TAG + "*************Unit Test End*************");
})

