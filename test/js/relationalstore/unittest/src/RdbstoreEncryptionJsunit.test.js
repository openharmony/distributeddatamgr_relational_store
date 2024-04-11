/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    + "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)"

let context = ability_featureAbility.getContext()
const STORE_CONFIG_ENCRYPT = {
    name: "Encrypt.db",
    encrypt: true,
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG_ENCRYPT2 = {
    name: "Encrypt2.db",
    encrypt: true,
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG_UNENCRYPT = {
    name: "Unencrypt.db",
    encrypt: false,
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG_WRONG = {
    name: "Encrypt.db",
    encrypt: false,
    securityLevel: data_relationalStore.SecurityLevel.S1,
}

async function CreatRdbStore(context, STORE_CONFIG) {
    let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG)
    await rdbStore.executeSql(CREATE_TABLE_TEST, null)
    let u8 = new Uint8Array([1, 2, 3])
    {
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
    }
    {
        const valueBucket = {
            "name": "lisi",
            "age": 28,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
    }
    {
        const valueBucket = {
            "name": "wangwu",
            "age": 38,
            "salary": 90.0,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
    }
    return rdbStore
}

describe('rdbEncryptTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG_ENCRYPT.name)
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG_UNENCRYPT.name)
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG_WRONG.name)
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************")

    /**
     * @tc.name RDB encrypted test
     * @tc.number SUB_DDM_RDB_JS_RdbEncryptTest_0010
     * @tc.desc RDB create encrypt db test
     */
    it('RdbEncryptTest_0010', 0, async function (done) {
        await console.log(TAG + "************* RdbEncryptTest_0010 start *************")
        let storePromise = data_relationalStore.getRdbStore(context, STORE_CONFIG_ENCRYPT);
        storePromise.then(async (store) => {
            try {
                await console.log(TAG + "getRdbStore done: " + store);
            } catch (err) {
                expect(null).assertFail();
            }
            store = null
        }).catch((err) => {
            expect(null).assertFail();
        })
        await storePromise
        storePromise = null

        done()
        await console.log(TAG + "************* RdbEncryptTest_0010 end *************")
    })

    /**
     * @tc.name RDB unencrypted test
     * @tc.number SUB_DDM_RDB_JS_RdbEncryptTest_0020
     * @tc.desc RDB create unencrypted db test
     */
    it('RdbEncryptTest_0020', 0, async function (done) {
        await console.log(TAG + "************* RdbEncryptTest_0020 start *************")
        let storePromise = data_relationalStore.getRdbStore(context, STORE_CONFIG_UNENCRYPT);
        storePromise.then(async (store) => {
            try {
                await console.log(TAG + "getRdbStore done: " + store);
            } catch (err) {
                expect(null).assertFail();
            }
            store = null
        }).catch((err) => {
            expect(null).assertFail();
        })
        await storePromise
        storePromise = null

        done()
        await console.log(TAG + "************* RdbEncryptTest_0020 end *************")
    })


    /**
     * @tc.name RDB Encrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbEncryptTest_0030
     * @tc.desc RDB Encrypt function test
     */
    it('RdbEncryptTest_0030', 0, async function (done) {
        await console.log(TAG + "************* RdbEncryptTest_0030 start *************")
        let rdbStore = await CreatRdbStore(context, STORE_CONFIG_ENCRYPT)
        let predicates = new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "zhangsan")
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "After restore resultSet query done")
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
            expect(1).assertEqual(id)
            expect("zhangsan").assertEqual(name)
            expect(1).assertEqual(blobType[0])
        } catch (err) {
            expect(false).assertTrue()
        }
        resultSet.close()
        resultSet = null
        rdbStore = null
        done()
        await console.log(TAG + "************* RdbEncryptTest_0030 end *************")
    })

    /**
     * @tc.name RDB Encrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbEncryptTest_0040
     * @tc.desc RDB Encrypt function test
     */
    it('RdbEncryptTest_0040', 0, async function () {
        await console.log(TAG + "************* RdbEncryptTest_0040 start *************")
        let rdbStore = await CreatRdbStore(context, STORE_CONFIG_ENCRYPT)
        rdbStore = null

        try {
            rdbStore = await CreatRdbStore(context, STORE_CONFIG_WRONG)
            expect(false).assertTrue()
        } catch (err) {
            expect(err.code).assertEqual(14800011);
        }

        await console.log(TAG + "************* RdbEncryptTest_0040 end *************")
    })

    /**
     * @tc.name RDB Encrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbEncryptTest_0050
     * @tc.desc RDB Encrypt function test for setDistributedTables and insert.
     */
    it('RdbEncryptTest_0050', 0, async function () {
        await console.log(TAG + "************* RdbEncryptTest_0050 start *************")
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG_ENCRYPT)
            await rdbStore.executeSql(CREATE_TABLE_TEST, null)
            await rdbStore.setDistributedTables(['test'])

            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(1).assertEqual(ret)
        } catch (err) {
            console.log(TAG + `fails errcode:${JSON.stringify(err)}.`);
            expect().assertFail();
        }
        console.log(TAG + "************* RdbEncryptTest_0050 end *************")
    })

    /**
     * @tc.name Scenario testcase of RDB, get correct encrypt file when open database
     * @tc.number SUB_DDM_RDB_JS_RdbEncryptTest_0060
     * @tc.desc 1. create db1 and insert data
     *          2. query db1
     *          3. create db2 and create table in db1
     *          4. query db1 and db2
     */
    it('RdbEncryptTest_0060', 0, async function () {
        await console.info(TAG + "************* RdbEncryptTest_0060 start *************")
        context = ability_featureAbility.getContext()
        let rdbStore1;
        let rdbStore2;
        // create 'rdbstore1'
        try {
            rdbStore1 = await CreatRdbStore(context, STORE_CONFIG_ENCRYPT);
        } catch (err) {
            expect().assertFail()
            console.error(`CreatRdbStore1 failed, error code: ${err.code}, err message: ${err.message}`);
        }

        // query 'rdbstore1'
        try {
            let predicates1 = new data_relationalStore.RdbPredicates("test")
            let resultSet1 = await rdbStore1.query(predicates1)
            expect(3).assertEqual(resultSet1.rowCount)
        } catch (err) {
            expect().assertFail()
            console.error(`First query rdbstore1 failed, error code: ${err.code}, err message: ${err.message}`);
        }

        // create 'rdbStore2'
        try {
            rdbStore2 = await CreatRdbStore(context, STORE_CONFIG_ENCRYPT2)
        } catch (err) {
            expect().assertFail()
            console.error(`CreatRdbStore2 failed, error code: ${err.code}, err message: ${err.message}`);
        }

        // create table and query 'rdbStore1'
        try {
            await rdbStore1.executeSql(CREATE_TABLE_TEST, null)
            let predicates1 = new data_relationalStore.RdbPredicates("test")
            let resultSet1 = await rdbStore1.query(predicates1)
            expect(3).assertEqual(resultSet1.rowCount)
        } catch (err) {
            expect().assertFail()
            console.error(`Second query rdbstore1 failed, error code: ${err.code}, err message: ${err.message}`);
        }

        // create table and query 'rdbStore2'
        try {
            await rdbStore2.executeSql(CREATE_TABLE_TEST, null)
            let predicates2 = new data_relationalStore.RdbPredicates("test")
            let resultSet2 = await rdbStore2.query(predicates2)
            expect(3).assertEqual(resultSet2.rowCount)
        } catch (err) {
            expect().assertFail()
            console.error(`Query rdbstore2 failed, error code: ${err.code}, err message: ${err.message}`);
        }
        console.info(TAG + "************* RdbEncryptTest_0060 end *************")
    })
    console.log(TAG + "*************Unit Test End*************")
})
