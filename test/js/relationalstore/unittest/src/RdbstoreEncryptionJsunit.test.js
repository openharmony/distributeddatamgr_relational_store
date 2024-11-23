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
import factory from '@ohos.data.distributedKVStore'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const TEST_BUNDLE_NAME = "com.example.myapplication"
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

const STORE_CONFIG_DEFAULT = {
    name: "default.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    encrypt: true,
    cryptoParam: {
        encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y']),
        iterationCount: 10000,
        encryptionAlgo: data_relationalStore.EncryptionAlgo.AES_256_GCM,
        hmacAlgo: data_relationalStore.HmacAlgo.SHA256,
        kdfAlgo: data_relationalStore.KdfAlgo.KDF_SHA256,
        cryptoPageSize: 1024
    }
}

const STORE_CONFIG_NON_DEFAULT = {
    name: "nondefault.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
    encrypt: true,
    cryptoParam: {
        encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y']),
        iterationCount: 25000,
        encryptionAlgo: data_relationalStore.EncryptionAlgo.AES_256_CBC,
        hmacAlgo: data_relationalStore.HmacAlgo.SHA512,
        kdfAlgo: data_relationalStore.KdfAlgo.KDF_SHA512,
        cryptoPageSize: 2048
    }
}

async function CreateRdbStore(context, STORE_CONFIG) {
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

async function CreateRdbStoreAndInsertData(context, store_config) {
    let rdbStore = await data_relationalStore.getRdbStore(context, store_config)
    await rdbStore.executeSql("CREATE TABLE t (x int, y int)", null)
    const valueBucket = {
        "x": 1,
        "y": 1
    }
    let insertPromise = rdbStore.insert("t", valueBucket)
    insertPromise.then(async (ret) => {
        expect(1).assertEqual(ret)
    })
    return rdbStore
}

async function CheckRdbStoreData(rdbStore) {
    let resultSet = await rdbStore.querySql("SELECT * from t")
    expect(1).assertEqual(resultSet.rowCount)
    expect(true).assertEqual(resultSet.goToFirstRow())
    const x = resultSet.getLong(resultSet.getColumnIndex("x"))
    const y = resultSet.getLong(resultSet.getColumnIndex("y"))
    expect(1).assertEqual(x)
    expect(1).assertEqual(y)
    return resultSet
}

describe('rdbEncryptTest', function () {
    beforeAll(async function () {
        await CreateRdbStoreAndInsertData(context, STORE_CONFIG_NON_DEFAULT)
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
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG_NON_DEFAULT.name)
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
        let rdbStore = await CreateRdbStore(context, STORE_CONFIG_ENCRYPT)
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
    it('RdbEncryptTest_0040', 0, async function (done) {
        console.log(TAG + "************* RdbEncryptTest_0040 start *************");
        context = ability_featureAbility.getContext();
        await CreateRdbStore(context, STORE_CONFIG_ENCRYPT);
        try {
          let rdbStore = await CreateRdbStore(context, STORE_CONFIG_WRONG);
          expect(rdbStore !== null).assertTrue();
        } catch (err) {
          console.log(TAG + `failed, errcode:${JSON.stringify(err)}.`);
          expect().assertFail();
        }
        done();
        console.log(TAG + "************* RdbEncryptTest_0040 end *************");
    })

    /**
     * @tc.name RdbEncryptTest_0041
     * @tc.number SUB_DDM_RDB_JS_RdbEncryptTest_0041
     * @tc.desc RDB Encrypt function test
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 1
     */
    it('RdbEncryptTest_0041', 0, async function (done) {
        console.log(TAG + "************* RdbEncryptTest_0041 start *************");
        context = ability_featureAbility.getContext();
        await CreateRdbStore(context, STORE_CONFIG_WRONG);
        try {
          let rdbStore = await CreateRdbStore(context, STORE_CONFIG_ENCRYPT);
          expect(rdbStore !== null).assertTrue();
        } catch (err) {
          console.log(TAG + `failed, errcode:${JSON.stringify(err)}.`);
          expect().assertFail();
        }
        done();
        console.log(TAG + "************* RdbEncryptTest_0041 end *************");
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
            rdbStore1 = await CreateRdbStore(context, STORE_CONFIG_ENCRYPT);
        } catch (err) {
            expect().assertFail()
            console.error(`CreateRdbStore1 failed, error code: ${err.code}, err message: ${err.message}`);
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
            rdbStore2 = await CreateRdbStore(context, STORE_CONFIG_ENCRYPT2)
        } catch (err) {
            expect().assertFail()
            console.error(`CreateRdbStore2 failed, error code: ${err.code}, err message: ${err.message}`);
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

    /**
     * @tc.name RDB decrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbDecryptTest_0010
     * @tc.desc RDB decrypt function non-default test
     */
    it('RdbDecryptTest_0010', 0, async function () {
        console.info(TAG + "************* RdbDecryptTest_0010 start *************")
        let default_config = {
            name: "default.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
            cryptoParam: {
                encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y'])
            }
        }
        context = ability_featureAbility.getContext()
        try {
            let rdbStore = await CreateRdbStoreAndInsertData(context, default_config)
            await rdbStore.close()
        } catch (err) {
            console.error(`Query rdbStore failed, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }

        try {
            let rdbStore2 = await data_relationalStore.getRdbStore(context, STORE_CONFIG_DEFAULT)
            let resultSet = await CheckRdbStoreData(rdbStore2)
            resultSet.close()
        } catch (err) {
            console.error(`Query rdbStore failed, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }
        console.log(TAG + "************* RdbDecryptTest_0010 end *************")
    })

    /**
     * @tc.name RDB decrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbDecryptTest_0020
     * @tc.desc RDB decrypt function non-default test
     */
    it('RdbDecryptTest_0020', 0, async function () {
        console.info(TAG + "************* RdbDecryptTest_0020 start *************")

        context = ability_featureAbility.getContext()
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG_NON_DEFAULT)
            let resultSet = await CheckRdbStoreData(rdbStore)
            await rdbStore.close()
        } catch (err) {
            console.error(`Query rdbStore failed, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }
        console.info(TAG + "************* RdbDecryptTest_0020 end *************")
    })

    /**
     * @tc.name RDB decrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbDecryptTest_0030
     * @tc.desc RDB decrypt function invalid key config test
     */
     it('RdbDecryptTest_0030', 0, async function () {
        console.info(TAG + "************* RdbDecryptTest_0030 start *************")
        let invalid_key_config = {
            name: "nondefault.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
            cryptoParam: {
                iterationCount: 25000,
                encryptionAlgo: data_relationalStore.EncryptionAlgo.AES_256_CBC,
                hmacAlgo: data_relationalStore.HmacAlgo.SHA512,
                kdfAlgo: data_relationalStore.KdfAlgo.KDF_SHA512,
                cryptoPageSize: 2048
            }
        }
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_key_config)
            expect().assertFail()
        } catch (err) {
            console.error(`Invalid key config, error code: ${err.code}, err message: ${err.message}`);
            expect("401").assertEqual(err.code)
        }
        console.info(TAG + "************* RdbDecryptTest_0030 end *************")
    })

    /**
     * @tc.name RDB decrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbDecryptTest_0040
     * @tc.desc RDB decrypt function invalid iteration config test
     */
     it('RdbDecryptTest_0040', 0, async function () {
        console.info(TAG + "************* RdbDecryptTest_0040 start *************")
        let invalid_iter_config = {
            name: "nondefault.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
            cryptoParam: {
                encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y']),
                iterationCount: -1,
                encryptionAlgo: data_relationalStore.EncryptionAlgo.AES_256_CBC,
                hmacAlgo: data_relationalStore.HmacAlgo.SHA512,
                kdfAlgo: data_relationalStore.KdfAlgo.KDF_SHA512,
                cryptoPageSize: 2048
            }
        }
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_iter_config)
            expect().assertFail()
        } catch (err) {
            console.error(`Invalid iter config, error code: ${err.code}, err message: ${err.message}`);
            expect("401").assertEqual(err.code)
        }
        console.info(TAG + "************* RdbDecryptTest_0040 end *************")
    })

    /**
     * @tc.name RDB decrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbDecryptTest_0050
     * @tc.desc RDB decrypt function invalid algorithm config test
     */
    it('RdbDecryptTest_0050', 0, async function () {
        console.info(TAG + "************* RdbDecryptTest_0050 start *************")
        let invalid_algo_config = {
            name: "nondefault.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
            cryptoParam: {
                encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y']),
                iterationCount: 25000,
                encryptionAlgo: data_relationalStore.EncryptionAlgo.AES_256_CBC + 1,
                hmacAlgo: data_relationalStore.HmacAlgo.SHA512,
                kdfAlgo: data_relationalStore.KdfAlgo.KDF_SHA512,
                cryptoPageSize: 2048
            }
        }
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_algo_config)
            expect().assertFail()
        } catch (err) {
            console.error(`Invalid algorithm config, error code: ${err.code}, err message: ${err.message}`);
            expect("401").assertEqual(err.code)
        }
        console.info(TAG + "************* RdbDecryptTest_0050 end *************")
    })

    /**
     * @tc.name RDB decrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbDecryptTest_0060
     * @tc.desc RDB decrypt function invalid page size config test
     */
    it('RdbDecryptTest_0060', 0, async function () {
        console.info(TAG + "************* RdbDecryptTest_0060 start *************")
        let invalid_page_size_config = {
            name: "nondefault.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
            cryptoParam: {
                encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y']),
                iterationCount: 25000,
                encryptionAlgo: data_relationalStore.EncryptionAlgo.AES_256_CBC,
                hmacAlgo: data_relationalStore.HmacAlgo.SHA512,
                kdfAlgo: data_relationalStore.KdfAlgo.KDF_SHA512,
                cryptoPageSize: 128
            }
        }
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_page_size_config)
            expect().assertFail()
        } catch (err) {
            console.error(`Invalid algorithm config 1, error code: ${err.code}, err message: ${err.message}`);
            expect("401").assertEqual(err.code)
        }

        invalid_page_size_config.cryptoParam.cryptoPageSize = 131072
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_page_size_config)
            expect().assertFail()
        } catch (err) {
            console.error(`Invalid algorithm config 2, error code: ${err.code}, err message: ${err.message}`);
            expect("401").assertEqual(err.code)
        }

        invalid_page_size_config.cryptoParam.cryptoPageSize = 2049
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_page_size_config)
            expect().assertFail()
        } catch (err) {
            console.error(`Invalid algorithm config 3, error code: ${err.code}, err message: ${err.message}`);
            expect("401").assertEqual(err.code)
        }
        console.log(TAG + "************* RdbDecryptTest_0060 end *************")
    })

    /**
     * @tc.name RDB decrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbDecryptTest_0070
     * @tc.desc RDB decrypt function attach test
     */
    it('RdbDecryptTest_0070', 0, async function () {
        console.info(TAG + "************* RdbDecryptTest_0070 start *************")
        let config = {
            name: "DecryptTest0070.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
            cryptoParam: {
                encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y'])
            }
        }
        let plain_config = {
            name: "plain.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: false
        }

        context = ability_featureAbility.getContext()
        try {
            let rdbStore = await CreateRdbStoreAndInsertData(context, config)
            await rdbStore.close()
            let rdbStore1 = await data_relationalStore.getRdbStore(context, plain_config)
            await rdbStore1.executeSql("CREATE table t (x int, y int)")
            await rdbStore1.close()
        } catch (err) {
            console.error(`Create rdbStores failed, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }

        let store;
        try {
            store = await data_relationalStore.getRdbStore(context, plain_config)
            let number = await store.attach(context, config, "attachDB")
            expect(1).assertEqual(number)
        } catch (err) {
            console.error(`Query rdbStore failed, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }

        let valueBucket;
        try {
            let resultSet = await store.querySql("SELECT * from attachDB.t")
            resultSet.goToFirstRow()
            const x = resultSet.getLong(resultSet.getColumnIndex("x"))
            const y = resultSet.getLong(resultSet.getColumnIndex("y"))
            valueBucket = {"x" : x, "y" : y}
            resultSet.close()
        } catch (err) {
            console.error(`Read data failed, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }

        try {
            expect(0).assertEqual(await store.detach("attachDB"))
        } catch (err) {
            console.error(`Detach rdbStore, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }

        try {
            let rowId = await store.insert("t", valueBucket)
            expect(1).assertEqual(rowId)
            await CheckRdbStoreData(store)
        } catch (err) {
            console.error(`Insert and check data, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }
        
        await store.close()
        console.log(TAG + "************* RdbDecryptTest_0070 end *************")
    })

    /**
     * @tc.name RDB decrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbDecryptTest_0080
     * @tc.desc RDB decrypt function invalid page size (-1/512/4294967296/MAX_SAFE_INTEGER)
     */
    it('RdbDecryptTest_0080', 0, async function () {
        console.info(TAG + "************* RdbDecryptTest_0080 start *************")
        let invalid_page_size_config = {
            name: "nondefault.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
            cryptoParam: {
                encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y']),
                iterationCount: 25000,
                encryptionAlgo: data_relationalStore.EncryptionAlgo.AES_256_CBC,
                hmacAlgo: data_relationalStore.HmacAlgo.SHA512,
                kdfAlgo: data_relationalStore.KdfAlgo.KDF_SHA512,
                cryptoPageSize: 512
            }
        }
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_page_size_config)
            expect().assertFail()
            console.error(`Page size 512 should fail, error code: ${err.code}, err message: ${err.message}`);
        } catch (err) {
            expect("401").assertEqual(err.code)
        }

        invalid_page_size_config.cryptoParam.cryptoPageSize = -1
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_page_size_config)
            expect().assertFail()
            console.error(`Page size -1 should fail, error code: ${err.code}, err message: ${err.message}`);
        } catch (err) {
            expect("401").assertEqual(err.code)
        }

        invalid_page_size_config.cryptoParam.cryptoPageSize = 4294967296
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_page_size_config)
            expect().assertFail()
            console.error(`Page size 4294967296 should fail, error code: ${err.code}, err message: ${err.message}`);
        } catch (err) {
            expect("401").assertEqual(err.code)
        }

        invalid_page_size_config.cryptoParam.cryptoPageSize = Number.MAX_SAFE_INTEGER
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, invalid_page_size_config)
            expect().assertFail()
            console.error(`Page size MAX_SAFE_INTEGER should fail, error code: ${err.code}, err msg: ${err.message}`);
        } catch (err) {
            expect("401").assertEqual(err.code)
        }

        console.log(TAG + "************* RdbDecryptTest_0080 end *************")
    })

    /**
     * @tc.name RDB decrypt test
     * @tc.number SUB_DDM_RDB_JS_RdbDecryptTest_0090
     * @tc.desc RDB decrypt function valid page size (1024/65536) test
     */
    it('RdbDecryptTest_0090', 0, async function () {
        console.info(TAG + "************* RdbDecryptTest_0090 start *************")
        let valid_page_size_config = {
            name: "validPageSize.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
            cryptoParam: {
                encryptionKey: new Uint8Array(['t', 'e', 's', 't', 'k', 'e', 'y']),
                iterationCount: 25000,
                encryptionAlgo: data_relationalStore.EncryptionAlgo.AES_256_CBC,
                hmacAlgo: data_relationalStore.HmacAlgo.SHA512,
                kdfAlgo: data_relationalStore.KdfAlgo.KDF_SHA512,
                cryptoPageSize: 1024
            }
        }
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, valid_page_size_config)
        } catch (err) {
            console.error(`Valid page size 1024 failed, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }

        valid_page_size_config.cryptoParam.cryptoPageSize = 65536
        try {
            let rdbStore = await data_relationalStore.getRdbStore(context, valid_page_size_config)
        } catch (err) {
            console.error(`Valid page size 65536 failed, error code: ${err.code}, err message: ${err.message}`);
            expect().assertFail()
        }

        console.log(TAG + "************* RdbDecryptTest_0090 end *************")
    })

    /**
     * @tc.number testEncryptRdbAndKv0001
     * @tc.name Normal test case of using encrypt kv, then using rdb attach interface
     * @tc.desc 1.Get encrypt kv db
     *          2.Get encrypt rdb1
     *          3.Get encrypt rdb2
     *          4.rdb2.attach rdb1
     */
    it('testEncryptRdbAndKv0001', 0, async () => {
        console.log(TAG + "************* testEncryptRdbAndKv0001 start *************");
        let kvConfig = {
            bundleName: TEST_BUNDLE_NAME,
            context: context
        }
        let options = {
            createIfMissing: true,
            encrypt: true,
            backup: false,
            autoSync: false,
            kvStoreType: factory.KVStoreType.SINGLE_VERSION,
            securityLevel: factory.SecurityLevel.S2,
        }
        let rdbConfig = {
            name: "RdbTest.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
        }
        let kvManager = factory.createKVManager(kvConfig);
        try {
            let kvDb = await kvManager.getKVStore('kvDb', options)
            rdbConfig.name = "RdbTest1.db"
            let rdbStore1 = await data_relationalStore.getRdbStore(context, rdbConfig);
            rdbConfig.name = "RdbTest2.db"
            let rdbStore2 = await data_relationalStore.getRdbStore(context, rdbConfig);
            rdbStore2.close();
            await rdbStore1.attach(context, rdbConfig, "alias");
            expect(true).assertTrue();
        } catch (e) {
            console.log(TAG + e);
            expect(null).assertFail();
            console.log(TAG + "testEncryptRdbAndKv0001 failed");
        }
        await kvManager.closeKVStore(TEST_BUNDLE_NAME, 'kvDb');
        await data_relationalStore.deleteRdbStore(context, "RdbTest1.db");
        await data_relationalStore.deleteRdbStore(context, "RdbTest2.db");
        // done();
        console.log(TAG + "************* testEncryptRdbAndKv0001 end *************");
    })

    /**
     * @tc.number testEncryptRdbAndKv0002
     * @tc.name Normal test case of using encrypt kv, then using rdb attach interface
     * @tc.desc 1.Get encrypt kv db
     *          2.Get encrypt rdb1
     *          3.rdb1.backup(rdb2)
     *          4.rdb1.restore(rdb2)
     */
    it('testEncryptRdbAndKv0002', 0, async () => {
        console.log(TAG + "************* testEncryptRdbAndKv0002 start *************");
        let kvConfig = {
            bundleName: TEST_BUNDLE_NAME,
            context: context
        }
        let options = {
            createIfMissing: true,
            encrypt: true,
            backup: false,
            autoSync: false,
            kvStoreType: factory.KVStoreType.SINGLE_VERSION,
            securityLevel: factory.SecurityLevel.S2,
        }
        let rdbConfig = {
            name: "RdbTest.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
            encrypt: true,
        }
        let kvManager = factory.createKVManager(kvConfig);
        try {
            let kvDb = await kvManager.getKVStore('kvDb', options)
            rdbConfig.name = "RdbTest1.db"
            let rdbStore1 = await data_relationalStore.getRdbStore(context, rdbConfig);
            await rdbStore1?.executeSql(CREATE_TABLE_TEST);
            console.log(TAG + "testEncryptRdbAndKv0002 create table test success");
            await rdbStore1.backup("RdbTest2.db");
            console.log(TAG + "testEncryptRdbAndKv0002 backup success");
            await rdbStore1?.executeSql("drop table test");
            console.log(TAG + "testEncryptRdbAndKv0002 drop table test success");
            await rdbStore1.restore("RdbTest2.db");
            console.log(TAG + "testEncryptRdbAndKv0002 restore success");
            let valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
            };
            await rdbStore1.insert("test", valueBucket)
            expect(true).assertTrue();
        } catch (err) {
            console.log(TAG + err);
            expect(null).assertFail();
            console.log(TAG + "testEncryptRdbAndKv0002 failed");
        }
        await kvManager.closeKVStore(TEST_BUNDLE_NAME, 'kvDb');
        await data_relationalStore.deleteRdbStore(context, "RdbTest1.db");
        await data_relationalStore.deleteRdbStore(context, "RdbTest2.db");
        console.log(TAG + "************* testEncryptRdbAndKv0002 end *************");
    })
    console.log(TAG + "*************Unit Test End*************")
})
