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
var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY, " +
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "TransactionTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}

var rdbStore = undefined;

describe('rdbStoreTransactionTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')

    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await rdbStore.executeSql("DELETE FROM test");
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "TransactionInsertTest.db");
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number testTransactionInsert0001
     * @tc.name Normal test case of transactions, insert a row of data
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute commit
     *          4.Query data
     */
    it('testTransactionInsert0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionInsert0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var num = await transaction.insert("test", valueBucket)
            expect(1).assertEqual(num);

            await transaction.commit()

            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await transaction.query(predicates)
            // console.log(TAG + "testTransactionInsert0001 result count " + resultSet.rowCount)
            // expect(1).assertEqual(resultSet.rowCount)
            // resultSet.close()
        } catch (e) {
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionInsert0001 failed");
        }
        done()
        console.log(TAG + "************* testTransactionInsert0001 end *************");
    })

    /**
     * @tc.number testTransactionBatchInsert0001
     * @tc.name Normal test case of transactions, insert a row of data
     * @tc.desc 1.Execute beginTransaction
     *          2.BatchInsert data
     *          3.Execute commit
     *          4.Query data
     */
    it('testTransactionBatchInsert0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionBatchInsert0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let valueBucketArray = new Array();
            for (let i = 0; i < 2; i++) {
                valueBucketArray.push(valueBucket);
            }
            var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
            var num = await transaction.batchInsert("test", valueBucketArray)
            expect(2).assertEqual(num);

            await transaction.commit()

            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await transaction.query(predicates)
            // console.log(TAG + "testTransactionBatchInsert0001 result count " + resultSet.rowCount)
            // expect(2).assertEqual(resultSet.rowCount)
            // resultSet.close()
        } catch (e) {
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionBatchInsert0001 failed");
        }
        done()
        console.log(TAG + "************* testTransactionBatchInsert0001 end *************");
    })

    /**
     * @tc.number testTransactionUpdate0001
     * @tc.name Normal test case of transactions, insert and update a row of data
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          2.Update data
     *          3.Execute commit
     *          4.Query data
     */
    it('testTransactionUpdate0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionUpdate0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.IMMEDIATE)
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await transaction.insert("test", valueBucket)

            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi");
            const updateValueBucket = {
                "name": "update",
                "age": 28,
                "salary": 25,
                "blobType": u8,
            }
            var num = await transaction.update("test", updateValueBucket)
            expect(1).assertEqual(num);
            await transaction.commit()

            let resultSet = await transaction.query(predicates)
            // console.log(TAG + "testTransactionInsert0001 result count " + resultSet.rowCount)
            // expect(1).assertEqual(resultSet.rowCount)
            // expect(true).assertEqual(resultSet.goToFirstRow())
            // const name = resultSet.getString(resultSet.getColumnIndex("name"))
            // expect("update").assertEqual(name);
            // const age = resultSet.getLong(resultSet.getColumnIndex("age"))
            // expect(28).assertEqual(age);
            // const salary = resultSet.getLong(resultSet.getColumnIndex("salary"))
            // expect(25).assertEqual(age);
            // resultSet.close()
        } catch (e) {
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionUpdate0001 failed");
        }
        done()
        console.log(TAG + "************* testTransactionUpdate0001 end *************");
    })

    /**
     * @tc.number testTransactionDelete0001
     * @tc.name Normal test case of transactions, insert and update a row of data
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          2.Delete data
     *          3.Execute commit
     *          4.Query data
     */
    it('testTransactionDelete0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionDelete0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.EXCLUSIVE)
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await transaction.insert("test", valueBucket)

            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi");
            var num = await transaction.delete(updateValueBucket)
            expect(1).assertEqual(num);
            await transaction.commit()

            let resultSet = await transaction.query(predicates)
            // console.log(TAG + "testTransactionInsert0001 result count " + resultSet.rowCount)
            // expect(0).assertEqual(resultSet.rowCount)
            // resultSet.close()
        } catch (e) {
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionDelete0001 failed");
        }
        done()
        console.log(TAG + "************* testTransactionDelete0001 end *************");
    })

    /**
     * @tc.number testTransactionDelete0001
     * @tc.name Normal test case of Execute, check integrity for store
     * @tc.desc 1. Execute sql: PRAGMA integrity_check
     *          2. Check returned value
     */
    it('testExecute0001', 0, async function (done) {
        console.info(TAG + "************* testExecute0001 start *************");
        try {
            var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.EXCLUSIVE)
            let ret = await transaction.execute("PRAGMA integrity_check");
            expect("ok").assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`integrity_check failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testExecute0001 end   *************");
    })

    /**
     * @tc.number testTransactionSyncInterface0001
     * @tc.name Normal test case of transactions, insert a row of data
     * @tc.desc 1.Execute beginTransaction
     *          2.BatchInsertSync data
     *          3.InsertSync data
     *          4.UpdateSync data
     *          5.DeleteSync data
     *          6.Execute commit
     *          7.querySqlSync
     *          7.ExecuteSync
     */
    it('testTransactionInsert0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionInsert0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var num = await transaction.insert("test", valueBucket)
            expect(1).assertEqual(num);

            await transaction.commit()

            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await transaction.query(predicates)
            // console.log(TAG + "testTransactionInsert0001 result count " + resultSet.rowCount)
            // expect(1).assertEqual(resultSet.rowCount)
            // resultSet.close()
        } catch (e) {
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionInsert0001 failed");
        }
        done()
        console.log(TAG + "************* testTransactionInsert0001 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");

})