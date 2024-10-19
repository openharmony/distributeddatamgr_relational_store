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

const TAG = "[RELATIONAL_STORE_TRANSACTION_JSKITS_TEST]"
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
        await data_relationalStore.deleteRdbStore(context, "TransactionTest.db");
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
        var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var num = await transaction.insert("test", valueBucket)
            expect(1).assertEqual(num);

            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await transaction.query(predicates)
            console.log(TAG + "testTransactionInsert0001 result count " + resultSet.rowCount)
            expect(1).assertEqual(resultSet.rowCount)
            resultSet.close()
            await transaction.commit()
        } catch (e) {
            await transaction.commit()
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
        var transaction = await rdbStore.createTransaction()
        try {
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
            var num = await transaction.batchInsert("test", valueBucketArray)
            expect(2).assertEqual(num);

            let resultSet = await transaction.querySql("select * from test")
            console.log(TAG + "testTransactionBatchInsert0001 result count " + resultSet.rowCount)
            expect(2).assertEqual(resultSet.rowCount)
            resultSet.close()

            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
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
        var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.IMMEDIATE)
        try {
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
            var num = await transaction.update(updateValueBucket, predicates)
            expect(1).assertEqual(num);

            let resultSet = await transaction.querySql("select * from test")
            console.log(TAG + "testTransactionUpdate0001 result count " + resultSet.rowCount)
            expect(1).assertEqual(resultSet.rowCount)
            expect(true).assertEqual(resultSet.goToFirstRow())
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            expect("update").assertEqual(name);
            const age = resultSet.getLong(resultSet.getColumnIndex("age"))
            expect(28).assertEqual(age);
            const salary = resultSet.getLong(resultSet.getColumnIndex("salary"))
            expect(25).assertEqual(salary);
            resultSet.close()
            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
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
        var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.EXCLUSIVE)
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await transaction.insert("test", valueBucket)

            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi");
            var num = await transaction.delete(predicates)
            expect(1).assertEqual(num);

            let resultSet = await transaction.querySql("select * from test")
            console.log(TAG + "testTransactionDelete0001 result count " + resultSet.rowCount)
            expect(0).assertEqual(resultSet.rowCount)
            resultSet.close()
            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionDelete0001 failed");
        }
        done()
        console.log(TAG + "************* testTransactionDelete0001 end *************");
    })

    /**
     * @tc.number testExecute0001
     * @tc.name Normal test case of Execute, check integrity for store
     * @tc.desc 1. Execute sql: PRAGMA integrity_check
     *          2. Check returned value
     */
    it('testExecute0001', 0, async function (done) {
        console.info(TAG + "************* testExecute0001 start *************");
        var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.EXCLUSIVE)
        try {
            let ret = await transaction.execute("PRAGMA integrity_check");
            expect("ok").assertEqual(ret);
            await transaction.commit();
        } catch (err) {
            await transaction.rollback();
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
    it('testTransactionSyncInterface0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionSyncInterface0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var num = await transaction.insertSync("test", valueBucket, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
            expect(1).assertEqual(num);
            const updateValueBucket = {
                "name": "update",
                "age": 28,
                "salary": 25,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi")
            num = await transaction.updateSync(updateValueBucket, predicates)
            expect(1).assertEqual(num);

            let deletePredicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "update")
            num = await transaction.deleteSync(deletePredicates);
            expect(1).assertEqual(num);

            let resultSet = await transaction.querySqlSync("select * from test")
            console.log(TAG + "testTransactionSyncInterface0001 result count " + resultSet.rowCount)
            expect(0).assertEqual(resultSet.rowCount)
            resultSet.close()

            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionSyncInterface0001 failed");
        }
        done()
        console.log(TAG + "************* testTransactionSyncInterface0001 end *************");
    })

    /**
     * @tc.number testTransactionRollback0001
     * @tc.name Normal test case of transactions, insert and update a row of data
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.rollback data
     *          4.Query data
     */
    it('testTransactionRollback0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionRollback0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction(data_relationalStore.TransactionType.EXCLUSIVE)
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await transaction.insert("test", valueBucket)

            await transaction.rollback()

            let resultSet = rdbStore.querySqlSync("select * from test")
            console.log(TAG + "testTransactionRollback0001 result count " + resultSet.rowCount)
            expect(0).assertEqual(resultSet.rowCount)
            resultSet.close()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionRollback0001 failed");
        }
        done()
        console.log(TAG + "************* testTransactionRollback0001 end *************");
    })

    /**
     * @tc.number testTransactionIsolation0001
     * @tc.name testTransactionIsolation. EXCLUSIVE and EXCLUSIVE
     * @tc.desc 1.begin EXCLUSIVE Transaction
     *          2.begin EXCLUSIVE Transaction again
     *          3.throw 14800015
     */
    it('testTransactionIsolation0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0001 start *************");
        var exclusiveTrans = await rdbStore.createTransaction(data_relationalStore.TransactionType.EXCLUSIVE)
        try {
            var trans = await rdbStore.createTransaction(data_relationalStore.TransactionType.EXCLUSIVE)
            trans.commit();
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0001 failed");
        } catch (e) {
            await exclusiveTrans.rollback();
            console.log(TAG + e);
            expect(e.code).assertEqual(14800015)
            console.log(TAG + "testTransactionIsolation0001 success");
        }
        done()
        console.log(TAG + "************* testTransactionIsolation0001 end *************");
    })

    /**
     * @tc.number testTransactionIsolation0002
     * @tc.name testTransactionIsolation. DEFERRED and EXCLUSIVE
     * @tc.desc 1.begin DEFERRED Transaction
     *          2.begin EXCLUSIVE Transaction again
     *          3.insert data with EXCLUSIVE Transaction
     *          4.query data with DEFERRED Transaction -> no data
     *          5.execute commit with EXCLUSIVE Transaction
     *          6.query data with DEFERRED Transaction -> has data
     */
    it('testTransactionIsolation0002', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0002 start *************");
        var deferredTrans = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
        try {
            var exclusiveTrans = await rdbStore.createTransaction(data_relationalStore.TransactionType.EXCLUSIVE)
            try {
                const valueBucket = {
                    "name": "lisi",
                    "age": 18,
                    "salary": 100.5,
                }
                var insertRow = await exclusiveTrans.insert("test", valueBucket);
                expect(1).assertEqual(insertRow)

                var resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
                expect(0).assertEqual(resultSet.rowCount);
                resultSet.close()

                await exclusiveTrans.commit();

                resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
                expect(1).assertEqual(resultSet.rowCount);
                resultSet.close()

            } catch (e) {
                exclusiveTrans.rollback();
                console.log(TAG + e);
                expect(null).assertFail()
                console.log(TAG + "insert failed");
            }
            await deferredTrans.commit();
        } catch (e) {
            await deferredTrans.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0002 failed");
        }
        done()
        console.log(TAG + "************* testTransactionIsolation0002 end *************");
    })

    /**
     * @tc.number testTransactionIsolation0003
     * @tc.name testTransactionIsolation. IMMEDIATE and rdbStore
     * @tc.desc 1.begin IMMEDIATE Transaction
     *          2.insert data with rdbStore -> busy
     *          3.insert data with IMMEDIATE Transaction
     *          4.execute commit with IMMEDIATE Transaction
     *          5.query data with rdbStore -> has data
     */
    it('testTransactionIsolation0003', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0003 start *************");
        var immediateTrans = await rdbStore.createTransaction(data_relationalStore.TransactionType.IMMEDIATE)
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            try {
                await rdbStore.insert("test", valueBucket);
                expect(null).assertFail()
            } catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800015)
                console.log(TAG + "insert failed");
            }
            var insertNum = await immediateTrans.insert("test", valueBucket);
            expect(insertNum).assertEqual(1);

            await immediateTrans.commit();

            var resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            expect(1).assertEqual(resultSet.rowCount);
            resultSet.close()
        } catch (e) {
            await immediateTrans.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0003 failed");
        }
        done()
        console.log(TAG + "************* testTransactionIsolation0003 end *************");
    })

    /**
     * @tc.number testTransactionIsolation0004
     * @tc.name testTransactionIsolation. DEFERRED and rdbStore
     * @tc.desc 1.begin DEFERRED Transaction
     *          2.insert data with rdbStore
     *          3.query data with DEFERRED Transaction -> has data
     *          4.insert data with rdbStore again
     *          5.insert data with DEFERRED Transaction
     *          6.query data with rdbStore -> has 2 row
     *          7.insert data with rdbStore again -> busy
     *          8.query data with DEFERRED Transaction -> has 3 row
     *          9.execute commit with DEFERRED Transaction
     *          10.insert data with rdbStore again
     *          11.query data with rdbStore -> has 4 row
     */
    it('testTransactionIsolation0004', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0004 start *************");
        var deferredTrans = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            await rdbStore.insert("test", valueBucket);

            var resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
            expect(1).assertEqual(resultSet.rowCount);
            resultSet.close()

            await rdbStore.insert("test", valueBucket);

            await deferredTrans.insert("test", valueBucket);

            resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            expect(2).assertEqual(resultSet.rowCount);

            try {
                await rdbStore.insert("test", valueBucket);
                expect(null).assertFail()
            } catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800015)
                console.log(TAG + "insert failed");
            }
            resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
            expect(3).assertEqual(resultSet.rowCount);

            await deferredTrans.commit();

            await rdbStore.insert("test", valueBucket);

            resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            expect(4).assertEqual(resultSet.rowCount);
            resultSet.close()
        } catch (e) {
            await deferredTrans.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0004 failed");
        }
        done()
        console.log(TAG + "************* testTransactionIsolation0004 end *************");
    })

    /**
     * @tc.number testTransactionIsolation0005
     * @tc.name testTransactionIsolation. DEFERRED and IMMEDIATE
     * @tc.desc 1.begin DEFERRED Transaction
     *          2.begin IMMEDIATE Transaction
     *          3.insert data with DEFERRED Transaction -> busy
     *          4.insert data with IMMEDIATE Transaction
     *          5.query data with DEFERRED Transaction -> no data
     *          6.execute commit with IMMEDIATE Transaction
     *          7.insert data with DEFERRED Transaction
     *          8.execute commit with DEFERRED Transaction
     *          9.query data with rdbStore -> has 4 row
     */
    it('testTransactionIsolation0005', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0005 start *************");
        var deferredTrans = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
        var immediateTrans = await rdbStore.createTransaction(data_relationalStore.TransactionType.IMMEDIATE)
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            try {
                await deferredTrans.insert("test", valueBucket);
                expect(null).assertFail()
            }
            catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800015)
                console.log(TAG + "insert failed");
            }
            var num = await immediateTrans.insert("test", valueBucket);
            expect(1).assertEqual(num);

            var resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
            expect(1).assertEqual(resultSet.rowCount);
            resultSet.close()

            await immediateTrans.commit();

            num = await deferredTrans.insert("test", valueBucket);
            expect(1).assertEqual(num);

            await deferredTrans.commit();

            resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            expect(2).assertEqual(resultSet.rowCount);
            resultSet.close()
        } catch (e) {
            await immediateTrans.rollback();
            await deferredTrans.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0005 failed");
        }
        done()
        console.log(TAG + "************* testTransactionIsolation0005 end *************");
    })

    /**
     * @tc.number testTransactionIsolation0006
     * @tc.name testTransactionIsolation. DEFERRED and DEFERRED
     * @tc.desc 1.insert data with rdbStore
     *          2.begin DEFERRED Transaction1
     *          3.begin DEFERRED Transaction2
     *          4.update data with DEFERRED Transaction1
     *          5.delete data with DEFERRED Transaction2 -> busy
     *          6.execute commit with DEFERRED Transaction1
     *          7.query data with DEFERRED Transaction2 -> has updated data
     *          8.delete data with DEFERRED Transaction2
     *          9.execute commit with DEFERRED Transaction2
     *          10.query data with rdbStore -> has 0 row
     */
    it('testTransactionIsolation0006', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0006 start *************");
        var deferredTrans1 = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
        var deferredTrans2 = await rdbStore.createTransaction(data_relationalStore.TransactionType.DEFERRED)
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            var num = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(num);

            const updateValueBucket = {
                "name": "deferredTrans1",
                "age": 18,
                "salary": 100.5,
            }
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi")
            num = await deferredTrans1.updateSync(updateValueBucket, predicates)
            expect(1).assertEqual(num);

            let deletePredicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("age", "18");
            try{
                await deferredTrans2.delete(deletePredicates)
            }catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800015)
                console.log(TAG + "insert failed");
            }

            await deferredTrans1.commit();

            var resultSet = deferredTrans2.querySqlSync("select * from test");
            expect(1).assertEqual(resultSet.rowCount);
            expect(true).assertEqual(resultSet.goToFirstRow())
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            expect("deferredTrans1").assertEqual(name);
            resultSet.close()

            num = await deferredTrans2.deleteSync(deletePredicates)
            expect(1).assertEqual(num);

            await deferredTrans2.commit();

            resultSet = rdbStore.querySqlSync("select * from test");
            expect(0).assertEqual(resultSet.rowCount);
            resultSet.close()
        } catch (e) {
            await deferredTrans2.rollback();
            await deferredTrans1.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0006 failed");
        }
        done()
        console.log(TAG + "************* testTransactionIsolation0006 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})