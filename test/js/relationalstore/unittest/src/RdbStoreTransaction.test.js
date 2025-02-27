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
        await rdbStore.executeSql(CREATE_TABLE_TEST);
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        await rdbStore.executeSql("DELETE FROM test");
        console.info(TAG + 'afterEach')
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
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
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
     * @tc.number testTransactionInsert0002
     * @tc.name Abnormal test case of transaction, insert a type mismatch data
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute commit
     */
    it('testTransactionInsert0002', 0, async function (done) {
        console.log(TAG + "************* testTransactionInsert0002 start *************");
        let u8 = new Uint8Array([1, 2, 3]);
        let transaction = await rdbStore?.createTransaction({
            transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        try {
            const valueBucket = {
                "id": "test",
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            };
            let row = transaction?.insertSync("test", valueBucket);
            console.log(TAG + "testTransactionInsert0002 insert row:" + row);
            expect(null).assertFail();
            await transaction?.commit();
        } catch (e) {
            await transaction?.rollback();
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800033)
            console.log(TAG + "testTransactionInsert0002 failed");
        }
        done();
        console.log(TAG + "************* testTransactionInsert0002 end *************");
    })

    /**
     * @tc.number testTransactionInsert0003
     * @tc.name Abnormal test case of transaction, insert with an abnormal table
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data to a no exist table
     *          3.Execute commit
     */
    it('testTransactionInsert0003', 0, async function (done) {
        console.log(TAG + "************* testTransactionInsert0003 start *************");
        let u8 = new Uint8Array([1, 2, 3]);
        let transaction = await rdbStore?.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            };
            let row = await transaction?.insert("testNotExist", valueBucket);
            console.log(TAG + "testTransactionInsert0003 insert row:" + row);
            expect(null).assertFail();
            await transaction?.commit();
        } catch (e) {
            await transaction?.rollback();
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800021)
            console.log(TAG + "testTransactionInsert0003 failed");
        }
        done();
        console.log(TAG + "************* testTransactionInsert0003 end *************");
    })

    /**
     * @tc.number testTransactionInsert0004
     * @tc.name Abnormal test case of transaction, insert an more attribute data
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert insert an more attribute data
     *          3.Execute commit
     */
    it('testTransactionInsert0004', 0, async function (done) {
        console.log(TAG + "************* testTransactionInsert0004 start *************");
        let u8 = new Uint8Array([1, 2, 3]);
        let transaction = await rdbStore?.createTransaction({
            transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
                "notExist": "test"
            };
            let row = transaction?.insertSync("test", valueBucket);
            console.log(TAG + "testTransactionInsert0004 insert row:" + row);
            expect(null).assertFail();
            await transaction?.commit();
        } catch (e) {
            await transaction?.rollback();
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800021)
            console.log(TAG + "testTransactionInsert0004 failed");
        }
        done();
        console.log(TAG + "************* testTransactionInsert0004 end *************");
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
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.IMMEDIATE
        })
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
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.IMMEDIATE
        })
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
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        })
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
     * @tc.number testExecute0002
     * @tc.name Normal test case of ExecuteSql
     * @tc.desc 1.Insert data
     *          2.ExecuteSql(delete age = "18" OR "20")
     *          3.QuerySql
     */
    it('testExecute0002', 0, async function (done) {
            console.log(TAG + "************* testExecute0002 start *************");
            var transaction = await rdbStore.createTransaction()
            var u8 = new Uint8Array([1, 2, 3])
            try {
                var valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": u8,
                }
                for (let i = 0; i < 3; i++) {
                    valueBucket.age = valueBucket.age + 1;
                    var row = await transaction.insert("test", valueBucket)
                    console.log(TAG + "testExecute0002 insert row " + row)
                }
                await transaction.execute("DELETE FROM test WHERE age = ? OR age = ?", [21, 20])

                let resultSet = await transaction.querySql("select * from test")
                console.log(TAG + "testExecute0002 transaction.querySql result count " + resultSet.rowCount)
                expect(1).assertEqual(resultSet.rowCount)
                expect(true).assertEqual(resultSet.goToFirstRow())
                const age = resultSet.getLong(resultSet.getColumnIndex("age"))
                expect(19).assertEqual(age);
                await resultSet.close()
                await transaction.commit()
            } catch (e) {
                await transaction.rollback()
                console.log(TAG + e);
                expect(null).assertFail()
                console.log(TAG + "testExecute0002 failed");
            }
            done();
            console.log(TAG + "************* testExecute0002 end   *************");
        }
    )

    /**
     * @tc.number testExecute0003
     * @tc.name Normal test case of ExecuteSql
     * @tc.desc 1.Insert data (param is long string)
     *          2.Query data
     *          3.ExecuteSql (delete age = 19 AND name = nameStr)
     *          4.Query data
     */
    it('ExecuteSqlTest0003', 0, async function (done) {
        console.log(TAG + "************* testExecute0003 start *************");
        var u8 = new Uint8Array([3, 4, 5])
        var transaction = await rdbStore.createTransaction()
        var nameStr = "lisi" + "e".repeat(2000) + "zhangsan"
        var valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        var row = await transaction.insert("test", valueBucket)
        console.log(TAG + "testExecute0003 insert row " + row)
        valueBucket.name = nameStr
        for (let i = 0; i < 2; i++) {
            row = await transaction.insert("test", valueBucket)
            valueBucket.age = valueBucket.age + 1;
            console.log(TAG + "testExecute0003 insert row " + row)
        }
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", nameStr)
            let querySqlPromise = transaction.query(predicates)
            querySqlPromise.then(async (resultSet) => {
                await expect(2).assertEqual(resultSet.rowCount)
                resultSet.close()
            }).catch((err) => {
                expect(null).assertFail();
            })
            await querySqlPromise
        }
        {
            let executeSqlPromise = transaction.execute("DELETE FROM test WHERE age = 19 AND name ='" + nameStr + "'")
            executeSqlPromise.then(async () => {
                await console.log(TAG + "executeSql done.");
            }).catch((err) => {
                console.log(TAG + "executeSql failed. " + err);
                expect(null).assertFail();
            })
            await executeSqlPromise
        }
        await transaction.commit();
        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", nameStr)
            let querySqlPromise = rdbStore.query(predicates)
            querySqlPromise.then(async (resultSet) => {
                console.log(TAG + "testExecute0003 rdbStore.querySql result count " + resultSet.rowCount)
                await expect(1).assertEqual(resultSet.rowCount)
                expect(true).assertEqual(resultSet.goToFirstRow())
                const name = resultSet.getString(resultSet.getColumnIndex("name"))
                expect(nameStr).assertEqual(name)
                expect(2012).assertEqual(name.length)
                expect(18).assertEqual(resultSet.getLong(resultSet.getColumnIndex("age")))
                expect(100.5).assertEqual(resultSet.getDouble(resultSet.getColumnIndex("salary")))
                const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                expect(3).assertEqual(blobType[0])
                resultSet.close();
                done();
            }).catch((err) => {
                console.log(TAG + err);
                expect(null).assertFail();
            })
            await querySqlPromise
        }
        done();
        console.log(TAG + "************* testExecute0003 end   *************");
    })

    /**
     * @tc.number testExecute0004
     * @tc.name Normal test case of ExecuteSql, drop table
     * @tc.desc 1.Insert data
     *          2.ExecuteSql (drop table)
     */
    it('testExecute0004', 0, async function (done) {
        console.log(TAG + "************* testExecute0004 start *************");
        var u8 = new Uint8Array([3, 4, 5])
        var transaction = await rdbStore.createTransaction()
        try {
            var valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let valueBucketArray = new Array();
            for (let i = 0; i < 3; i++) {
                valueBucket.age = valueBucket.age + 1;
                valueBucketArray.push(valueBucket);
            }
            var num = await transaction.batchInsert("test", valueBucketArray)
            expect(3).assertEqual(num);
            await transaction.execute("DROP TABLE IF EXISTS test")

            let resultSet = await transaction.querySql("select * from test")
            console.log(TAG + "testExecute0004 transaction.querySql result count " + resultSet.rowCount)
            expect(resultSet.rowCount < 1).assertTrue()
            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testExecute0004 failed");
        }
        done();
        console.log(TAG + "************* testExecute0004 end   *************");
    })

    /**
     * @tc.number testExecute0005
     * @tc.name Normal test case of executeSql and querySql, PRAGMA user_version
     * @tc.desc 1.Set user_version
     *          2.Get user_version
     */
    it('testExecute0005', 0, async function (done) {
        console.log(TAG + "************* testExecute0005 start *************");
        // 2 is used to set the store version
        var transaction = await rdbStore.createTransaction()
        try {
            await transaction.execute("PRAGMA user_version = 2")
            let resultSet = await transaction.querySql("PRAGMA user_version");
            console.log(TAG + "testExecute0005 transaction.querySql result count " + resultSet.rowCount)
            resultSet.goToFirstRow();
            expect(2).assertEqual(resultSet.getLong(0))
            resultSet.close();
            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testExecute0005 failed");
        }
        done();
        console.log(TAG + "************* testExecute0005 end   *************");
    })

    /**
     * @tc.number testExecute0006
     * @tc.name Normal test case of executeSql and querySql, PRAGMA table_info
     * @tc.desc 1.Get table_info
     *          2.Check table_info
     */
    it('testExecute0006', 0, async function (done) {
        console.log(TAG + "************* testExecute0006 start *************");
        var transaction = await rdbStore.createTransaction()
        try {
            let resultSet = await transaction.querySql("PRAGMA table_info(test)");
            console.log(TAG + "testExecute0006 transaction.querySql result count " + resultSet.rowCount)
            resultSet.goToFirstRow();
            expect(0).assertEqual(resultSet.getLong(0))
            expect("id").assertEqual(resultSet.getString(1))
            expect("INTEGER").assertEqual(resultSet.getString(2))
            resultSet.goToNextRow();
            expect(1).assertEqual(resultSet.getLong(0))
            expect("name").assertEqual(resultSet.getString(1))
            expect("TEXT").assertEqual(resultSet.getString(2))
            expect(1).assertEqual(resultSet.getLong(3))
            resultSet.goToNextRow();
            expect(2).assertEqual(resultSet.getLong(0))
            expect("age").assertEqual(resultSet.getString(1))
            expect("INTEGER").assertEqual(resultSet.getString(2))
            resultSet.goToNextRow();
            expect(3).assertEqual(resultSet.getLong(0))
            expect("salary").assertEqual(resultSet.getString(1))
            expect("REAL").assertEqual(resultSet.getString(2))
            resultSet.goToNextRow();
            expect(4).assertEqual(resultSet.getLong(0))
            expect("blobType").assertEqual(resultSet.getString(1))
            expect("BLOB").assertEqual(resultSet.getString(2))
            resultSet.close();
            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testExecute0006 failed");
        }
        done();
        console.log(TAG + "************* testExecute0006 end   *************");
    })

    /**
     * @tc.number testExecute0007
     * @tc.name Normal test case of executeSql, if spaces before the sql
     * @tc.desc 1.Set user_version
     *          2.Get user_version
     */
    it('testExecute0007', 0, async function (done) {
        console.log(TAG + "************* testExecute0007 start *************");
        var transaction = await rdbStore.createTransaction()
        try {
            // 2 is used to set the store version
            await transaction.execute("   PRAGMA user_version = 2")
            let resultSet = await transaction.querySql("PRAGMA user_version");
            console.log(TAG + "testExecute0007 transaction.querySql1 result count " + resultSet.rowCount)
            resultSet.goToFirstRow();
            expect(2).assertEqual(resultSet.getLong(0))

            await transaction.execute("\r\nPRAGMA user_version = 3")
            resultSet = await transaction.querySql("PRAGMA user_version");
            console.log(TAG + "testExecute0007 transaction.querySql2 result count " + resultSet.rowCount)
            resultSet.goToFirstRow();
            expect(3).assertEqual(resultSet.getLong(0))
            resultSet.close();
            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testExecute0007 failed");
        }
        done();
        console.log(TAG + "************* testExecute0007 end   *************");
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
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
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
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        })
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
     *          3.throw 14800024
     */
    it('testTransactionIsolation0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0001 start *************");
        var exclusiveTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        })
        try {
            var trans = await rdbStore.createTransaction({
                transactionType: data_relationalStore.TransactionType.EXCLUSIVE
            })
            trans.commit();
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0001 failed");
        } catch (e) {
            await exclusiveTrans.rollback();
            console.log(TAG + e);
            expect(e.code).assertEqual(14800024)
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
     *          6.query data with DEFERRED Transaction -> no data  -> why? step 4 start isolation
     *          7.query data with Rdb -> has data
     */
    it('testTransactionIsolation0002', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0002 start *************");
        var deferredTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            var exclusiveTrans = await rdbStore.createTransaction({
                transactionType: data_relationalStore.TransactionType.EXCLUSIVE
            })
            try {
                const valueBucket = {
                    "name": "lisi",
                    "age": 18,
                    "salary": 100.5,
                }
                var insertRow = await exclusiveTrans.insert("test", valueBucket);
                console.log(TAG + "testTransactionIsolation0002 exclusiveTrans.insert row " + insertRow)
                expect(1).assertEqual(insertRow)

                var resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
                console.log(TAG + "testTransactionIsolation0002 deferredTrans querySqlSync before exclusiveTrans commit count " + resultSet.rowCount);
                expect(0).assertEqual(resultSet.rowCount);
                resultSet.close()

                await exclusiveTrans.commit();

                resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
                console.log(TAG + "testTransactionIsolation0002 deferredTrans querySqlSync after exclusiveTrans commit count " + resultSet.rowCount);
                expect(0).assertEqual(resultSet.rowCount);

                resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
                console.log(TAG + "testTransactionIsolation0002 rdbStore querySqlSync after exclusiveTrans commit count " + resultSet.rowCount);
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
        var immediateTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.IMMEDIATE
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            try {
                await rdbStore.insert("test", valueBucket);
                console.log(TAG + "testTransactionIsolation0003 rdbStore.insert success ");
                expect(null).assertFail()
            } catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800024)
                console.log(TAG + "insert failed");
            }
            var insertRow = await immediateTrans.insert("test", valueBucket);
            console.log(TAG + "testTransactionIsolation0003 immediateTrans.insert row " + insertRow);
            expect(insertRow).assertEqual(1);

            await immediateTrans.commit();

            var resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testTransactionIsolation0003 querySqlSync count " + resultSet.rowCount);
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
     *          3.insert data with DEFERRED Transaction
     *          4.query data with rdbStore -> has 2 row
     *          5.insert data with rdbStore again -> busy
     *          6.query data with DEFERRED Transaction -> has 2 row
     *          7.execute commit with DEFERRED Transaction
     *          8.insert data with rdbStore again
     *          9.query data with rdbStore -> has 3 row
     */
    it('testTransactionIsolation0004', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0004 start *************");
        var deferredTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            await rdbStore.insert("test", valueBucket);

            await deferredTrans.insert("test", valueBucket);

            var resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testTransactionIsolation0004 rdbStore.querySqlSync count " + resultSet.rowCount);
            expect(1).assertEqual(resultSet.rowCount);

            try {
                await rdbStore.insert("test", valueBucket);
                console.log(TAG + "testTransactionIsolation0004 insert success ");
                expect(null).assertFail()
            } catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800024)
                console.log(TAG + "insert failed");
            }
            resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testTransactionIsolation0004 deferredTrans.querySqlSync count " + resultSet.rowCount);
            expect(2).assertEqual(resultSet.rowCount);

            await deferredTrans.commit();

            await rdbStore.insert("test", valueBucket);

            resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testTransactionIsolation0004 rdbStore.querySqlSync after deferredTrans commit count " + resultSet.rowCount);
            expect(3).assertEqual(resultSet.rowCount);
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
     *          5.execute commit with IMMEDIATE Transaction
     *          6.insert data with DEFERRED Transaction
     *          7.execute commit with DEFERRED Transaction
     *          8.query data with rdbStore -> has 4 row
     */
    it('testTransactionIsolation0005', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0005 start *************");
        var deferredTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        var immediateTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.IMMEDIATE
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            try {
                await deferredTrans.insert("test", valueBucket);
                expect(null).assertFail()
            } catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800024)
                console.log(TAG + "insert failed");
            }
            var insertRow = await immediateTrans.insert("test", valueBucket);
            console.log(TAG + "testTransactionIsolation0005 immediateTrans.insert row " + insertRow);
            expect(1).assertEqual(insertRow);

            await immediateTrans.commit();

            insertRow = await deferredTrans.insert("test", valueBucket);
            console.log(TAG + "testTransactionIsolation0005 deferredTrans.insert after immediateTrans.commit row " + insertRow);
            expect(2).assertEqual(insertRow);

            await deferredTrans.commit();

            var resultSet = rdbStore.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testTransactionIsolation0005 querySqlSync count " + resultSet.rowCount);
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
        var deferredTrans1 = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        var deferredTrans2 = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            var rowId = await rdbStore.insert("test", valueBucket);
            console.log(TAG + "testTransactionIsolation0006 insert row " + rowId);
            expect(1).assertEqual(rowId);

            const updateValueBucket = {
                "name": "deferredTrans1",
                "age": 18,
                "salary": 100.5,
            }
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi")
            rowId = await deferredTrans1.updateSync(updateValueBucket, predicates)
            console.log(TAG + "testTransactionIsolation0006 insert row " + rowId);
            expect(1).assertEqual(rowId);

            let deletePredicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("age", "18");
            try {
                await deferredTrans2.delete(deletePredicates)
                console.log(TAG + "testTransactionIsolation0006 deferredTrans2.delete success ");
                expect(null).assertFail()
            } catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800024)
                console.log(TAG + "insert failed");
            }

            await deferredTrans1.commit();

            var resultSet = deferredTrans2.querySqlSync("select * from test");
            console.log(TAG + "testTransactionIsolation0006 deferredTrans2.querySqlSync count " + resultSet.rowCount);
            expect(1).assertEqual(resultSet.rowCount);
            expect(true).assertEqual(resultSet.goToFirstRow())
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            expect("deferredTrans1").assertEqual(name);
            resultSet.close()

            var num = await deferredTrans2.deleteSync(deletePredicates)
            console.log(TAG + "testTransactionIsolation0006 delete num " + num);
            expect(1).assertEqual(num);

            await deferredTrans2.commit();

            resultSet = rdbStore.querySqlSync("select * from test");
            console.log(TAG + "testTransactionIsolation0006 rdbStore.querySqlSync count " + resultSet.rowCount);
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

    /**
     * @tc.number testTransactionIsolation0007
     * @tc.name testTransactionIsolation. DEFERRED and EXCLUSIVE
     * @tc.desc 1.begin DEFERRED Transaction1
     *          2.begin EXCLUSIVE Transaction
     *          3.insert data with EXCLUSIVE Transaction
     *          4.execute commit with EXCLUSIVE Transaction
     *          5.query data with DEFERRED1 Transaction -> has data
     *          6.begin DEFERRED Transaction2
     *          7.query data with DEFERRED2 Transaction -> has data
     */
    it('testTransactionIsolation0007', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0007 start *************");
        var deferredTrans1 = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            var exclusiveTrans = await rdbStore.createTransaction({
                transactionType: data_relationalStore.TransactionType.EXCLUSIVE
            })
            try {
                const valueBucket = {
                    "name": "lisi",
                    "age": 18,
                    "salary": 100.5,
                }
                var insertRow = await exclusiveTrans.insert("test", valueBucket);
                console.log(TAG + "testTransactionIsolation0007 exclusiveTrans.insert row " + insertRow)
                expect(1).assertEqual(insertRow)
                await exclusiveTrans.commit();

                var resultSet = deferredTrans1.querySqlSync("select * from test where name = ?", ["lisi"]);
                console.log(TAG + "testTransactionIsolation0007 deferredTrans1 querySqlSync after exclusiveTrans commit count " + resultSet.rowCount);
                expect(1).assertEqual(resultSet.rowCount);

                var deferredTrans2 = await rdbStore.createTransaction({
                    transactionType: data_relationalStore.TransactionType.DEFERRED
                })
                try {
                    resultSet = deferredTrans2.querySqlSync("select * from test where name = ?", ["lisi"]);
                    console.log(TAG + "testTransactionIsolation0007 deferredTrans2 querySqlSync after exclusiveTrans commit count " + resultSet.rowCount);
                    expect(1).assertEqual(resultSet.rowCount);
                    resultSet.close()
                } catch (e) {
                    deferredTrans2.rollback();
                    console.log(TAG + e);
                    expect(null).assertFail()
                    console.log(TAG + "querySqlSync failed");
                }

            } catch (e) {
                exclusiveTrans.rollback();
                console.log(TAG + e);
                expect(null).assertFail()
                console.log(TAG + "insert failed");
            }
            await deferredTrans1.commit();
        } catch (e) {
            await deferredTrans1.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0007 failed");
        }
        done()
        console.log(TAG + "************* testTransactionIsolation0007 end *************");
    })

    /**
     * @tc.number testTransactionIsolation0008
     * @tc.name testTransactionIsolation. DEFERRED and rdbStore
     * @tc.desc 1.begin DEFERRED Transaction
     *          2.insert data with rdbStore
     *          3.query data with DEFERRED Transaction -> has 1 data
     *          4.begin EXCLUSIVE Transaction -> busy
     *          5.insert data with DEFERRED Transaction
     *          6.execute commit with DEFERRED Transaction
     *          7.begin EXCLUSIVE Transaction
     *          8.query data with EXCLUSIVE Transaction -> has 2 data
     */
    it('testTransactionIsolation0008', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0008 start *************");
        var deferredTrans = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            await rdbStore.insert("test", valueBucket);

            var resultSet = deferredTrans.querySqlSync("select * from test where name = ?", ["lisi"]);
            console.log(TAG + "testTransactionIsolation0008 querySqlSync1 count " + resultSet.rowCount);
            expect(1).assertEqual(resultSet.rowCount);
            resultSet.close()
            try {
                var exclusiveTrans = await rdbStore.createTransaction({
                    transactionType: data_relationalStore.TransactionType.EXCLUSIVE
                })
                console.log(TAG + "begin EXCLUSIVE success abnormal");
                await exclusiveTrans.rollback();
            } catch (e) {
                console.log(TAG + e);
                console.log(TAG + "begin EXCLUSIVE failed");
                expect(true).assertFail();
            }
            var rowId = await deferredTrans.insert("test", valueBucket);
            console.log(TAG + "testTransactionIsolation0008 deferredTrans.insert row " + rowId)
            expect(2).assertEqual(rowId);

            await deferredTrans.commit();

            try {
                var exclusiveTrans = await rdbStore.createTransaction({
                    transactionType: data_relationalStore.TransactionType.EXCLUSIVE
                })
                console.log(TAG + "begin EXCLUSIVE success");
                try {
                    resultSet = exclusiveTrans.querySqlSync("select * from test");
                    console.log(TAG + "testTransactionIsolation0008 exclusiveTrans.querySqlSync count " + resultSet.rowCount);
                    expect(2).assertEqual(resultSet.rowCount);
                    resultSet.close()
                } catch (e) {
                    console.log(TAG + e);
                    expect(null).assertFail()
                    console.log(TAG + "exclusiveTrans.querySqlSync failed");
                }
                exclusiveTrans.rollback();
            } catch (e) {
                console.log(TAG + e);
                expect(null).assertFail()
                console.log(TAG + "begin EXCLUSIVE failed");
            }
        } catch (e) {
            await deferredTrans.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0008 failed");
        }
        done()
        console.log(TAG + "************* testTransactionIsolation0008 end *************");
    })

    /**
     * @tc.number testTransactionIsolation0009
     * @tc.name testTransactionIsolation. DEFERRED and DEFERRED
     * @tc.desc 1.insert data with rdbStore
     *          2.begin DEFERRED Transaction1
     *          3.begin DEFERRED Transaction2
     *          4.update data to update1 with DEFERRED Transaction1
     *          5.query data with DEFERRED Transaction2 -> has before update data
     *          6.update update1 to update2 with DEFERRED Transaction1
     *          7.execute commit with DEFERRED Transaction1
     *          8.query data with DEFERRED Transaction2 -> has before update data
     *          9.delete data with DEFERRED Transaction2 -> busy
     *          10.execute commit with DEFERRED Transaction2
     *          11.query data with rdbStore -> has 1 row
     */
    it('testTransactionIsolation0009', 0, async function (done) {
        console.log(TAG + "************* testTransactionIsolation0009 start *************");
        var deferredTrans1 = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        var deferredTrans2 = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
            }
            var rowId = await rdbStore.insert("test", valueBucket);
            console.log(TAG + "testTransactionIsolation0009 insert row " + rowId);
            expect(1).assertEqual(rowId);

            const updateValueBucket1 = {
                "name": "update1",
                "age": 18,
                "salary": 100.5,
            }
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi")
            var num = await deferredTrans1.updateSync(updateValueBucket1, predicates)
            console.log(TAG + "testTransactionIsolation0009 updateSync 1 num " + num);
            expect(1).assertEqual(num);

            var resultSet = deferredTrans2.querySqlSync("select * from test");
            console.log(TAG + "testTransactionIsolation0009 deferredTrans2.querySqlSync1 count " + resultSet.rowCount);
            expect(1).assertEqual(resultSet.rowCount);
            expect(true).assertEqual(resultSet.goToFirstRow())
            var name = resultSet.getString(resultSet.getColumnIndex("name"))
            expect("lisi").assertEqual(name);
            resultSet.close()

            const updateValueBucket2 = {
                "name": "update2",
                "age": 18,
                "salary": 100.5,
            }
            predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "update1")
            var num = await deferredTrans1.updateSync(updateValueBucket2, predicates)
            console.log(TAG + "testTransactionIsolation0009 updateSync 2 num " + num);
            expect(1).assertEqual(num);

            await deferredTrans1.commit();

            resultSet = deferredTrans2.querySqlSync("select * from test");
            console.log(TAG + "testTransactionIsolation0009 deferredTrans2.querySqlSync2 count " + resultSet.rowCount);
            expect(1).assertEqual(resultSet.rowCount);
            expect(true).assertEqual(resultSet.goToFirstRow())
            name = resultSet.getString(resultSet.getColumnIndex("name"))
            expect("lisi").assertEqual(name);
            resultSet.close()

            let deletePredicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("age", "18");
            try {
                num = await deferredTrans2.delete(deletePredicates)
                console.log(TAG + "testTransactionIsolation0009 delete num " + num);
                expect(null).assertFail()
            } catch (e) {
                console.log(TAG + e);
                expect(e.code).assertEqual(14800024)
            }
            await deferredTrans2.commit();

            resultSet = rdbStore.querySqlSync("select * from test");
            console.log(TAG + "testTransactionIsolation0009 rdbStore.querySqlSync count " + resultSet.rowCount);
            expect(1).assertEqual(resultSet.rowCount);
            resultSet.close()
        } catch (e) {
            await deferredTrans2.rollback();
            await deferredTrans1.rollback();
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testTransactionIsolation0009 failed");
        }
        done()
        console.log(TAG + "************* testTransactionIsolation0009 end *************");
    })

    /**
     * @tc.number testTransactionEnd0001
     * @tc.name Query data with closed transaction
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute commit
     *          4.Query data with transaction -> throw 14800014
     */
    it('testTransactionEnd0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionEnd0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.IMMEDIATE
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var num = await transaction.insert("test", valueBucket)
            expect(1).assertEqual(num);
            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await transaction.query(predicates)
            console.log(TAG + "testTransactionEnd0001 result count " + resultSet.rowCount)
            expect(null).assertFail()
            resultSet.close()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800014)
        }
        done()
        console.log(TAG + "************* testTransactionEnd0001 end *************");
    })

    /**
     * @tc.number testTransactionEnd0002
     * @tc.name Query data with closed transaction
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Query data with transaction -> get resultSet
     *          4.Execute commit
     *          5.resultSet go to first row -> throw 14800014
     */
    it('testTransactionEnd0002', 0, async function (done) {
        console.log(TAG + "************* testTransactionEnd0002 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        })
        let resultSet;
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
            resultSet = await transaction.query(predicates)
            console.log(TAG + "testTransactionEnd0002 result count " + resultSet.rowCount)
            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
        }
        expect(false).assertEqual(resultSet.goToFirstRow())
        done()
        console.log(TAG + "************* testTransactionEnd0002 end *************");
    })

    /**
     * @tc.number testTransactionEnd0003
     * @tc.name Insert data with closed transaction
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute commit
     *          4.Insert data with closed transaction -> throw 14800014
     */
    it('testTransactionEnd0003', 0, async function (done) {
        console.log(TAG + "************* testTransactionEnd0003 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        try {
            var rowId = await transaction.insert("test", valueBucket)
            expect(1).assertEqual(rowId);
            await transaction.commit()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
        }
        try {
            rowId = await transaction.insert("test", valueBucket)
            console.log(TAG + "testTransactionEnd0003 insert rowId " + rowId)
            expect(null).assertFail()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800014)
        }
        done()
        console.log(TAG + "************* testTransactionEnd0003 end *************");
    })

    /**
     * @tc.number testTransactionEnd0004
     * @tc.name Update data with closed transaction
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute rollback
     *          4.Update data with closed transaction -> throw 14800014
     */
    it('testTransactionEnd0004', 0, async function (done) {
        console.log(TAG + "************* testTransactionEnd0004 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.IMMEDIATE
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var rowId = await transaction.insert("test", valueBucket)
            expect(1).assertEqual(rowId);
            await transaction.rollback()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi");
            const updateValueBucket = {
                "name": "update",
                "age": 28,
                "salary": 25,
                "blobType": u8,
            }
            rowId = await transaction.update(updateValueBucket, predicates)
            console.log(TAG + "testTransactionEnd0004 update rowId " + rowId)
            expect(null).assertFail()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800014)
        }
        done()
        console.log(TAG + "************* testTransactionEnd0004 end *************");
    })

    /**
     * @tc.number testTransactionEnd0005
     * @tc.name Delete data with closed transaction
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute rollback
     *          4.Delete data with closed transaction -> throw 14800014
     */
    it('testTransactionEnd0005', 0, async function (done) {
        console.log(TAG + "************* testTransactionEnd0005 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var rowId = await transaction.insert("test", valueBucket)
            expect(1).assertEqual(rowId);
            await transaction.rollback()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("test");
            predicates.equalTo("name", "lisi");
            var num = transaction.deleteSync(predicates)
            console.log(TAG + "testTransactionEnd0005 delete num " + num)
            expect(null).assertFail()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800014)
        }
        done()
        console.log(TAG + "************* testTransactionEnd0005 end *************");
    })

    /**
     * @tc.number testTransactionEnd0006
     * @tc.name Execute Sql with closed transaction
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute rollback
     *          4.Execute Sql with closed transaction -> throw 14800014
     */
    it('testTransactionEnd0006', 0, async function (done) {
        console.log(TAG + "************* testTransactionEnd0006 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var rowId = await transaction.insert("test", valueBucket)
            expect(1).assertEqual(rowId);
            await transaction.rollback()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
        }
        try {
            let ret = transaction.executeSync("PRAGMA integrity_check");
            console.log(TAG + "testTransactionEnd0006 executeSync PRAGMA integrity_check: " + ret)
            expect(null).assertFail()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800014)
        }
        done()
        console.log(TAG + "************* testTransactionEnd0006 end *************");
    })

    /**
     * @tc.number testTransactionEnd0007
     * @tc.name Execute Sql with closed transaction
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute rollback
     *          4.Commit with closed transaction -> throw 14800014
     */
    it('testTransactionEnd0007', 0, async function (done) {
        console.log(TAG + "************* testTransactionEnd0007 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        var transaction = await rdbStore.createTransaction({
            transactionType: data_relationalStore.TransactionType.DEFERRED
        })
        try {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            var rowId = await transaction.insert("test", valueBucket)
            expect(1).assertEqual(rowId);
            await transaction.rollback()
        } catch (e) {
            await transaction.rollback()
            console.log(TAG + e + " code: " + e.code);
            expect(null).assertFail()
        }
        try {
            await transaction.commit();
            console.log(TAG + "testTransactionEnd0007 commit success")
            expect(null).assertFail()
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(14800014)
        }
        done()
        console.log(TAG + "************* testTransactionEnd0007 end *************");
    })

    /**
     * @tc.number testTransactionBusy0001
     * @tc.name Abnormal test case of createTransaction
     * @tc.desc 1.Execute beginTransaction 5 times
     */
    it('testTransactionBusy0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionBusy0001 start *************");
        let transactions = [];
        try {
            for (let i = 0; i < 5; i++) {
                transactions.push(await rdbStore?.createTransaction({
                    transactionType: data_relationalStore.TransactionType.DEFERRED
                }));
                console.log(TAG + "testTransactionBusy0001 createTransaction success. i " + i);
            }
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            // expect(e.code).assertEqual(14800000)
            expect(e.code).assertEqual(14800015)
            console.log(TAG + "testTransactionBusy0001 failed");
        }
        done();
        transactions.forEach(element => {
            element?.rollback();
            console.log(TAG + "testTransactionBusy0001 rollback");
        });
        console.log(TAG + "************* testTransactionBusy0001 end *************");
    })

    /**
     * @tc.number testTransactionWithReadOnlyStore0001
     * @tc.name createTransactionWithReadOnlyStore
     * @tc.desc 1.Get a readOnly store
     *          2.createTransaction with readOnly store
     */
    it('testTransactionWithReadOnlyStore0001', 0, async function (done) {
        console.log(TAG + "************* testTransactionWithReadOnlyStore0001 start *************");
        let storeConfig = {
            name: "ReadOnlyTransactionTest.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
        }
        let store = await data_relationalStore.getRdbStore(context, storeConfig);
        await store.close()
        storeConfig.isReadOnly = true;
        let readOnlyStore = await data_relationalStore.getRdbStore(context, storeConfig);
        expect(readOnlyStore === null).assertFalse();
        try {
            let transaction = await readOnlyStore?.createTransaction({
                transactionType: data_relationalStore.TransactionType.DEFERRED
            });
            console.log(TAG + "testTransactionWithReadOnlyStore0001 createTransaction success");
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
            };
            let row = transaction?.insertSync("test", valueBucket);
            console.log(TAG + "testTransactionWithReadOnlyStore0001 insert row:" + row);
            await transaction?.rollback();
            expect(null).assertFail();
        } catch (e) {
            console.log(TAG + e + " code: " + e.code);
            expect(e.code).assertEqual(801)
            console.log(TAG + "testTransactionWithReadOnlyStore0001 success");
        }
        await data_relationalStore.deleteRdbStore(context, storeConfig);
        done();
        console.log(TAG + "************* testTransactionWithReadOnlyStore0001 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})