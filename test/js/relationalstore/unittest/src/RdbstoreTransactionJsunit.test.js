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
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY, " + 
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "TransactionInsertTest.db",
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
     * @tc.number testRdbTransactionInsert0001
     * @tc.name Normal test case of transactions, insert a row of data
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute commit
     *          4.Query data
     */
    it('testRdbTransactionInsert0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            rdbStore.beginTransaction()
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)

            rdbStore.commit()

            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates)
            console.log(TAG + "testRdbTransactionInsert0001 result count " + resultSet.rowCount)
            expect(1).assertEqual(resultSet.rowCount)
            resultSet.close()
        } catch (e) {
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testRdbTransactionInsert0001 failed");
        }
        done()
        console.log(TAG + "************* testRdbTransactionInsert0001 end *************");
    })

    /**
     * @tc.number testRdbTransactionInsert0002
     * @tc.name Normal test case of transaction, insert three rows of data
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute commit
     *          4.Query data
     */
    it('testRdbTransactionInsert0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreInsert0002 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            rdbStore.beginTransaction()
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)

            const valueBucket1 = {
                "name": "zhangsan",
                "age": 20,
                "salary": 9.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket1)


            const valueBucket2 = {
                "name": "wangwu",
                "age": 16,
                "salary": 99,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket2)

            rdbStore.commit()

            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates)
            expect(3).assertEqual(resultSet.rowCount)
            resultSet.close()
        } catch (e) {
            expect(null).assertFail()
            console.log(TAG + "testRdbTransactionInsert0002 failed");
        }
        done()
        console.log(TAG + "************* testRdbTransactionInsert0002 end *************");
    })


    /**
     * @tc.number testRdbTransactionInsert0003
     * @tc.name Normal test case of transaction, query data before commit
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Query data (expect 0 row)
     *          4.Insert data
     *          5.Execute commit
     */
    it('testRdbTransactionInsert0003', 0, async function (done) {
        console.log(TAG + "************* testRdbTransactionInsert0003 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            rdbStore.beginTransaction()
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)

            const valueBucket1 = {
                "name": "zhangsan",
                "age": 20,
                "salary": 9.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket1)

            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates)
            expect(0).assertEqual(resultSet.rowCount)
            resultSet.close()
            const valueBucket2 = {
                "name": "wangwu",
                "age": 16,
                "salary": 99,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket2)

            rdbStore.commit()
        } catch (e) {
            expect(null).assertFail()
            console.log(TAG + "testRdbTransactionInsert0003 failed");
        }
        done()
        console.log(TAG + "************* testRdbTransactionInsert0003 end *************");
    })

    /**
     * @tc.number testRdbTransactionInsert0004
     * @tc.name Abnormal test case of transaction insert, if catch exception then rollback
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data (primary key conflict)
     *          3.Execute rollBack
     *          4.Query data
     */
    it('testRdbTransactionRollBack0001', 0, async function (done) {
        console.log(TAG + "************* testRdbTransactionRollBack0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            rdbStore.beginTransaction()
            const valueBucket = {
                "id": 1,
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
            await rdbStore.insert("test", valueBucket)

            rdbStore.commit()
        } catch (e) {
            rdbStore.rollBack()
            let predicates = new data_relationalStore.RdbPredicates("test");
            let resultSet = await rdbStore.query(predicates)
            console.log(TAG + "testRdbTransactionRollBack0001 result count " + resultSet.rowCount);
            expect(0).assertEqual(resultSet.rowCount)
            resultSet.close()
        }
        done()
        console.log(TAG + "************* testRdbTransactionRollBack0001 end *************");
    })

    /**
     * @tc.number testRdbTransactionInsert0005
     * @tc.name Normal test case of transaction, begin transactions within a transaction
     * @tc.desc 1.Execute beginTransaction
     *          2.Insert data
     *          3.Execute beginTransaction
     *          4.Insert data
     *          5.Execute rollBack
     *          6.Insert data
     *          7.Execute commit
     *          8.Query data
     */
    it('testRdbTransactionMulti0003', 0, async function (done) {
        console.log(TAG + "************* testRdbTransactionMulti0003 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        try {
            rdbStore.beginTransaction()
            const valueBucket = {
                "id": 1,
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket);

            rdbStore.beginTransaction()
            const valueBucket1 = {
                "name": "zhangsan",
                "age": 20,
                "salary": 220.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket1)

            rdbStore.rollBack()

            await rdbStore.insert("test", valueBucket)
            rdbStore.commit()

            let predicates = new data_relationalStore.RdbPredicates("test");
            let ret = await rdbStore.query(predicates)
            expect(1).assertEqual(ret.rowCount)
            ret.close()
        } catch (e) {
            rdbStore.rollBack()
            console.log(TAG + "testRdbTransactionMulti0003 rollback ***** ");
        }
        done()
        console.log(TAG + "************* testRdbTransactionMulti0003 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");

})