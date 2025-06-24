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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

var context = globalThis.abilityContext;

const TAG = "[RELATIONAL_STORE_TRANSACTION_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
  name: "TransactionTest.db",
  securityLevel: data_relationalStore.SecurityLevel.S3,
}

var rdbStore = undefined;

export default function () {
  describe('rdbStoreTransactionJsunitTest', function () {
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


    it('testRdbTransInsert0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsert0001 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbTrans.insert("test", valueBucket);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsert0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsert0001 failed");
      }

      console.log(TAG + "************* testRdbTransInsert0001 end *************");
      done();
    })

    it('testRdbTransInsert0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsert0002 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbTrans.insert("test", valueBucket);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsert0002 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsert0002 failed");
      }

      console.log(TAG + "************* testRdbTransInsert0002 end *************");
      done();
    })

    it('testRdbTransInsert0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsert0003 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbTrans.insert("test", valueBucket);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsert0003 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsert0003 failed");
      }

      console.log(TAG + "************* testRdbTransInsert0003 end *************");
      done();
    })

    it('testRdbTransInsert0011', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsert0011 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbTrans.insert("test", valueBucket);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsert0011 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsert0011 failed");
      }

      console.log(TAG + "************* testRdbTransInsert0011 end *************");
      done();
    })

    it('testRdbTransInsert0012', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsert0012 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbTrans.insert("test", valueBucket);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsert0012 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsert0012 failed");
      }

      console.log(TAG + "************* testRdbTransInsert0012 end *************");
      done();
    })

    it('testRdbTransInsert0013', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsert0013 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbTrans.insert("test", valueBucket);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsert0013 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsert0013 failed");
      }

      console.log(TAG + "************* testRdbTransInsert0013 end *************");
      done();
    })

    it('testRdbTransInsertSync0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsertSync0001 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = rdbTrans.insertSync("test", valueBucket);
        expect(1).assertEqual(rowId);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsertSync0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsertSync0001 failed");
      }

      console.log(TAG + "************* testRdbTransInsertSync0001 end *************");
      done();
    })

    it('testRdbTransInsertSync0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsertSync0002 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = rdbTrans.insertSync("test", valueBucket);
        expect(1).assertEqual(rowId);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsertSync0002 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsertSync0002 failed");
      }

      console.log(TAG + "************* testRdbTransInsertSync0002 end *************");
      done();
    })

    it('testRdbTransInsertSync0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsertSync0003 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = rdbTrans.insertSync("test", valueBucket);
        expect(1).assertEqual(rowId);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsertSync0003 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsertSync0003 failed");
      }

      console.log(TAG + "************* testRdbTransInsertSync0003 end *************");
      done();
    })

    it('testRdbTransInsertSync0011', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsertSync0011 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = rdbTrans.insertSync("test", valueBucket);
        expect(1).assertEqual(rowId);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsertSync0011 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsertSync0011 failed");
      }

      console.log(TAG + "************* testRdbTransInsertSync0011 end *************");
      done();
    })

    it('testRdbTransInsertSync0012', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsertSync0012 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = rdbTrans.insertSync("test", valueBucket);
        expect(1).assertEqual(rowId);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsertSync0012 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsertSync0012 failed");
      }

      console.log(TAG + "************* testRdbTransInsertSync0012 end *************");
      done();
    })

    it('testRdbTransInsertSync0013', 0, async (done) => {
      console.log(TAG + "************* testRdbTransInsertSync0013 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = rdbTrans.insertSync("test", valueBucket);
        expect(1).assertEqual(rowId);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransInsertSync0013 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransInsertSync0013 failed");
      }

      console.log(TAG + "************* testRdbTransInsertSync0013 end *************");
      done();
    })

    it('testRdbTransBatchInsert0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsert0001 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = await rdbTrans.batchInsert("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsert0001 result count " + resultSet.rowCount);
        expect(100).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsert0001 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsert0001 end *************");
      done();
    })

    it('testRdbTransBatchInsert0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsert0002 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = await rdbTrans.batchInsert("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsert0002 result count " + resultSet.rowCount);
        expect(100).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsert0002 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsert0002 end *************");
      done();
    })

    it('testRdbTransBatchInsert0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsert0003 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = await rdbTrans.batchInsert("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsert0003 result count " + resultSet.rowCount);
        expect(100).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsert0003 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsert0003 end *************");
      done();
    })

    it('testRdbTransBatchInsert0011', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsert0011 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = await rdbTrans.batchInsert("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsert0011 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsert0011 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsert0011 end *************");
      done();
    })

    it('testRdbTransBatchInsert0012', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsert0012 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = await rdbTrans.batchInsert("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsert0012 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsert0012 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsert0012 end *************");
      done();
    })

    it('testRdbTransBatchInsert0013', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsert0013 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = await rdbTrans.batchInsert("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsert0013 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsert0013 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsert0013 end *************");
      done();
    })

    it('testRdbTransBatchInsertSync0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsertSync0001 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = rdbTrans.batchInsertSync("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsertSync0001 result count " + resultSet.rowCount);
        expect(100).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsertSync0001 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsertSync0001 end *************");
      done();
    })

    it('testRdbTransBatchInsertSync0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsertSync0002 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = rdbTrans.batchInsertSync("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsertSync0002 result count " + resultSet.rowCount);
        expect(100).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsertSync0002 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsertSync0002 end *************");
      done();
    })

    it('testRdbTransBatchInsertSync0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsertSync0003 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = rdbTrans.batchInsertSync("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsertSync0003 result count " + resultSet.rowCount);
        expect(100).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsertSync0003 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsertSync0003 end *************");
      done();
    })

    it('testRdbTransBatchInsertSync0011', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsertSync0011 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = rdbTrans.batchInsertSync("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsertSync0011 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsertSync0011 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsertSync0011 end *************");
      done();
    })

    it('testRdbTransBatchInsertSync0012', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsertSync0012 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = rdbTrans.batchInsertSync("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsertSync0012 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsertSync0012 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsertSync0012 end *************");
      done();
    })

    it('testRdbTransBatchInsertSync0013', 0, async (done) => {
      console.log(TAG + "************* testRdbTransBatchInsertSync0013 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const valueBuckets = new Array(100).fill(0).map(() => {
          const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
          return valueBucket;
        })
        const rowCount = rdbTrans.batchInsertSync("test", valueBuckets);
        expect(rowCount).assertEqual(100);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransBatchInsertSync0013 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransBatchInsertSync0013 failed");
      }

      console.log(TAG + "************* testRdbTransBatchInsertSync0013 end *************");
      done();
    })

    it('testRdbTransUpdate0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdate0001 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = await rdbTrans.insert("test", valueBucket);
        expect(rowId).assertEqual(1);
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        await rdbTrans.update({ age: 20 }, updatePredicates);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdate0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(20);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdate0001 failed");
      }

      console.log(TAG + "************* testRdbTransUpdate0001 end *************");
      done();
    })

    it('testRdbTransUpdate0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdate0002 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = await rdbTrans.insert("test", valueBucket);
        expect(rowId).assertEqual(1);
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        await rdbTrans.update({ age: 20 }, updatePredicates);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdate0002 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(20);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdate0002 failed");
      }

      console.log(TAG + "************* testRdbTransUpdate0002 end *************");
      done();
    })

    it('testRdbTransUpdate0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdate0003 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = await rdbTrans.insert("test", valueBucket);
        expect(rowId).assertEqual(1);
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        await rdbTrans.update({ age: 20 }, updatePredicates);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdate0003 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(20);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdate0003 failed");
      }

      console.log(TAG + "************* testRdbTransUpdate0003 end *************");
      done();
    })

    console.log(TAG + "*************Unit Test End*************");
  })
}