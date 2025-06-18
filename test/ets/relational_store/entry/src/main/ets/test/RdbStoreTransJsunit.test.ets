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

// @ts-nocheck
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import data_relationalStore from '@ohos.data.relationalStore'

var context = globalThis.abilityContext;

const TAG = "[RELATIONAL_STORE_TRANSACTION_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
  name: "TransactionTest.db",
  securityLevel: data_relationalStore.SecurityLevel.S3,
}

var rdbStore = undefined;

async function insertInThread(context, transType, insertCount = 1) {
  const TAG = "[RELATIONAL_STORE_JS_KITS_TEST]"
  let rdbTrans;
  try {
    rdbTrans = await rdbStore.createTransaction({
      transactionType: transType
    });
    console.log(TAG + 'insertInThread after createTrans');

    const u8 = new Uint8Array([1, 2, 3]);
    const valueBuckets = new Array(insertCount).fill(0).map(() => {
      return {
        "name": "lisi",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      };
    });
    const resultCount = await rdbTrans.batchInsert("test", valueBuckets);
    await rdbTrans.commit();
    console.log(TAG + 'insertInThread after commit');
    return resultCount;
  } catch (err) {
    if (rdbTrans) {
      rdbTrans.rollback();
    }
    console.error(TAG + "************* testRdbTransInsert error thread insert *************");
    console.error(TAG + JSON.stringify(err));
    return err.code;
  }
}

async function queryInThread(context, transType, querySql) {
  const TAG = "[RELATIONAL_STORE_JS_KITS_TEST]"
  let rdbTrans;
  try {
    rdbTrans = await rdbStore.createTransaction({
      transactionType: transType
    });

    const resultSet = await rdbTrans.querySql(querySql);
    const rowCount = resultSet.rowCount;

    await rdbTrans.commit();
    return rowCount;
  } catch (err) {
    if (rdbTrans) {
      rdbTrans.rollback();
    }
    console.error(TAG + "************* testRdbTransInsert error thread insert *************");
    console.error(TAG + JSON.stringify(err));
    return err.code;
  }
}

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

    it('testRdbTransUpdate0011', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdate0011 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = await rdbStore.insert("test", valueBucket);
        expect(rowId).assertEqual(1);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        await rdbTrans.update({ age: 20 }, updatePredicates);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdate0011 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(18);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdate0011 failed");
      }

      console.log(TAG + "************* testRdbTransUpdate0011 end *************");
      done();
    })

    it('testRdbTransUpdate0012', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdate0012 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = await rdbStore.insert("test", valueBucket);
        expect(rowId).assertEqual(1);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        await rdbTrans.update({ age: 20 }, updatePredicates);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdate0012 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(18);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdate0012 failed");
      }

      console.log(TAG + "************* testRdbTransUpdate0012 end *************");
      done();
    })

    it('testRdbTransUpdate0013', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdate0013 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = await rdbStore.insert("test", valueBucket);
        expect(rowId).assertEqual(1);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        await rdbTrans.update({ age: 20 }, updatePredicates);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdate0013 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(18);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdate0013 failed");
      }

      console.log(TAG + "************* testRdbTransUpdate0013 end *************");
      done();
    })

    it('testRdbTransUpdateSync0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdateSync0001 start *************");
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
        rdbTrans.updateSync({ age: 20 }, updatePredicates);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdateSync0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(20);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdateSync0001 failed");
      }

      console.log(TAG + "************* testRdbTransUpdateSync0001 end *************");
      done();
    })

    it('testRdbTransUpdateSync0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdateSync0002 start *************");
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
        rdbTrans.updateSync({ age: 20 }, updatePredicates);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdateSync0002 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(20);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdateSync0002 failed");
      }

      console.log(TAG + "************* testRdbTransUpdateSync0002 end *************");
      done();
    })

    it('testRdbTransUpdateSync0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdateSync0003 start *************");
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
        rdbTrans.updateSync({ age: 20 }, updatePredicates);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdateSync0003 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(20);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdateSync0003 failed");
      }

      console.log(TAG + "************* testRdbTransUpdateSync0003 end *************");
      done();
    })

    it('testRdbTransUpdateSync0011', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdateSync0011 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = await rdbStore.insert("test", valueBucket);
        expect(rowId).assertEqual(1);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        rdbTrans.updateSync({ age: 20 }, updatePredicates);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdateSync0011 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(18);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdateSync0011 failed");
      }

      console.log(TAG + "************* testRdbTransUpdateSync0011 end *************");
      done();
    })

    it('testRdbTransUpdateSync0012', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdateSync0012 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = await rdbStore.insert("test", valueBucket);
        expect(rowId).assertEqual(1);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        rdbTrans.updateSync({ age: 20 }, updatePredicates);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdateSync0012 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(18);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdateSync0012 failed");
      }

      console.log(TAG + "************* testRdbTransUpdateSync0012 end *************");
      done();
    })

    it('testRdbTransUpdateSync0013', 0, async (done) => {
      console.log(TAG + "************* testRdbTransUpdateSync0013 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        const rowId = await rdbStore.insert("test", valueBucket);
        expect(rowId).assertEqual(1);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        rdbTrans.updateSync({ age: 20 }, updatePredicates);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransUpdateSync0013 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        const rowData = resultSet.getRow();
        expect(rowData['age']).assertEqual(18);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransUpdateSync0013 failed");
      }

      console.log(TAG + "************* testRdbTransUpdateSync0013 end *************");
      done();
    })

    it('testRdbTransDelete0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDelete0001 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        const deleteRows = await rdbTrans.delete(updatePredicates);
        expect(deleteRows).assertEqual(3);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDelete0001 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDelete0001 failed");
      }

      console.log(TAG + "************* testRdbTransDelete0001 end *************");
      done();
    })

    it('testRdbTransDelete0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDelete0002 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        const deleteRows = await rdbTrans.delete(updatePredicates);
        expect(deleteRows).assertEqual(3);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDelete0002 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDelete0002 failed");
      }

      console.log(TAG + "************* testRdbTransDelete0002 end *************");
      done();
    })

    it('testRdbTransDelete0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDelete0003 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        const deleteRows = await rdbTrans.delete(updatePredicates);
        expect(deleteRows).assertEqual(3);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDelete0003 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDelete0003 failed");
      }

      console.log(TAG + "************* testRdbTransDelete0003 end *************");
      done();
    })

    it('testRdbTransDelete0011', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDelete0011 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        await rdbTrans.delete(updatePredicates);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDelete0011 result count " + resultSet.rowCount);
        expect(3).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDelete0011 failed");
      }

      console.log(TAG + "************* testRdbTransDelete0011 end *************");
      done();
    })

    it('testRdbTransDelete0012', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDelete0012 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        await rdbTrans.delete(updatePredicates);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDelete0012 result count " + resultSet.rowCount);
        expect(3).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDelete0012 failed");
      }

      console.log(TAG + "************* testRdbTransDelete0012 end *************");
      done();
    })

    it('testRdbTransDelete0013', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDelete0013 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        await rdbTrans.delete(updatePredicates);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDelete0013 result count " + resultSet.rowCount);
        expect(3).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDelete0013 failed");
      }

      console.log(TAG + "************* testRdbTransDelete0013 end *************");
      done();
    })

    it('testRdbTransDeleteSync0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDeleteSync0001 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        const deleteRows = rdbTrans.deleteSync(updatePredicates);
        expect(deleteRows).assertEqual(3);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDeleteSync0001 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDeleteSync0001 failed");
      }

      console.log(TAG + "************* testRdbTransDeleteSync0001 end *************");
      done();
    })

    it('testRdbTransDeleteSync0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDeleteSync0002 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        const deleteRows = rdbTrans.deleteSync(updatePredicates);
        expect(deleteRows).assertEqual(3);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDeleteSync0002 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDeleteSync0002 failed");
      }

      console.log(TAG + "************* testRdbTransDeleteSync0002 end *************");
      done();
    })

    it('testRdbTransDeleteSync0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDeleteSync0003 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        const deleteRows = rdbTrans.deleteSync(updatePredicates);
        expect(deleteRows).assertEqual(3);
        await rdbTrans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDeleteSync0003 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.goToFirstRow();
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDeleteSync0003 failed");
      }

      console.log(TAG + "************* testRdbTransDeleteSync0003 end *************");
      done();
    })

    it('testRdbTransDeleteSync0011', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDeleteSync0011 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        const deleteRows = rdbTrans.deleteSync(updatePredicates);
        expect(deleteRows).assertEqual(3);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDeleteSync0011 result count " + resultSet.rowCount);
        expect(3).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDeleteSync0011 failed");
      }

      console.log(TAG + "************* testRdbTransDeleteSync0011 end *************");
      done();
    })

    it('testRdbTransDeleteSync0012', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDeleteSync0012 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        const deleteRows = rdbTrans.deleteSync(updatePredicates);
        expect(deleteRows).assertEqual(3);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDeleteSync0012 result count " + resultSet.rowCount);
        expect(3).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDeleteSync0012 failed");
      }

      console.log(TAG + "************* testRdbTransDeleteSync0012 end *************");
      done();
    })

    it('testRdbTransDeleteSync0013', 0, async (done) => {
      console.log(TAG + "************* testRdbTransDeleteSync0013 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(3).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rowId = await rdbStore.batchInsert("test", valueBuckets);
        expect(rowId).assertEqual(3);
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        const updatePredicates = new data_relationalStore.RdbPredicates("test");
        updatePredicates.equalTo('name', 'lisi');
        const deleteRows = rdbTrans.deleteSync(updatePredicates);
        expect(deleteRows).assertEqual(3);
        await rdbTrans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransDeleteSync0013 result count " + resultSet.rowCount);
        expect(3).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransDeleteSync0013 failed");
      }

      console.log(TAG + "************* testRdbTransDeleteSync0013 end *************");
      done();
    })

    it('testRdbTransQuery0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransQuery0001 start *************");
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
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbTrans.query(predicates);
        console.log(TAG + "testRdbTransQuery0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        await rdbTrans.commit();
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransQuery0001 failed");
      }

      console.log(TAG + "************* testRdbTransQuery0001 end *************");
      done();
    })

    it('testRdbTransQuery0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransQuery0002 start *************");
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
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbTrans.query(predicates);
        console.log(TAG + "testRdbTransQuery0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        await rdbTrans.commit();
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransQuery0002 failed");
      }

      console.log(TAG + "************* testRdbTransQuery0002 end *************");
      done();
    })

    it('testRdbTransQuery0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransQuery0003 start *************");
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
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbTrans.query(predicates);
        console.log(TAG + "testRdbTransQuery0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        await rdbTrans.commit();
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransQuery0003 failed");
      }

      console.log(TAG + "************* testRdbTransQuery0003 end *************");
      done();
    })

    it('testRdbTransQuery0011', 0, async (done) => {
      console.log(TAG + "************* testRdbTransQuery0011 start *************");
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
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbTrans.querySync(predicates);
        console.log(TAG + "testRdbTransQuery0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        await rdbTrans.commit();
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransQuery0011 failed");
      }

      console.log(TAG + "************* testRdbTransQuery0011 end *************");
      done();
    })

    it('testRdbTransQuery0012', 0, async (done) => {
      console.log(TAG + "************* testRdbTransQuery0012 start *************");
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
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbTrans.querySync(predicates);
        console.log(TAG + "testRdbTransQuery0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        await rdbTrans.commit();
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransQuery0012 failed");
      }

      console.log(TAG + "************* testRdbTransQuery0012 end *************");
      done();
    })

    it('testRdbTransQuery0013', 0, async (done) => {
      console.log(TAG + "************* testRdbTransQuery0013 start *************");
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
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbTrans.querySync(predicates);
        console.log(TAG + "testRdbTransQuery0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        await rdbTrans.commit();
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransQuery0013 failed");
      }

      console.log(TAG + "************* testRdbTransQuery0013 end *************");
      done();
    })

    it('testRdbTransSameThreadInsert0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadInsert0001 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await insertInThread(context, data_relationalStore.TransactionType.DEFERRED, 10);
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadInsert0001 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadInsert0001 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadInsert0001 end *************");
      done();
    })

    it('testRdbTransSameThreadInsert0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadInsert0002 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await insertInThread(context, data_relationalStore.TransactionType.DEFERRED, 10);
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadInsert0002 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadInsert0002 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadInsert0002 end *************");
      done();
    })

    it('testRdbTransSameThreadInsert0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadInsert0003 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await insertInThread(context, data_relationalStore.TransactionType.DEFERRED, 10);
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadInsert0003 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadInsert0003 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadInsert0003 end *************");
      done();
    })

    it('testRdbTransSameThreadInsert0004', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadInsert0004 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        console.log(TAG + "before second trans create");
        const errCode = await insertInThread(context, data_relationalStore.TransactionType.DEFERRED, 10);
        console.log(TAG + "after second trans create");
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        console.log(TAG + "before query predicates create");
        let predicates = new data_relationalStore.RdbPredicates("test");
        console.log(TAG + "after query predicates create");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadInsert0004 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadInsert0004 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadInsert0004 end *************");
      done();
    })

    it('testRdbTransSameThreadInsert0005', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadInsert0005 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await insertInThread(context, data_relationalStore.TransactionType.DEFERRED, 10);
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadInsert0005 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadInsert0005 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadInsert0005 end *************");
      done();
    })

    it('testRdbTransSameThreadInsert0006', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadInsert0006 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await insertInThread(context, data_relationalStore.TransactionType.DEFERRED, 10);
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadInsert0006 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadInsert0006 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadInsert0006 end *************");
      done();
    })

    it('testRdbTransSameThreadInsert0007', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadInsert0007 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await insertInThread(context, data_relationalStore.TransactionType.DEFERRED, 10);
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadInsert0007 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadInsert0007 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadInsert0007 end *************");
      done();
    })

    it('testRdbTransSameThreadInsert0008', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadInsert0008 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await insertInThread(context, data_relationalStore.TransactionType.EXCLUSIVE, 10);
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadInsert0008 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadInsert0008 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadInsert0008 end *************");
      done();
    })

    it('testRdbTransSameThreadInsert0009', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadInsert0009 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await insertInThread(context, data_relationalStore.TransactionType.EXCLUSIVE, 10);
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadInsert0009 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadInsert0009 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadInsert0009 end *************");
      done();
    })

    it('testRdbTransSameThreadQuery0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadQuery0001 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const rowCount = await queryInThread(context, data_relationalStore.TransactionType.DEFERRED, 'select * from test');
        expect(rowCount).assertEqual(0);

        await rdbTrans.commit();

        {
          const rowCount = await queryInThread(context, data_relationalStore.TransactionType.DEFERRED, 'select * from test');
          expect(rowCount).assertEqual(10);
        }
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadQuery0001 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadQuery0001 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadQuery0001 end *************");
      done();
    })

    it('testRdbTransSameThreadQuery0002', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadQuery0002 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const rowCount = await queryInThread(context, data_relationalStore.TransactionType.DEFERRED, 'select * from test');
        expect(rowCount).assertEqual(0);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadQuery0002 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadQuery0002 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadQuery0002 end *************");
      done();
    })

    it('testRdbTransSameThreadQuery0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadQuery0003 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })

        await rdbStore.batchInsert('test', valueBuckets);

        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const rowCount = await queryInThread(context, data_relationalStore.TransactionType.DEFERRED, 'select * from test');
        expect(rowCount).assertEqual(10);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadQuery0003 result count " + resultSet.rowCount);
        expect(20).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadQuery0003 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadQuery0003 end *************");
      done();
    })

    it('testRdbTransSameThreadQuery0004', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadQuery0004 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await queryInThread(context, data_relationalStore.TransactionType.IMMEDIATE, 'select * from test');
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadQuery0004 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadQuery0004 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadQuery0004 end *************");
      done();
    })

    it('testRdbTransSameThreadQuery0005', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadQuery0005 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await queryInThread(context, data_relationalStore.TransactionType.IMMEDIATE, 'select * from test');
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadQuery0005 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadQuery0005 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadQuery0005 end *************");
      done();
    })

    it('testRdbTransSameThreadQuery0006', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadQuery0006 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await queryInThread(context, data_relationalStore.TransactionType.IMMEDIATE, 'select * from test');
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadQuery0006 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadQuery0006 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadQuery0006 end *************");
      done();
    })

    it('testRdbTransSameThreadQuery0007', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadQuery0007 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.DEFERRED
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await queryInThread(context, data_relationalStore.TransactionType.EXCLUSIVE, 'select * from test');
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadQuery0007 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadQuery0007 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadQuery0007 end *************");
      done();
    })

    it('testRdbTransSameThreadQuery0008', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadQuery0008 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await queryInThread(context, data_relationalStore.TransactionType.EXCLUSIVE, 'select * from test');
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadQuery0008 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadQuery0008 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadQuery0008 end *************");
      done();
    })

    it('testRdbTransSameThreadQuery0009', 0, async (done) => {
      console.log(TAG + "************* testRdbTransSameThreadQuery0009 start *************");
      try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(10).fill(0).map(() => {
          return {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
          };
        })
        const rdbTrans = await rdbStore.createTransaction({
          transactionType: data_relationalStore.TransactionType.EXCLUSIVE
        });

        const insertCount = await rdbTrans.batchInsert('test', valueBuckets);
        expect(insertCount).assertEqual(10);

        const errCode = await queryInThread(context, data_relationalStore.TransactionType.EXCLUSIVE, 'select * from test');
        expect(errCode).assertEqual(14800024);

        await rdbTrans.commit();

        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = rdbStore.querySync(predicates);
        console.log(TAG + "testRdbTransSameThreadQuery0009 result count " + resultSet.rowCount);
        expect(10).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransSameThreadQuery0009 failed");
      }

      console.log(TAG + "************* testRdbTransSameThreadQuery0009 end *************");
      done();
    })

    /**
     * @tc.name rdb transaction insert test
     * @tc.number testRdbTransactionInsert0001
     * @tc.desc rdb transaction insert & commit, the result comes out is 3 items;
     */
    it('testRdbTransactionInsert0001', 0, async (done) => {
      console.log(TAG + "************* testRdbStoreInsert0001 start *************");
      const u8 = new Uint8Array([1, 2, 3]);
      try {
        const rdbTrans = await rdbStore.createTransaction();
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
        console.log(TAG + "testRdbTransactionInsert0001 result count " + resultSet.rowCount);
        expect(1).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        console.log(TAG + e);
        expect(null).assertFail();
        console.log(TAG + "testRdbTransactionInsert0001 failed");
      }
      done();
      console.log(TAG + "************* testRdbTransactionInsert0001 end *************");
    })

    /**
     * @tc.name rdb transaction insert test
     * @tc.number testRdbTransactionInsert0001
     * @tc.desc rdb transaction insert & commit, the result comes out is 3 items;
     */
    it('testRdbTransactionInsert0002', 0, async (done) => {
      console.log(TAG + "************* testRdbStoreInsert0002 start *************");
      const u8 = new Uint8Array([1, 2, 3]);
      try {
        const trans = await rdbStore.createTransaction();
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await trans.insert("test", valueBucket);
        const valueBucket1 = {
          "name": "zhangsan",
          "age": 20,
          "salary": 9.5,
          "blobType": u8,
        };
        await trans.insert("test", valueBucket1);
        const valueBucket2 = {
          "name": "wangwu",
          "age": 16,
          "salary": 99,
          "blobType": u8,
        };
        await trans.insert("test", valueBucket2);
        await trans.commit();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(3).assertEqual(resultSet.rowCount);
        resultSet.close();
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "testRdbTransactionInsert0002 failed");
      }
      done();
      console.log(TAG + "************* testRdbTransactionInsert0002 end *************");
    })

    /**
     * @tc.name rdb transaction insert test
     * @tc.number testRdbTransactionInsert0002
     * @tc.desc while using transaction to insert values, querying the db,
     *     the result comes out is 0;
     */
    it('testRdbTransactionInsert0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransactionInsert0003 start *************");
      const u8 = new Uint8Array([1, 2, 3]);
      try {
        const trans = await rdbStore.createTransaction();
        const valueBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await trans.insert("test", valueBucket);
        const valueBucket1 = {
          "name": "zhangsan",
          "age": 20,
          "salary": 9.5,
          "blobType": u8,
        };
        await trans.insert("test", valueBucket1);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await trans.query(predicates);
        expect(2).assertEqual(resultSet.rowCount);
        resultSet.close();
        const valueBucket2 = {
          "name": "wangwu",
          "age": 16,
          "salary": 99,
          "blobType": u8,
        };
        await trans.insert("test", valueBucket2);
        await trans.commit();
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "testRdbTransactionInsert0003 failed");
      }
      done();
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
    it('testRdbTransactionRollBack0001', 0, async (done) => {
      console.log(TAG + "************* testRdbTransactionRollBack0001 start *************");
      const u8 = new Uint8Array([1, 2, 3]);
      const trans = await rdbStore.createTransaction({
        transactionType: data_relationalStore.TransactionType.EXCLUSIVE
      });
      try {
        const valueBucket = {
          "id": 1,
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await trans.insert("test", valueBucket);
        await trans.insert("test", valueBucket);
        trans.commit();
      } catch (e) {
        trans.rollback();
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        console.log(TAG + "testRdbTransactionRollBack0001 result count " + resultSet.rowCount);
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
      }
      done();
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
    it('testRdbTransactionMulti0003', 0, async (done) => {
      console.log(TAG + "************* testRdbTransactionMulti0003 start *************");
      const u8 = new Uint8Array([1, 2, 3]);
      let trans = await rdbStore.createTransaction();
      const trans2 = await rdbStore.createTransaction();
      try {
        const valueBucket = {
          "id": 1,
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        await trans.insert("test", valueBucket);
        console.log(TAG + "before second create trans");
        console.log(TAG + "after second create trans");
        const valueBucket1 = {
          "name": "zhangsan",
          "age": 20,
          "salary": 220.5,
          "blobType": u8,
        };
        await trans2.insert("test", valueBucket1);
      } catch (e) {
        expect(e.code).assertEqual(14800024)
        await trans.rollback();
        await trans2.rollback();
        console.log(TAG + "testRdbTransactionMulti0003 rollback ***** ");
      }
      done();
      console.log(TAG + "************* testRdbTransactionMulti0003 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
  })
}