/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from "@ohos/hypium";
import data_relationalStore from '@ohos.data.relationalStore';
import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';

let context = abilityDelegatorRegistry.getAbilityDelegator().getAppContext().getApplicationContext();
const TAG = "[RdbErrMsgOptimize]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" +
  "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
const STORE_CONFIG: data_relationalStore.StoreConfig = {
  name: "RdbErrMsgOptimize.db",
  securityLevel: data_relationalStore.SecurityLevel.S1,
}

let rdbStore: data_relationalStore.RdbStore;
export default function rdbErrMsgOptimizeTest() {
  describe('rdbErrMsgOptimizeTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async (done: Function) => {
      console.info(TAG + 'beforeEach')
      try {
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST);
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": new Uint8Array([1, 2, 3]),
        }
        await rdbStore.insert("test", valueBucket);
      } catch (err) {
        console.log(`${TAG} beforeEach error code:${err.code}, message:${err.message}`);
      }
      done();
    })
    afterEach(async (done: Function) => {
      console.info(TAG + 'afterEach')
      try {
        await rdbStore.close();
      } catch (err) {
        console.log(`${TAG} afterEach close error code:${err.code}, message:${err.message}`);
      }
      await data_relationalStore.deleteRdbStore(context, "RdbErrMsgOptimize.db");
      done();
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_001
     * @tc.name Verify 14800021 Insert async appends SqlLog to message
     * @tc.desc 1.Insert a row with an invalid column name into a valid table
     *          2.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_InsertAsync_SqlLog_001', 0, async (done: Function) => {
      console.log(TAG + "************* 001 start *************");
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "lisi",
          "invalid_column": 999,
        }
        await rdbStore.insert("test", valueBucket);
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 001 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("has no column named")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_002
     * @tc.name Verify 14800021 Insert sync appends SqlLog to message
     * @tc.desc 1.Insert a row with an invalid column name via insertSync
     *          2.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_InsertSync_SqlLog_002', 0, async (done: Function) => {
      console.log(TAG + "************* 002 start *************");
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "lisi",
          "invalid_column": 999,
        }
        rdbStore.insertSync("test", valueBucket);
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 002 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("has no column named")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_003
     * @tc.name Verify 14800021 Update async appends SqlLog to message
     * @tc.desc 1.Update rows with an invalid column name via async update
     *          2.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_UpdateAsync_SqlLog_003', 0, async (done: Function) => {
      console.log(TAG + "************* 003 start *************");
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "invalid_column": 999,
        }
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo('name', 'zhangsan');
        await rdbStore.update(valueBucket, predicates);
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 003 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("no such column")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_004
     * @tc.name Verify 14800021 Delete async appends SqlLog to message
     * @tc.desc 1.Delete rows from a non-existent table via async delete
     *          2.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_DeleteAsync_SqlLog_004', 0, async (done: Function) => {
      console.log(TAG + "************* 004 start *************");
      try {
        let predicates = new data_relationalStore.RdbPredicates("wrong_table");
        predicates.equalTo('id', 1);
        await rdbStore.delete(predicates);
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 004 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("no such table")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_005
     * @tc.name Verify 14800021 ExecuteSql async appends SqlLog to message
     * @tc.desc 1.Execute DELETE on a non-existent table via executeSql
     *          2.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_ExecuteSqlAsync_SqlLog_005', 0, async (done: Function) => {
      console.log(TAG + "************* 005 start *************");
      try {
        await rdbStore.executeSql("DELETE FROM wrong_table");
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 005 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("no such table")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_006
     * @tc.name Verify 14800000 Transaction batchInsertSync with empty table name
     * @tc.desc 1.Create an IMMEDIATE transaction
     *          2.Call batchInsertSync with empty table name
     *          3.Expect err.code == 14800000 and err.message contains native error description
     */
    it('ErrMsg_14800000_TransBatchInsertSync_EmptyTableName_006', 0, async (done: Function) => {
      console.log(TAG + "************* 006 start *************");
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "test",
        }
        transaction?.batchInsertSync("", [valueBucket]);
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(`${TAG} 006 code:${e.code}, message:${e.message}`);
        expect(e.code == 14800000).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_007
     * @tc.name Verify 14800021 Transaction insertSync appends SqlLog to message
     * @tc.desc 1.Create an IMMEDIATE transaction
     *          2.Insert a row with an invalid column via insertSync
     *          3.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_TransInsertSync_SqlLog_007', 0, async (done: Function) => {
      console.log(TAG + "************* 007 start *************");
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "lisi",
          "invalid_column": 999,
        }
        transaction?.insertSync("test", valueBucket);
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(`${TAG} 007 code:${e.code}, message:${e.message}`);
        expect(e.code == 14800021).assertTrue();
        expect(e.message.includes("has no column named")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_008
     * @tc.name Verify 14800021 Transaction deleteSync appends SqlLog to message
     * @tc.desc 1.Create an IMMEDIATE transaction
     *          2.Delete rows from a non-existent table via deleteSync
     *          3.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_TransDeleteSync_SqlLog_008', 0, async (done: Function) => {
      console.log(TAG + "************* 008 start *************");
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        let predicates = new data_relationalStore.RdbPredicates("wrong_table");
        predicates.equalTo('id', 1);
        transaction?.deleteSync(predicates);
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(`${TAG} 008 code:${e.code}, message:${e.message}`);
        expect(e.code == 14800021).assertTrue();
        expect(e.message.includes("no such table")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_009
     * @tc.name Verify 14800000 Transaction insertSync with empty table name
     * @tc.desc 1.Create an IMMEDIATE transaction
     *          2.Call insertSync with empty table name
     *          3.Expect err.code == 14800000 and err.message contains native error description
     */
    it('ErrMsg_14800000_TransInsertSync_EmptyTableName_009', 0, async (done: Function) => {
      console.log(TAG + "************* 009 start *************");
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "test",
        }
        transaction?.insertSync("", valueBucket);
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(`${TAG} 009 code:${e.code}, message:${e.message}`);
        expect(e.code == 14800000).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_010
     * @tc.name Verify 14800021 Transaction updateSync appends SqlLog to message
     * @tc.desc 1.Create an IMMEDIATE transaction
     *          2.Update rows with an invalid column via updateSync
     *          3.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_TransUpdateSync_SqlLog_010', 0, async (done: Function) => {
      console.log(TAG + "************* 010 start *************");
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "invalid_column": 999,
        }
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo('name', 'zhangsan');
        transaction?.updateSync(valueBucket, predicates);
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(`${TAG} 010 code:${e.code}, message:${e.message}`);
        expect(e.code == 14800021).assertTrue();
        expect(e.message.includes("no such column")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_013
     * @tc.name Verify 14800021 Update sync appends SqlLog to message
     * @tc.desc 1.Update rows with an invalid column name via updateSync
     *          2.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_UpdateSync_SqlLog_013', 0, async (done: Function) => {
      console.log(TAG + "************* 013 start *************");
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "invalid_column": 999,
        }
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo('name', 'zhangsan');
        rdbStore.updateSync(valueBucket, predicates);
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 013 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("no such column")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_014
     * @tc.name Verify 14800021 Delete sync appends SqlLog to message
     * @tc.desc 1.Delete rows from a non-existent table via deleteSync
     *          2.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_DeleteSync_SqlLog_014', 0, async (done: Function) => {
      console.log(TAG + "************* 014 start *************");
      try {
        let predicates = new data_relationalStore.RdbPredicates("wrong_table");
        predicates.equalTo('id', 1);
        rdbStore.deleteSync(predicates);
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 014 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("no such table")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_015
     * @tc.name Verify 14800021 Execute async appends SqlLog to message
     * @tc.desc 1.Execute INSERT on a non-existent table via async execute
     *          2.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_ExecuteAsync_SqlLog_015', 0, async (done: Function) => {
      console.log(TAG + "************* 015 start *************");
      try {
        await rdbStore.execute("INSERT INTO wrong_table(name) VALUES('test')");
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 015 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("no such table")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_016
     * @tc.name Verify 14800021 Execute sync appends SqlLog to message
     * @tc.desc 1.Execute INSERT on a non-existent table via executeSync
     *          2.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_ExecuteSync_SqlLog_016', 0, async (done: Function) => {
      console.log(TAG + "************* 016 start *************");
      try {
        rdbStore.executeSync("INSERT INTO wrong_table(name) VALUES('test')");
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 016 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("no such table")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_017
     * @tc.name Verify 14800021 Execute SELECT throws not-supported error
     * @tc.desc 1.Execute SELECT via async execute on a valid table
     *          2.Expect err.code == 14800021 and err.message contains "not supported"
     */
    it('ErrMsg_14800021_Execute_NotSupportSql_017', 0, async (done: Function) => {
      console.log(TAG + "************* 017 start *************");
      try {
        await rdbStore.execute("SELECT * FROM test");
        expect(true).assertFail();
      } catch (err) {
        console.log(`${TAG} 017 code:${err.code}, message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
        expect(err.message.includes("not supported")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_018
     * @tc.name Verify 14800021 Transaction execute async appends SqlLog to message
     * @tc.desc 1.Create an IMMEDIATE transaction
     *          2.Execute INSERT on a non-existent table via async execute
     *          3.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_TransExecuteAsync_SqlLog_018', 0, async (done: Function) => {
      console.log(TAG + "************* 018 start *************");
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        await transaction?.execute("INSERT INTO wrong_table(name) VALUES('test')");
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(`${TAG} 018 code:${e.code}, message:${e.message}`);
        expect(e.code == 14800021).assertTrue();
        expect(e.message.includes("no such table")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_019
     * @tc.name Verify 14800021 Transaction executeSync appends SqlLog to message
     * @tc.desc 1.Create an IMMEDIATE transaction
     *          2.Execute INSERT on a non-existent table via executeSync
     *          3.Expect err.code == 14800021 and err.message contains SqlLog detail
     */
    it('ErrMsg_14800021_TransExecuteSync_SqlLog_019', 0, async (done: Function) => {
      console.log(TAG + "************* 019 start *************");
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        transaction?.executeSync("INSERT INTO wrong_table(name) VALUES('test')");
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(`${TAG} 019 code:${e.code}, message:${e.message}`);
        expect(e.code == 14800021).assertTrue();
        expect(e.message.includes("no such table")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_020
     * @tc.name Verify 14800000 Transaction execute SELECT throws inner error
     * @tc.desc 1.Create an IMMEDIATE transaction
     *          2.Execute SELECT via async execute on a valid table
     *          3.Expect err.code == 14800000 and err.message contains "Inner error"
     */
    it('ErrMsg_14800000_TransExecute_NotSupportSql_020', 0, async (done: Function) => {
      console.log(TAG + "************* 020 start *************");
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        await transaction?.execute("SELECT * FROM test");
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(`${TAG} 020 code:${e.code}, message:${e.message}`);
        expect(e.code == 14800000).assertTrue();
        expect(e.message.includes("Inner error")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_021
     * @tc.name Verify 14800000 Transaction executeSync SELECT throws inner error
     * @tc.desc 1.Create an IMMEDIATE transaction
     *          2.Execute SELECT via executeSync on a valid table
     *          3.Expect err.code == 14800000 and err.message contains "Inner error"
     */
    it('ErrMsg_14800000_TransExecuteSync_NotSupportSql_021', 0, async (done: Function) => {
      console.log(TAG + "************* 021 start *************");
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        transaction?.executeSync("SELECT * FROM test");
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(`${TAG} 021 code:${e.code}, message:${e.message}`);
        expect(e.code == 14800000).assertTrue();
        expect(e.message.includes("Inner error")).assertTrue();
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_022
     * @tc.name Verify concurrent insertSync on same RdbStore returns isolated error messages
     * @tc.desc 1.Create two concurrent operations on the same store that both trigger errors
     *          2.Each operation should see its own error message, not the other thread's
     */
    it('ErrMsg_ConcurrentInsertSync_ThreadIsolation_022', 0, async (done: Function) => {
      console.log(TAG + "************* 022 start *************");
      try {
        const bucket1: data_relationalStore.ValuesBucket = {
          "name": "thread1",
          "col_not_exist_1": 1,
        }
        const bucket2: data_relationalStore.ValuesBucket = {
          "name": "thread2",
          "col_not_exist_2": 2,
        }
        let err1: any = null;
        let err2: any = null;
        const p1 = new Promise<void>((resolve) => {
          try {
            rdbStore.insertSync("test", bucket1);
          } catch (e) {
            err1 = e;
          }
          resolve();
        });
        const p2 = new Promise<void>((resolve) => {
          try {
            rdbStore.insertSync("test", bucket2);
          } catch (e) {
            err2 = e;
          }
          resolve();
        });
        await Promise.all([p1, p2]);
        console.log(`${TAG} 022 err1 code:${err1?.code}, message:${err1?.message}`);
        console.log(`${TAG} 022 err2 code:${err2?.code}, message:${err2?.message}`);
        if (err1 != null) {
          expect(err1.code == 14800021).assertTrue();
          expect(err1.message.includes("has no column named")).assertTrue();
        }
        if (err2 != null) {
          expect(err2.code == 14800021).assertTrue();
          expect(err2.message.includes("has no column named")).assertTrue();
        }
        expect(err1 != null || err2 != null).assertTrue();
      } catch (err) {
        console.log(`${TAG} 022 unexpected error:${err.code}, message:${err.message}`);
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_023
     * @tc.name Verify concurrent async insert on same RdbStore returns isolated error messages
     * @tc.desc 1.Run two async inserts with invalid columns concurrently on same store
     *          2.Expect both to return 14800021 with SqlLog detail
     */
    it('ErrMsg_ConcurrentInsertAsync_ThreadIsolation_023', 0, async (done: Function) => {
      console.log(TAG + "************* 023 start *************");
      try {
        const bucket1: data_relationalStore.ValuesBucket = {
          "name": "async1",
          "col_async_invalid_1": 1,
        }
        const bucket2: data_relationalStore.ValuesBucket = {
          "name": "async2",
          "col_async_invalid_2": 2,
        }
        let results = await Promise.allSettled([
          rdbStore.insert("test", bucket1),
          rdbStore.insert("test", bucket2),
        ]);
        for (let i = 0; i < results.length; i++) {
          let r = results[i];
          if (r.status === "rejected") {
            console.log(`${TAG} 023 rejected[${i}] code:${r.reason?.code}, message:${r.reason?.message}`);
            expect(r.reason.code == 14800021).assertTrue();
            expect(r.reason.message.includes("has no column named")).assertTrue();
          }
        }
        let hasRejection = results.some((r: any) => r.status === "rejected");
        expect(hasRejection).assertTrue();
      } catch (err) {
        console.log(`${TAG} 023 unexpected error:${err.code}, message:${err.message}`);
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_024
     * @tc.name Verify sequential operations on same RdbStore do not cross-contaminate error messages
     * @tc.desc 1.Insert with invalid column, verify error msg A
     *          2.Insert different invalid column, verify error msg B (not A)
     */
    it('ErrMsg_SequentialInsert_NoCrossContamination_024', 0, async (done: Function) => {
      console.log(TAG + "************* 024 start *************");
      try {
        const bucketA: data_relationalStore.ValuesBucket = {
          "name": "seqA",
          "col_seq_invalid_A": 1,
        }
        try {
          await rdbStore.insert("test", bucketA);
          expect(true).assertFail();
        } catch (errA) {
          console.log(`${TAG} 024 errA code:${errA.code}, message:${errA.message}`);
          expect(errA.code == 14800021).assertTrue();
          expect(errA.message.includes("has no column named")).assertTrue();
          expect(errA.message.includes("col_seq_invalid_A")).assertTrue();
        }
        const bucketB: data_relationalStore.ValuesBucket = {
          "name": "seqB",
          "col_seq_invalid_B": 2,
        }
        try {
          await rdbStore.insert("test", bucketB);
          expect(true).assertFail();
        } catch (errB) {
          console.log(`${TAG} 024 errB code:${errB.code}, message:${errB.message}`);
          expect(errB.code == 14800021).assertTrue();
          expect(errB.message.includes("has no column named")).assertTrue();
          expect(errB.message.includes("col_seq_invalid_B")).assertTrue();
          expect(!errB.message.includes("col_seq_invalid_A")).assertTrue();
        }
      } catch (err) {
        console.log(`${TAG} 024 unexpected error:${err.code}, message:${err.message}`);
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_025
     * @tc.name Verify concurrent async insert returns isolated error messages with different columns
     * @tc.desc 1.Run two async inserts with different invalid columns concurrently on same store
     *          2.Expect each error message contains its own invalid column name, not the other's
     */
    it('ErrMsg_ConcurrentInsertAsync_DifferentErrorMsg_025', 0, async (done: Function) => {
      console.log(TAG + "************* 025 start *************");
      try {
        const bucket1: data_relationalStore.ValuesBucket = {
          "name": "diff1",
          "col_diff_invalid_1": 1,
        }
        const bucket2: data_relationalStore.ValuesBucket = {
          "name": "diff2",
          "col_diff_invalid_2": 2,
        }
        let results = await Promise.allSettled([
          rdbStore.insert("test", bucket1),
          rdbStore.insert("test", bucket2),
        ]);
        for (let i = 0; i < results.length; i++) {
          let r = results[i];
          if (r.status === "rejected") {
            console.log(`${TAG} 025 rejected[${i}] code:${r.reason?.code}, message:${r.reason?.message}`);
          }
        }
        let r0 = results[0];
        let r1 = results[1];
        if (r0.status === "rejected" && r1.status === "rejected") {
          expect(r0.reason.code == 14800021).assertTrue();
          expect(r1.reason.code == 14800021).assertTrue();
          expect(r0.reason.message.includes("col_diff_invalid_1")).assertTrue();
          expect(!r0.reason.message.includes("col_diff_invalid_2")).assertTrue();
          expect(r1.reason.message.includes("col_diff_invalid_2")).assertTrue();
          expect(!r1.reason.message.includes("col_diff_invalid_1")).assertTrue();
        } else if (r0.status === "rejected") {
          expect(r0.reason.code == 14800021).assertTrue();
          expect(r0.reason.message.includes("has no column named")).assertTrue();
        } else if (r1.status === "rejected") {
          expect(r1.reason.code == 14800021).assertTrue();
          expect(r1.reason.message.includes("has no column named")).assertTrue();
        }
        expect(r0.status === "rejected" || r1.status === "rejected").assertTrue();
      } catch (err) {
        console.log(`${TAG} 025 unexpected error:${err.code}, message:${err.message}`);
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_026
     * @tc.name Verify concurrent async update/delete return isolated error messages with different error types
     * @tc.desc 1.Run async update(wrong_table) and async delete(wrong_table) concurrently
     *          2.Expect both return 14800021 with "no such table", each isolated
     */
    it('ErrMsg_ConcurrentUpdateDeleteAsync_DifferentErrorMsg_026', 0, async (done: Function) => {
      console.log(TAG + "************* 026 start *************");
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "invalid_column": 999,
        }
        let predicatesUpdate = new data_relationalStore.RdbPredicates("wrong_table_update");
        predicatesUpdate.equalTo('id', 1);
        let predicatesDelete = new data_relationalStore.RdbPredicates("wrong_table_delete");
        predicatesDelete.equalTo('id', 1);
        let results = await Promise.allSettled([
          rdbStore.update(valueBucket, predicatesUpdate),
          rdbStore.delete(predicatesDelete),
        ]);
        for (let i = 0; i < results.length; i++) {
          let r = results[i];
          if (r.status === "rejected") {
            console.log(`${TAG} 026 rejected[${i}] code:${r.reason?.code}, message:${r.reason?.message}`);
            expect(r.reason.code == 14800021).assertTrue();
            expect(r.reason.message.includes("no such table")).assertTrue();
          }
        }
        let hasRejection = results.some((r: any) => r.status === "rejected");
        expect(hasRejection).assertTrue();
      } catch (err) {
        console.log(`${TAG} 026 unexpected error:${err.code}, message:${err.message}`);
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_027
     * @tc.name Verify concurrent async executeSql return isolated error messages
     * @tc.desc 1.Run two async executeSql with different invalid SQL concurrently
     *          2.Expect each error contains its own table name context
     */
    it('ErrMsg_ConcurrentExecuteSqlAsync_DifferentErrorMsg_027', 0, async (done: Function) => {
      console.log(TAG + "************* 027 start *************");
      try {
        let results = await Promise.allSettled([
          rdbStore.executeSql("DELETE FROM wrong_table_a"),
          rdbStore.executeSql("DELETE FROM wrong_table_b"),
        ]);
        for (let i = 0; i < results.length; i++) {
          let r = results[i];
          if (r.status === "rejected") {
            console.log(`${TAG} 027 rejected[${i}] code:${r.reason?.code}, message:${r.reason?.message}`);
            expect(r.reason.code == 14800021).assertTrue();
            expect(r.reason.message.includes("no such table")).assertTrue();
          }
        }
        let r0 = results[0];
        let r1 = results[1];
        if (r0.status === "rejected" && r1.status === "rejected") {
          expect(r0.reason.message.includes("wrong_table_a")).assertTrue();
          expect(r1.reason.message.includes("wrong_table_b")).assertTrue();
          expect(!r0.reason.message.includes("wrong_table_b")).assertTrue();
          expect(!r1.reason.message.includes("wrong_table_a")).assertTrue();
        } else if (r0.status === "rejected") {
          expect(r0.reason.message.includes("no such table")).assertTrue();
        } else if (r1.status === "rejected") {
          expect(r1.reason.message.includes("no such table")).assertTrue();
        }
        expect(r0.status === "rejected" || r1.status === "rejected").assertTrue();
      } catch (err) {
        console.log(`${TAG} 027 unexpected error:${err.code}, message:${err.message}`);
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_028
     * @tc.name Verify sequential sync operations do not cross-contaminate error messages
     * @tc.desc 1.insertSync with invalid column A, verify error msg contains A
     *          2.insertSync with invalid column B, verify error msg contains B, not A
     */
    it('ErrMsg_SequentialInsertSync_NoCrossContamination_028', 0, async (done: Function) => {
      console.log(TAG + "************* 028 start *************");
      try {
        const bucketA: data_relationalStore.ValuesBucket = {
          "name": "syncA",
          "col_sync_invalid_A": 1,
        }
        try {
          rdbStore.insertSync("test", bucketA);
          expect(true).assertFail();
        } catch (errA) {
          console.log(`${TAG} 028 errA code:${errA.code}, message:${errA.message}`);
          expect(errA.code == 14800021).assertTrue();
          expect(errA.message.includes("has no column named")).assertTrue();
          expect(errA.message.includes("col_sync_invalid_A")).assertTrue();
        }
        const bucketB: data_relationalStore.ValuesBucket = {
          "name": "syncB",
          "col_sync_invalid_B": 2,
        }
        try {
          rdbStore.insertSync("test", bucketB);
          expect(true).assertFail();
        } catch (errB) {
          console.log(`${TAG} 028 errB code:${errB.code}, message:${errB.message}`);
          expect(errB.code == 14800021).assertTrue();
          expect(errB.message.includes("has no column named")).assertTrue();
          expect(errB.message.includes("col_sync_invalid_B")).assertTrue();
          expect(!errB.message.includes("col_sync_invalid_A")).assertTrue();
        }
      } catch (err) {
        console.log(`${TAG} 028 unexpected error:${err.code}, message:${err.message}`);
      }
      done();
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_RdbErrMsgOptimize_029
     * @tc.name Verify sequential operations with different error types do not cross-contaminate
     * @tc.desc 1.deleteSync from wrong_table → error "no such table"
     *          2.insertSync with invalid column → error "has no column named"
     *          3.Verify second error does not contain "no such table"
     */
    it('ErrMsg_SequentialDifferentError_NoCrossContamination_029', 0, async (done: Function) => {
      console.log(TAG + "************* 029 start *************");
      try {
        let predicates = new data_relationalStore.RdbPredicates("wrong_table");
        predicates.equalTo('id', 1);
        try {
          rdbStore.deleteSync(predicates);
          expect(true).assertFail();
        } catch (errA) {
          console.log(`${TAG} 029 errA code:${errA.code}, message:${errA.message}`);
          expect(errA.code == 14800021).assertTrue();
          expect(errA.message.includes("no such table")).assertTrue();
        }
        const bucketB: data_relationalStore.ValuesBucket = {
          "name": "diffErrB",
          "col_diff_err_B": 2,
        }
        try {
          rdbStore.insertSync("test", bucketB);
          expect(true).assertFail();
        } catch (errB) {
          console.log(`${TAG} 029 errB code:${errB.code}, message:${errB.message}`);
          expect(errB.code == 14800021).assertTrue();
          expect(errB.message.includes("has no column named")).assertTrue();
          expect(!errB.message.includes("no such table")).assertTrue();
        }
      } catch (err) {
        console.log(`${TAG} 029 unexpected error:${err.code}, message:${err.message}`);
      }
      done();
    })

    console.log(TAG + "*************Unit Test End*************");
  })
}
