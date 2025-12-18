/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
import relationalStore from '@ohos.data.relationalStore';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import { createCorruptDb, getRowCount, callAndCodeCheck, call } from './TestUtils';
const TAG = "[RDB_STORE_BATCHINSERT_WITH_RETURNING_TEST]";
let rdbStore: relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "data ASSET, " + "data1 ASSETS," + "blobType BLOB)";

const dbName = "BachInsertRdbStore.db";
const STORE_CONFIG: relationalStore.StoreConfig = {
  name: dbName,
  securityLevel: relationalStore.SecurityLevel.S1,
}

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

let options: relationalStore.TransactionOptions = {
  transactionType: relationalStore.TransactionType.IMMEDIATE
}

const defaultReturningConfig: relationalStore.ReturningConfig = { columns: ['name', 'age'] };
const defaultVb: relationalStore.ValuesBucket = { 'name': 'zhangsan' };

async function resetRdbStore()
{
  console.info(TAG + 'resetRdbStore');
  try {
    await rdbStore?.close();
  } catch (e) {
    console.info(TAG + 'close failed');
  }
  try {
    await relationalStore.deleteRdbStore(context, STORE_CONFIG);
    rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
    expect(rdbStore != undefined).assertTrue();
    await rdbStore?.executeSql(CREATE_TABLE_TEST);
  } catch(e) {
    console.error(TAG + `resetRdbStore failed. code is ${e.code}, message is ${e.message}`);
    expect(true).assertFail();
  }
}

async function getTrans() : Promise<relationalStore.Transaction>
{
  await resetRdbStore();
  let trans = await rdbStore?.createTransaction(options);
  return trans as relationalStore.Transaction;
}

export default function RdbStoreBatchInsertWithReturning() {
  describe('RdbStoreBatchInsertWithReturning', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore?.executeSql(CREATE_TABLE_TEST);
    })
    afterEach(async () => {
      console.info(TAG + 'afterEach');
      await relationalStore.deleteRdbStore(context, STORE_CONFIG);
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning001
     * @tc.desc 1. empty table name.
     */
    it('batchInsertWithReturning001', 0, async (done: Function) => {
      await callAndCodeCheck("14800001", "batchInsertWithReturning001", async ()=>{
        await rdbStore?.batchInsertWithReturning("", [{'name': 'zhangsan'}], defaultReturningConfig);
      })
      await callAndCodeCheck("14800001", "batchInsertWithReturningSync001", async ()=>{
        rdbStore?.batchInsertWithReturningSync("", [{'name': 'zhangsan'}], defaultReturningConfig);
      })
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck("14800001", "transBatchInsertWithReturning001", async ()=>{
        await trans?.batchInsertWithReturning("", [{'name': 'zhangsan'}], defaultReturningConfig);
      })
      await callAndCodeCheck("14800001", "transBatchInsertWithReturningSync001", async ()=>{
        trans?.batchInsertWithReturningSync("", [{'name': 'zhangsan'}], defaultReturningConfig);
      })
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning002
     * @tc.desc 1. Incorrect table name.
     */
    it('batchInsertWithReturning002', 0, async (done: Function) => {
      await callAndCodeCheck(14800021, "batchInsertWithReturning002", async ()=>{
        await rdbStore?.batchInsertWithReturning("test1", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800021, "batchInsertWithReturningSync002", async ()=>{
        rdbStore?.batchInsertWithReturningSync("test1", [defaultVb], defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800021, "transBatchInsertWithReturning002", async ()=>{
        await trans?.batchInsertWithReturning("test1", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800021, "transBatchInsertWithReturningSync002", async ()=>{
        trans?.batchInsertWithReturningSync("test1", [defaultVb], defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning003
     * @tc.desc 1. There are spaces in the table name.
     */
    it('batchInsertWithReturning003', 0, async (done: Function) => {
      await callAndCodeCheck("14800001", "batchInsertWithReturning003", async ()=>{
        await rdbStore?.batchInsertWithReturning("test test1", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "batchInsertWithReturningSync003", async ()=>{
        rdbStore?.batchInsertWithReturningSync("test test1", [defaultVb], defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck("14800001", "transBatchInsertWithReturning003", async ()=>{
        await trans?.batchInsertWithReturning("test test1", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "transBatchInsertWithReturningSync003", async ()=>{
        trans?.batchInsertWithReturningSync("test test1", [defaultVb], defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning004
     * @tc.desc 1. The values is an empty array.
     */
    it('batchInsertWithReturning004', 0, async (done: Function) => {
      await callAndCodeCheck("14800001", "batchInsertWithReturning004", async ()=>{
        await rdbStore?.batchInsertWithReturning("test", [], defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "batchInsertWithReturningSync004", async ()=>{
        rdbStore?.batchInsertWithReturningSync("test", [], defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck("14800001", "transBatchInsertWithReturning004", async ()=>{
        await trans?.batchInsertWithReturning("test", [], defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "transBatchInsertWithReturningSync004", async ()=>{
        trans?.batchInsertWithReturningSync("test", [], defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning005
     * @tc.desc 1. Values: Pass in normal values.
     */
    it('batchInsertWithReturning005', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan', 'age': 18 };
      let checkResult = async (results:relationalStore.Result|undefined)=>{
        expect(results?.resultSet.goToNextRow()).assertTrue();
        const row:relationalStore.ValuesBucket = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(results?.changed).assertEqual(1);
        expect(row['name']).assertEqual("zhangsan");
        expect(row['age']).assertEqual(18);
      }
      await call("batchInsertWithReturning005", async ()=>{
        let results = await rdbStore?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
        await checkResult(results);
      })
      await resetRdbStore();
      await call("batchInsertWithReturningSync005", async ()=>{
        let results = rdbStore?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
        await checkResult(results);
      })
      let trans = await getTrans();
      await call("transBatchInsertWithReturning005", async ()=>{
        let results = await trans?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
        await checkResult(results);
        await trans.commit();
      })
      trans = await getTrans();
      await call("transBatchInsertWithReturningSync005", async ()=>{
        let results = trans?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
        await checkResult(results);
        await trans.commit();
      })
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning006
     * @tc.desc 1. There are duplicate assets in the values.
     */
    it('batchInsertWithReturning006', 0, async (done: Function) => {
      const asset: relationalStore.Asset = {
        name: "example-image.jpg",
        uri: "content://media/external/images/media/12345",
        path: "/storage/emulated/0/Pictures/example-image.jpg",
        createTime: "2024-01-15T10:30:00Z",
        modifyTime: "2024-01-15T14:45:23Z",
        size: "2048576"
      }
      let assets: relationalStore.Assets = [asset, asset];
      const valueBucket: relationalStore.ValuesBucket = { 'data1': assets };
      await callAndCodeCheck("14800001", "batchInsertWithReturning006", async ()=>{
        await rdbStore?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      })
      await callAndCodeCheck("14800001", "batchInsertWithReturningSync006", async ()=>{
        rdbStore?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      })
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck("14800001", "transBatchInsertWithReturning006", async ()=>{
        await trans?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      })
      await callAndCodeCheck("14800001", "transBatchInsertWithReturningSync006", async ()=>{
        trans?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      })
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning007
     * @tc.desc 1. 1 < values.size <= 1024, The returned results can contain all the changed data.
     */
    it('batchInsertWithReturning007', 0, async (done: Function) => {
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 0; i < 1024; i++) {
        const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' + i };
        valueBuckets.push(valueBucket);
      }
      let checkResult = (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(1024);
        expect(getRowCount(results?.resultSet)).assertEqual(1024);
      };
      await call("batchInsertWithReturning007", async ()=> {
        let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, defaultReturningConfig);
        checkResult(results);
      });
      await resetRdbStore();
      await call("batchInsertWithReturningSync007", async ()=> {
        let results = rdbStore?.batchInsertWithReturningSync("test", valueBuckets, defaultReturningConfig);
        checkResult(results);
      });
      let trans = await getTrans();
      await call("transBatchInsertWithReturning007", async ()=> {
        let results = await trans?.batchInsertWithReturning("test", valueBuckets, defaultReturningConfig);
        checkResult(results);
      });
      trans = await getTrans();
      await call("transBatchInsertWithReturningSync007", async ()=> {
        let results = trans?.batchInsertWithReturningSync("test", valueBuckets, defaultReturningConfig);
        checkResult(results);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning008
     * @tc.desc 1. values.size > 1024, The returned results contains only 1024 entries.
     * Any excess entries are discarded, and the number of changed entries represents the actual number of modified rows.
     */
    it('batchInsertWithReturning008', 0, async (done: Function) => {
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 0; i < 1025; i++) {
        const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' + i };
        valueBuckets.push(valueBucket);
      }
      let checkResult = (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(1025);
        expect(getRowCount(results?.resultSet)).assertEqual(1024);
      };
      await call("batchInsertWithReturning008", async ()=> {
        let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, defaultReturningConfig);
        checkResult(results);
      });
      await resetRdbStore();
      await call("batchInsertWithReturningSync008", async ()=> {
        let results = rdbStore?.batchInsertWithReturningSync("test", valueBuckets, defaultReturningConfig);
        checkResult(results);
      });
      let trans = await getTrans();
      await call("transBatchInsertWithReturning008", async ()=> {
        let results = await trans?.batchInsertWithReturning("test", valueBuckets, defaultReturningConfig);
        checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transBatchInsertWithReturningSync008", async ()=> {
        let results = trans?.batchInsertWithReturningSync("test", valueBuckets, defaultReturningConfig);
        checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning009
     * @tc.desc 1. 1 < columns.size <= 4, Return the results of the specified field.
     */
    it('batchInsertWithReturning009', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan', 'age': 18 };
      let checkResult = (results:relationalStore.Result|undefined) => {
        results?.resultSet.goToNextRow();
        let row = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(row['name']).assertEqual("zhangsan");
        expect(row['age']).assertEqual(18);
      };
      await call("batchInsertWithReturning009", async ()=> {
        let results = await rdbStore?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
        checkResult(results);
      });
      await resetRdbStore();
      await call("batchInsertWithReturningSync009", async ()=> {
        let results = rdbStore?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
        checkResult(results);
      });
      let trans = await getTrans();
      await call("transBatchInsertWithReturning009", async ()=> {
        let results = await trans?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
        checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transBatchInsertWithReturningSync009", async ()=> {
        let results = trans?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
        checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning010
     * @tc.desc 1. columns.size == 0.
     */
    it('batchInsertWithReturning010', 0, async (done: Function) => {
      const config: relationalStore.ReturningConfig = { columns: [] };
      await callAndCodeCheck('14800001', "batchInsertWithReturning010", async () => {
        await rdbStore?.batchInsertWithReturning("test", [defaultVb], config);
      });
      await callAndCodeCheck('14800001', "batchInsertWithReturningSync010", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [defaultVb], config);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck('14800001', "transBatchInsertWithReturning010", async () => {
        await trans?.batchInsertWithReturning("test", [defaultVb], config);
      });
      await callAndCodeCheck('14800001', "transBatchInsertWithReturningSync010", async () => {
        trans?.batchInsertWithReturningSync("test", [defaultVb], config);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning011
     * @tc.desc 1. columns.size > 4, Throwing an error.
     */
    it('batchInsertWithReturning011', 0, async (done: Function) => {
      const config: relationalStore.ReturningConfig = { columns: ['name', 'age', 'salary', 'data', 'blobType'] };
      await callAndCodeCheck('14800001', "batchInsertWithReturning011", async () => {
        await rdbStore?.batchInsertWithReturning("test", [defaultVb], config);
      });
      await callAndCodeCheck('14800001', "batchInsertWithReturningSync011", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [defaultVb], config);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck('14800001', "transBatchInsertWithReturning011", async () => {
        await trans?.batchInsertWithReturning("test", [defaultVb], config);
      });
      await callAndCodeCheck('14800001', "transBatchInsertWithReturningSync011", async () => {
        trans?.batchInsertWithReturningSync("test", [defaultVb], config);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning012
     * @tc.desc 1. columns contain special characters: "*"," ",",".
     */
    it('batchInsertWithReturning012', 0, async (done: Function) => {
      let columnsCase = [['ab*'], ["a b"], ["a,b"] ];
      for (let i = 0; i < columnsCase.length; ++i) {
        const config: relationalStore.ReturningConfig = { columns: columnsCase[i] };
        await callAndCodeCheck('14800001', "batchInsertWithReturning012-" + i, async () => {
          await rdbStore?.batchInsertWithReturning("test", [defaultVb], config);
        });
        await callAndCodeCheck('14800001', "batchInsertWithReturningSync012-" + i, async () => {
          rdbStore?.batchInsertWithReturningSync("test", [defaultVb], config);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('14800001', "transBatchInsertWithReturning012-" + i, async () => {
          await trans?.batchInsertWithReturning("test", [defaultVb], config);
        });
        await callAndCodeCheck('14800001', "transBatchInsertWithReturningSync012-" + i, async () => {
          trans?.batchInsertWithReturningSync("test", [defaultVb], config);
        });
        await trans?.rollback();
      }
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning013
     * @tc.desc 1. Do not transmit conflict, handle according to the default conflict resolution mode.
     */
    it('batchInsertWithReturning013', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      await rdbStore?.insert("test", valueBucket);
      valueBucket.name = "lisi";
      await callAndCodeCheck(14800032, "batchInsertWithReturning013", async () => {
        await rdbStore?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      });
      await callAndCodeCheck(14800032, "batchInsertWithReturningSync013", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800032, "transBatchInsertWithReturning013", async () => {
        await trans?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      });
      await callAndCodeCheck(14800032, "transBatchInsertWithReturningSync013", async () => {
        trans?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning014
     * @tc.desc 1. Conflict is null, handle according to the default conflict resolution mode.
     */
    it('batchInsertWithReturning014', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'id': 1, 'name': 'zhangsan' };
      await rdbStore?.insert("test", valueBucket);
      valueBucket.name = "lisi";
      await callAndCodeCheck(14800032, "batchInsertWithReturning014", async () => {
        await rdbStore?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig, null);
      });
      await callAndCodeCheck(14800032, "batchInsertWithReturningSync014", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig, null);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800032, "transBatchInsertWithReturning014", async () => {
        await trans?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig, null);
      });
      await callAndCodeCheck(14800032, "transBatchInsertWithReturningSync014", async () => {
        trans?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig, null);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning015
     * @tc.desc 1. Conflict is undefined, handle according to the default conflict resolution mode.
     */
    it('batchInsertWithReturning015', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'id': 1, 'name': 'zhangsan' };
      await rdbStore?.insert("test", valueBucket);
      valueBucket.name = "lisi";
      await callAndCodeCheck(14800032, "batchInsertWithReturning015", async () => {
        await rdbStore?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig, undefined);
      });
      await callAndCodeCheck(14800032, "batchInsertWithReturningSync015", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig, undefined);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800032, "transBatchInsertWithReturning015", async () => {
        await trans?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig, undefined);
      });
      await callAndCodeCheck(14800032, "transBatchInsertWithReturningSync015", async () => {
        trans?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig, undefined);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning016
     * @tc.desc 1. Conflict is ON_CONFLICT_REPLACE.
     */
    it('batchInsertWithReturning016', 0, async (done: Function) => {
      const valueBucket1: relationalStore.ValuesBucket = {'id': 1, 'name': 'zhangsan', 'age': 18 };
      const valueBucket2: relationalStore.ValuesBucket = { 'id': 1, 'name': 'lisi', 'age': 20 };
      const config: relationalStore.ReturningConfig = { columns: ['id', 'name', 'age'] };
      let checkResult = async (results:relationalStore.Result|undefined,
        store:relationalStore.RdbStore|relationalStore.Transaction|undefined) => {
        expect(results?.changed).assertEqual(2);
        results?.resultSet.goToNextRow();
        let row = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(row['id']).assertEqual(1);
        expect(row['name']).assertEqual("zhangsan");
        expect(row['age']).assertEqual(18);
        results?.resultSet.goToNextRow();
        row = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(row['id']).assertEqual(1);
        expect(row['name']).assertEqual("lisi");
        expect(row['age']).assertEqual(20);
        let res = await store?.querySql("SELECT * FROM test");
        expect(res?.rowCount).assertEqual(1);
        res?.goToNextRow();
        row = res?.getRow() as relationalStore.ValuesBucket;
        expect(row['name']).assertEqual("lisi");
        res?.close();
      };
      await call("batchInsertWithReturning016", async ()=> {
        let results = await rdbStore?.batchInsertWithReturning("test", [valueBucket1, valueBucket2], config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results, rdbStore);
      });
      await resetRdbStore();
      await call("batchInsertWithReturningSync016", async ()=> {
        let results = rdbStore?.batchInsertWithReturningSync("test", [valueBucket1, valueBucket2], config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results, rdbStore);
      });
      let trans = await getTrans();
      await call("transBatchInsertWithReturning016", async ()=> {
        let results = await trans?.batchInsertWithReturning("test", [valueBucket1, valueBucket2], config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results, trans);
      });
      await trans.commit();
      trans = await getTrans();
      await call("transBatchInsertWithReturningSync016", async ()=> {
        let results = trans?.batchInsertWithReturningSync("test", [valueBucket1, valueBucket2], config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results, trans);
      });
      await trans.commit();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning017
     * @tc.desc 1. Normal parameters, rdb already close.
     */
    it('batchInsertWithReturning017', 0, async (done: Function) => {
      await rdbStore?.close();
      await callAndCodeCheck('14800014', "batchInsertWithReturning017", async () => {
        await rdbStore?.batchInsertWithReturning("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck('14800014', "batchInsertWithReturningSync017", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [defaultVb], defaultReturningConfig);
      });
      await resetRdbStore();
      let trans = await rdbStore?.createTransaction(options);
      await trans?.commit();
      await callAndCodeCheck(14800014, "transBatchInsertWithReturning017", async () => {
        await trans?.batchInsertWithReturning("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800014, "transBatchInsertWithReturningSync017", async () => {
        trans?.batchInsertWithReturningSync("test", [defaultVb], defaultReturningConfig);
      });
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning018
     * @tc.desc 1. Abnormal parameters, rdb already close.
     */
    it('batchInsertWithReturning018', 0, async (done: Function) => {
      const config: relationalStore.ReturningConfig = { columns: ['name?', 'age'] };
      await rdbStore?.close();
      await callAndCodeCheck('14800014', "batchInsertWithReturning018", async () => {
        await rdbStore?.batchInsertWithReturning("test", [defaultVb], config);
      });
      await callAndCodeCheck('14800014', "batchInsertWithReturningSync018", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [defaultVb], config);
      });
      await resetRdbStore();
      let trans = await rdbStore?.createTransaction(options);
      await trans?.commit();
      await callAndCodeCheck(14800014, "transBatchInsertWithReturning018", async () => {
        await trans?.batchInsertWithReturning("test", [defaultVb], config);
      });
      await callAndCodeCheck(14800014, "transBatchInsertWithReturningSync018", async () => {
        trans?.batchInsertWithReturningSync("test", [defaultVb], config);
      });
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning019
     * @tc.desc 1. Database corruption.
     */
    it('batchInsertWithReturning019', 0, async (done: Function) => {
      await createCorruptDb(context, STORE_CONFIG);
      await callAndCodeCheck(14800011, "batchInsertWithReturning019", async () => {
        await rdbStore?.batchInsertWithReturning("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800011, "batchInsertWithReturningSync019", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [defaultVb], defaultReturningConfig);
      });
      await resetRdbStore();
      let trans = await rdbStore?.createTransaction(options);
      await createCorruptDb(context, STORE_CONFIG);
      await callAndCodeCheck(14800011, "transBatchInsertWithReturning019", async () => {
        await trans?.batchInsertWithReturning("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800011, "transBatchInsertWithReturningSync019", async () => {
        trans?.batchInsertWithReturningSync("test", [defaultVb], defaultReturningConfig);
      });
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning020
     * @tc.desc 1. The database file is locked.
     */
    it('batchInsertWithReturning020', 0, async (done: Function) => {
      let deferredTrans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      let trans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      await deferredTrans?.insert("test", defaultVb);
      await callAndCodeCheck(14800024, "batchInsertWithReturning020", async () => {
        await rdbStore?.batchInsertWithReturning("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800024, "batchInsertWithReturningSync020", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800024, "transBatchInsertWithReturning020", async () => {
        await trans?.batchInsertWithReturning("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800024, "transBatchInsertWithReturningSync020", async () => {
        trans?.batchInsertWithReturningSync("test", [defaultVb], defaultReturningConfig);
      });
      await deferredTrans?.rollback();
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning021
     * @tc.desc 1. A table in the database is locked.
     */
    it('batchInsertWithReturning021', 0, async (done: Function) => {
      const STORE_CONFIG1: relationalStore.StoreConfig = {
        name: dbName,
        securityLevel: relationalStore.SecurityLevel.S1,
        persist: false,
      };
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      await rdbStore?.executeSql(CREATE_TABLE_TEST);
      let deferredTrans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      let trans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      await deferredTrans?.insert("test", defaultVb);
      await callAndCodeCheck(14800025, "batchInsertWithReturning021", async () => {
        await rdbStore?.batchInsertWithReturning("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800025, "batchInsertWithReturningSync021", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800025, "transBatchInsertWithReturning021", async () => {
        await trans?.batchInsertWithReturning("test", [defaultVb], defaultReturningConfig);
      });
      await callAndCodeCheck(14800025, "transBatchInsertWithReturningSync021", async () => {
        trans?.batchInsertWithReturningSync("test", [defaultVb], defaultReturningConfig);
      });
      await deferredTrans?.rollback();
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning022
     * @tc.desc 1. The Database is full.
     */
    it('batchInsertWithReturning022', 0, async (done: Function) => {
      let maxPageCount:number = await rdbStore?.execute("PRAGMA max_page_count = 256;");
      expect(maxPageCount).assertEqual(256);
      let u8 = new Uint8Array(1024 * 1024).fill(1);
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan1', 'blobType': u8 };
      await callAndCodeCheck(14800029, "batchInsertWithReturning022", async () => {
        await rdbStore?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      });
      await callAndCodeCheck(14800029, "batchInsertWithReturningSync022", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      maxPageCount = await trans?.execute("PRAGMA max_page_count = 256;");
      expect(maxPageCount).assertEqual(256);
      await callAndCodeCheck(14800029, "transBatchInsertWithReturning022", async () => {
        await trans?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      });
      await callAndCodeCheck(14800029, "transBatchInsertWithReturningSync022", async () => {
        trans?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning023
     * @tc.desc 1. Violation of constraints.
     */
    it('batchInsertWithReturning023', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { "name": null };
      await callAndCodeCheck(14800032, "batchInsertWithReturning023", async () => {
        await rdbStore?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      });
      await callAndCodeCheck(14800032, "batchInsertWithReturningSync023", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800032, "transBatchInsertWithReturning023", async () => {
        await trans?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      });
      await callAndCodeCheck(14800032, "transBatchInsertWithReturningSync023", async () => {
        trans?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning024
     * @tc.desc 1. Data type error.
     */
    it('batchInsertWithReturning024', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { "id": "abc", "name": 18 };
      await callAndCodeCheck(14800033, "batchInsertWithReturning024", async () => {
        await rdbStore?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      });
      await callAndCodeCheck(14800033, "batchInsertWithReturningSync024", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800033, "transBatchInsertWithReturning024", async () => {
        await trans?.batchInsertWithReturning("test", [valueBucket], defaultReturningConfig);
      });
      await callAndCodeCheck(14800033, "transBatchInsertWithReturningSync024", async () => {
        trans?.batchInsertWithReturningSync("test", [valueBucket], defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning025
     * @tc.desc 1. conflict: ON_CONFLICT_REPLACE, twice batchInsertWithReturning.
     */
    it('batchInsertWithReturning025', 0, async (done: Function) => {
      const valueBucket1: relationalStore.ValuesBucket = { "id": 1, "name": "zhangsan", "age": 18 };
      const valueBucket2: relationalStore.ValuesBucket = { "id": 1, "name": "lisi", "age": 20 };
      const config: relationalStore.ReturningConfig = { columns: ['name', 'age', 'id'] };
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(1);
        results?.resultSet.goToNextRow();
        let row = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(row['id']).assertEqual(1);
        expect(row['name']).assertEqual("lisi");
        expect(row['age']).assertEqual(20);
      }
      await call("batchInsertWithReturning025", async () => {
        await rdbStore?.batchInsertWithReturning("test", [valueBucket1], config);
        let results = await rdbStore?.batchInsertWithReturning("test", [valueBucket2], config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results);
      });
      await resetRdbStore();
      await call("batchInsertWithReturningSync025", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [valueBucket1], config);
        let results = rdbStore?.batchInsertWithReturningSync("test", [valueBucket2], config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results);
      });
      let trans = await getTrans();
      await call("transBatchInsertWithReturning025", async () => {
        await trans?.batchInsertWithReturning("test", [valueBucket1], config);
        let results = await trans?.batchInsertWithReturning("test", [valueBucket2], config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transBatchInsertWithReturningSync025", async () => {
        await trans?.batchInsertWithReturning("test", [valueBucket1], config);
        let results = await trans?.batchInsertWithReturning("test", [valueBucket2], config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning026
     * @tc.desc 1. illegal table name
     */
    it('batchInsertWithReturning026', 0, async (done: Function) => {
      let illegalTableNames:Array<string> = ["123test", "te.s.t", ".test", "test.."];
      for (let i = 0; i < illegalTableNames.length; ++i) {
        await callAndCodeCheck('14800001', "batchInsertWithReturning026-" + i, async () => {
          await rdbStore?.batchInsertWithReturning(illegalTableNames[i], [defaultVb], defaultReturningConfig);
        });
        await callAndCodeCheck('14800001', "batchInsertWithReturningSync026-" + i, async () => {
          rdbStore?.batchInsertWithReturningSync(illegalTableNames[i], [defaultVb], defaultReturningConfig);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('14800001', "transBatchInsertWithReturning026-" + i, async () => {
          await trans?.batchInsertWithReturning(illegalTableNames[i], [defaultVb], defaultReturningConfig);
        });
        await callAndCodeCheck('14800001', "transBatchInsertWithReturningSync026-" + i, async () => {
          trans?.batchInsertWithReturningSync(illegalTableNames[i], [defaultVb], defaultReturningConfig);
        });
        await trans?.rollback();
      }
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning027
     * @tc.desc 1. maxReturningCount <= 0 || maxReturningCount > 0x7ffe.
     */
    it('batchInsertWithReturning027', 0, async (done: Function) => {
      const MAX_RETURNING_COUNT = 0x7fff; // 32767
      let maxReturningCounts:Array<number> = [-2, 0, MAX_RETURNING_COUNT];
      for (let i = 0; i < maxReturningCounts.length; ++i) {
        const config: relationalStore.ReturningConfig = {
          columns: ['name', 'age'],
          maxReturningCount: maxReturningCounts[i]
        };
        await callAndCodeCheck('14800001', "batchInsertWithReturning027-" + i, async () => {
          await rdbStore?.batchInsertWithReturning("test", [defaultVb], config);
        });
        await callAndCodeCheck('14800001', "batchInsertWithReturningSync027-" + i, async () => {
          rdbStore?.batchInsertWithReturningSync("test", [defaultVb], config);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('14800001', "transBatchInsertWithReturning027-" + i, async () => {
          await trans?.batchInsertWithReturning("test", [defaultVb], config);
        });
        await callAndCodeCheck('14800001', "transBatchInsertWithReturningSync027-" + i, async () => {
          trans?.batchInsertWithReturningSync("test", [defaultVb], config);
        });
        await trans?.rollback();
      }
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning028
     * @tc.desc 1. valueBuckets.size < maxReturningCount < 0x7FFF.
     */
    it('batchInsertWithReturning028', 0, async (done: Function) => {
      const config: relationalStore.ReturningConfig = { columns: ['name'], maxReturningCount: 5 };
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(2);
        expect(getRowCount(results?.resultSet)).assertEqual(2);
      };
      await call("batchInsertWithReturning028", async () => {
        let results = await rdbStore?.batchInsertWithReturning("test", [defaultVb, defaultVb], config);
        await checkResult(results);
      });
      await call("batchInsertWithReturningSync028", async () => {
        let results = rdbStore?.batchInsertWithReturningSync("test", [defaultVb, defaultVb], config);
        await checkResult(results);
      });
      let trans = await rdbStore?.createTransaction(options);
      await call("transBatchInsertWithReturning028", async () => {
        let results = await trans?.batchInsertWithReturning("test", [defaultVb, defaultVb], config);
        await checkResult(results);
      });
      await call("transBatchInsertWithReturningSync028", async () => {
        let results = trans?.batchInsertWithReturningSync("test", [defaultVb, defaultVb], config);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning029
     * @tc.desc 1. maxReturningCount < valueBuckets.size < 0x7FFF.
     */
    it('batchInsertWithReturning029', 0, async (done: Function) => {
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 0; i < 10; i++) {
        const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' + i, };
        valueBuckets.push(valueBucket);
      }
      const config: relationalStore.ReturningConfig = { columns: ['name'], maxReturningCount: 5 };
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(10);
        expect(getRowCount(results?.resultSet)).assertEqual(5);
      };
      await call("batchInsertWithReturning029", async () => {
        let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, config);
        await checkResult(results);
      });
      await call("batchInsertWithReturningSync029", async () => {
        let results = rdbStore?.batchInsertWithReturningSync("test", valueBuckets, config);
        await checkResult(results);
      });
      let trans = await rdbStore?.createTransaction(options);
      await call("transBatchInsertWithReturning029", async () => {
        let results = await trans?.batchInsertWithReturning("test", valueBuckets, config);
        await checkResult(results);
      });
      await call("transBatchInsertWithReturningSync029", async () => {
        let results = trans?.batchInsertWithReturningSync("test", valueBuckets, config);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning030
     * @tc.desc 1. Pass special characters to field names.
     */
    it('batchInsertWithReturning030', 0, async (done: Function) => {
      const config: relationalStore.ReturningConfig = { columns: ['name?']};
      await callAndCodeCheck(14800021, "batchInsertWithReturning023", async () => {
        await rdbStore?.batchInsertWithReturning("test", [defaultVb], config);
      });
      await callAndCodeCheck(14800021, "batchInsertWithReturningSync023", async () => {
        rdbStore?.batchInsertWithReturningSync("test", [defaultVb], config);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800021, "transBatchInsertWithReturning023", async () => {
        await trans?.batchInsertWithReturning("test", [defaultVb], config);
      });
      await callAndCodeCheck(14800021, "transBatchInsertWithReturningSync023", async () => {
        trans?.batchInsertWithReturningSync("test", [defaultVb], config);
      });
      await trans?.rollback();
      done();
    })
  })
}