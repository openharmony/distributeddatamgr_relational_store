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
const TAG = "[RDB_STORE_UPDATE_WITH_RETURNING_TEST]";
let rdbStore: relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "data ASSET, " + "data1 ASSETS," + "blobType BLOB)";

const dbName = "UpdateRdbStore.db";
const STORE_CONFIG: relationalStore.StoreConfig = {
  name: dbName,
  securityLevel: relationalStore.SecurityLevel.S1,
};

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();
let options: relationalStore.TransactionOptions = {
  transactionType: relationalStore.TransactionType.DEFERRED
};
const defaultReturningConfig: relationalStore.ReturningConfig = { columns: ['name', 'age'] };

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
    let valueBuckets = new Array<relationalStore.ValuesBucket>();
    const num = 10;
    for (let i = 0; i < num; i++) {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' + i, 'age': 18 + i };
      valueBuckets.push(valueBucket);
    }
    let changedRows = await rdbStore?.batchInsert("test", valueBuckets);
    expect(changedRows).assertEqual(num);
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

export default function RdbStoreUpdateWithReturning() {
  describe('RdbStoreUpdateWithReturning', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
      await resetRdbStore();
    })
    afterEach(async () => {
      console.info(TAG + 'afterEach');
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning001
     * @tc.desc 1. Values is normal.
     */
    it('updateWithReturning001', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'lisi', 'age': 20 };
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan1');
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(1);
        results?.resultSet.goToNextRow();
        let row = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(row['name']).assertEqual("lisi");
        expect(row['age']).assertEqual(20);
        expect(results?.resultSet.goToNextRow()).assertFalse();
      };
      await call("updateWithReturning001", async () => {
        let results = await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
        await checkResult(results);
      });
      await resetRdbStore();
      await call("updateWithReturningSync001", async () => {
        let results = rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
        await checkResult(results);
      });
      let trans = await getTrans();
      await call("transUpdateWithReturning001", async () => {
        let results = await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
        await checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transUpdateWithReturningSync001", async () => {
        let results = trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning002
     * @tc.desc 1. Values is empty.
     */
    it('updateWithReturning002', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan4');
      await callAndCodeCheck("14800001", "updateWithReturning002", async () => {
        await rdbStore?.updateWithReturning({}, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "updateWithReturningSync002", async () => {
        rdbStore?.updateWithReturningSync({}, predicates, defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck("14800001", "transUpdateWithReturning002", async () => {
        await trans?.updateWithReturning({}, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "transUpdateWithReturningSync002", async () => {
        trans?.updateWithReturningSync({}, predicates, defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning003
     * @tc.desc 1. The tableName is wrong.
     */
    it('updateWithReturning003', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan', 'age': 18 };
      let predicates = new relationalStore.RdbPredicates("wrongTableName");
      predicates.equalTo('name', 'zhangsan4');
      await callAndCodeCheck(14800021, "updateWithReturning003", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800021, "updateWithReturningSync003", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800021, "transUpdateWithReturning003", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800021, "transUpdateWithReturningSync003", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning004
     * @tc.desc 1. There are spaces in the table name.
     */
    it('updateWithReturning004', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      let predicates = new relationalStore.RdbPredicates("test test1");
      await callAndCodeCheck("14800001", "updateWithReturning004", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "updateWithReturningSync004", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck("14800001", "transUpdateWithReturning004", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "transUpdateWithReturningSync004", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning005
     * @tc.desc 1. values.size > 1024, The returned results contains only 1024 entries.
     * Any excess entries are discarded, and the number of changed entries represents the actual number of modified rows.
     */
    it('updateWithReturning005', 0, async (done: Function) => {
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 10; i < 1025; i++) {
        const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' + i, 'age': 18 + i };
        valueBuckets.push(valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      const valueBucket1: relationalStore.ValuesBucket = { 'name': 'lisi', 'age': 18 };
      let initData = async () => {
        let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, defaultReturningConfig);
        expect(results?.changed).assertEqual(1015);
      };
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(1025);
        expect(getRowCount(results?.resultSet)).assertEqual(1024);
      };
      await call("updateWithReturning005", async () => {
        await initData();
        let results = await rdbStore?.updateWithReturning(valueBucket1, predicates, defaultReturningConfig);
        await checkResult(results);
      });
      await resetRdbStore();
      await call("updateWithReturningSync005", async () => {
        await initData();
        let results = rdbStore?.updateWithReturningSync(valueBucket1, predicates, defaultReturningConfig);
        await checkResult(results);
      });
      let trans = await getTrans();
      await call("transUpdateWithReturning005", async () => {
        await initData();
        let results = await trans?.updateWithReturning(valueBucket1, predicates, defaultReturningConfig);
        await checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transUpdateWithReturningSync005", async () => {
        await initData();
        let results = trans?.updateWithReturningSync(valueBucket1, predicates, defaultReturningConfig);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning006
     * @tc.desc 1. 0 < values.size <= 1024, The returned results can contain all the changed data.
     */
    it('updateWithReturning006', 0, async (done: Function) => {
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 10; i < 1024; i++) {
        const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' + i, 'age': 18 + i };
        valueBuckets.push(valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      const valueBucket1: relationalStore.ValuesBucket = { 'name': 'lisi', 'age': 18 };
      let initData = async () => {
        let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, defaultReturningConfig);
        expect(results?.changed).assertEqual(1014);
      };
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(1024);
        expect(getRowCount(results?.resultSet)).assertEqual(1024);
      };
      await call("updateWithReturning006", async () => {
        await initData();
        let results = await rdbStore?.updateWithReturning(valueBucket1, predicates, defaultReturningConfig);
        await checkResult(results);
      });
      await resetRdbStore();
      await call("updateWithReturningSync006", async () => {
        await initData();
        let results = rdbStore?.updateWithReturningSync(valueBucket1, predicates, defaultReturningConfig);
        await checkResult(results);
      });
      let trans = await getTrans();
      await call("transUpdateWithReturning006", async () => {
        await initData();
        let results = await trans?.updateWithReturning(valueBucket1, predicates, defaultReturningConfig);
        await checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transUpdateWithReturningSync006", async () => {
        await initData();
        let results = trans?.updateWithReturningSync(valueBucket1, predicates, defaultReturningConfig);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning007
     * @tc.desc 1. There are duplicate assets in the values.
     */
    it('updateWithReturning007', 0, async (done: Function) => {
      console.log(TAG + "************* updateWithReturning030 start *************");
      const asset1: relationalStore.Asset = {
        name: "example-image.jpg",
        uri: "content://media/external/images/media/12345",
        path: "/storage/emulated/0/Pictures/example-image.jpg",
        createTime: "2024-01-15T10:30:00Z",
        modifyTime: "2024-01-15T14:45:23Z",
        size: "2048576"
      }
      let assets: relationalStore.Assets = [asset1, asset1];
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'lisi', 'age': 30, 'data1': assets };
      let predicates = new relationalStore.RdbPredicates("test");
      await callAndCodeCheck("14800001", "updateWithReturning007", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "updateWithReturningSync007", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck("14800001", "transUpdateWithReturning007", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "transUpdateWithReturningSync007", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning008
     * @tc.desc 1. 1 < columns.size <= 4, Return the results of the specified field.
     */
    it('updateWithReturning008', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'lisi', 'age': 20 };
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan4');
      let checkResult = async (results:relationalStore.Result|undefined) => {
        results?.resultSet.goToNextRow();
        let row = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(row['name']).assertEqual("lisi");
        expect(row['age']).assertEqual(20);
      };
      await call("updateWithReturning008", async () => {
        let results = await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
        await checkResult(results);
      });
      await resetRdbStore();
      await call("updateWithReturningSync008", async () => {
        let results = rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
        await checkResult(results);
      });
      let trans = await getTrans();
      await call("transUpdateWithReturning008", async () => {
        let results = await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
        await checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transUpdateWithReturningSync008", async () => {
        let results = trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning009
     * @tc.desc 1. columns.size == 0, errCode 14800001.
     */
    it('updateWithReturning009', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan', 'age': 18 };
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = { columns: [] };
      await callAndCodeCheck("14800001", "updateWithReturning009", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, config);
      });
      await callAndCodeCheck("14800001", "updateWithReturningSync009", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, config);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck("14800001", "transUpdateWithReturning009", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, config);
      });
      await callAndCodeCheck("14800001", "transUpdateWithReturningSync009", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, config);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning010
     * @tc.desc 1. fields.size > 4, Throwing an error.
     */
    it('updateWithReturning010', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan', 'age': 18 };
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = { columns: ['name', 'age', 'salary', 'data', 'blobType'] };
      await callAndCodeCheck("14800001", "updateWithReturning010", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, config);
      });
      await callAndCodeCheck("14800001", "updateWithReturningSync010", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, config);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck("14800001", "transUpdateWithReturning010", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, config);
      });
      await callAndCodeCheck("14800001", "transUpdateWithReturningSync010", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, config);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning011
     * @tc.desc 1. columns contain special characters: "*"," ",",".
     */
    it('updateWithReturning011', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      let predicates = new relationalStore.RdbPredicates("test");
      let columnsCase = [['ab*'], ["a b"], ["a,b"] ];
      for (let i = 0; i < columnsCase.length; ++i) {
        const config: relationalStore.ReturningConfig = { columns: columnsCase[i] };
        await callAndCodeCheck('14800001', "updateWithReturning011-" + i, async () => {
          await rdbStore?.updateWithReturning(valueBucket, predicates, config);
        });
        await callAndCodeCheck('14800001', "updateWithReturningSync011-" + i, async () => {
          rdbStore?.updateWithReturningSync(valueBucket, predicates, config);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('14800001', "transUpdateWithReturning011-" + i, async () => {
          await trans?.updateWithReturning(valueBucket, predicates, config);
        });
        await callAndCodeCheck('14800001', "transUpdateWithReturningSync011-" + i, async () => {
          trans?.updateWithReturningSync(valueBucket, predicates, config);
        });
        await trans?.rollback();
      }
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning012
     * @tc.desc 1. Do not transmit conflict, handle according to the default conflict resolution mode.
     */
    it('updateWithReturning012', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': null };
      let predicates = new relationalStore.RdbPredicates("test");
      await callAndCodeCheck(14800032, "updateWithReturning012", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800032, "updateWithReturningSync012", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800032, "transUpdateWithReturning012", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800032, "transUpdateWithReturningSync012", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning013
     * @tc.desc 1. Conflict is null, handle according to the default conflict resolution mode.
     */
    it('updateWithReturning013', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': null };
      let predicates = new relationalStore.RdbPredicates("test");
      await callAndCodeCheck(14800032, "updateWithReturning013", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig, null);
      });
      await callAndCodeCheck(14800032, "updateWithReturningSync013", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig, null);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800032, "transUpdateWithReturning013", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig, null);
      });
      await callAndCodeCheck(14800032, "transUpdateWithReturningSync013", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig, null);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning014
     * @tc.desc 1. Conflict is undefined, handle according to the default conflict resolution mode.
     */
    it('updateWithReturning014', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': null };
      let predicates = new relationalStore.RdbPredicates("test");
      await callAndCodeCheck(14800032, "updateWithReturning014", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig, undefined);
      });
      await callAndCodeCheck(14800032, "updateWithReturningSync014", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig, undefined);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800032, "transUpdateWithReturning014", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig, undefined);
      });
      await callAndCodeCheck(14800032, "transUpdateWithReturningSync014", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig, undefined);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning015
     * @tc.desc 1. Conflict is ON_CONFLICT_REPLACE.
     */
    it('updateWithReturning015', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'id': 1, 'name': 'lisi', 'age': 20 };
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = { columns: ['id', 'name', 'age'] };
      let checkResult = async (results:relationalStore.Result|undefined,
        store:relationalStore.RdbStore|relationalStore.Transaction|undefined) => {
        expect(results?.changed).assertEqual(1);
        results?.resultSet.goToNextRow();
        let row = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(row['id']).assertEqual(1);
        expect(row['name']).assertEqual("lisi");
        expect(row['age']).assertEqual(20);
        expect(results?.resultSet.goToNextRow()).assertFalse();
        let res = await store?.querySql("SELECT * FROM test Where id = 1");
        res?.goToNextRow();
        row = res?.getRow() as relationalStore.ValuesBucket;
        expect(row['name']).assertEqual("lisi");
        res?.close();
      };
      await call("updateWithReturning015", async ()=> {
        let results = await rdbStore?.updateWithReturning(valueBucket, predicates, config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results, rdbStore);
      });
      await resetRdbStore();
      await call("updateWithReturningSync015", async ()=> {
        let results = rdbStore?.updateWithReturningSync(valueBucket, predicates, config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results, rdbStore);
      });
      let trans = await getTrans();
      await call("transUpdateWithReturning015", async ()=> {
        let results = await trans?.updateWithReturning(valueBucket, predicates, config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results, trans);
      });
      await trans.commit();
      trans = await getTrans();
      await call("transUpdateWithReturningSync015", async ()=> {
        let results = trans?.updateWithReturningSync(valueBucket, predicates, config,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
        await checkResult(results, trans);
      });
      await trans.commit();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning016
     * @tc.desc 1. Normal parameters, rdb already close.
     */
    it('updateWithReturning016', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      await rdbStore?.close();
      let predicates = new relationalStore.RdbPredicates("test");
      await callAndCodeCheck("14800014", "updateWithReturning016", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800014", "updateWithReturningSync016", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      let trans = await getTrans();
      await trans.commit();
      await callAndCodeCheck(14800014, "transUpdateWithReturning016", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800014, "transUpdateWithReturningSync016", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning017
     * @tc.desc 1. Abnormal parameters, rdb already close.
     */
    it('updateWithReturning017', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      await rdbStore?.close();
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = { columns: ['name?', 'age' ] };
      await callAndCodeCheck("14800014", "updateWithReturning017", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, config);
      });
      await callAndCodeCheck("14800014", "updateWithReturningSync017", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, config);
      });
      let trans = await getTrans();
      await trans.commit();
      await callAndCodeCheck(14800014, "transUpdateWithReturning017", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, config);
      });
      await callAndCodeCheck(14800014, "transUpdateWithReturningSync017", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, config);
      });
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning018
     * @tc.desc 1. Database corruption.
     */
    it('updateWithReturning018', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      await createCorruptDb(context, STORE_CONFIG);
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      await callAndCodeCheck(14800011, "updateWithReturning018", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800011, "updateWithReturningSync018", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      let trans = await getTrans();
      await createCorruptDb(context, STORE_CONFIG);
      await callAndCodeCheck(14800011, "transUpdateWithReturning018", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800011, "transUpdateWithReturningSync018", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning019
     * @tc.desc 1. The database file is locked.
     */
    it('updateWithReturning019', 0, async (done: Function) => {
      let deferredTrans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      let trans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      let predicates = new relationalStore.RdbPredicates("test");
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      await deferredTrans?.insert("test", valueBucket);
      await callAndCodeCheck(14800024, "batchInsertWithReturning019", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800024, "batchInsertWithReturningSync019", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800024, "transBatchInsertWithReturning019", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800024, "transBatchInsertWithReturningSync019", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      await deferredTrans?.rollback();
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning020
     * @tc.desc 1. The Database is full.
     */
    it('updateWithReturning020', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      let maxPageCount:number = await rdbStore?.execute("PRAGMA max_page_count = 256;");
      expect(maxPageCount).assertEqual(256);
      let u8 = new Uint8Array(1024 * 1024).fill(1);
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan1', 'blobType': u8 };
      await callAndCodeCheck(14800029, "updateWithReturning020", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800029, "updateWithReturningSync020", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      maxPageCount = await trans?.execute("PRAGMA max_page_count = 256;");
      expect(maxPageCount).assertEqual(256);
      await callAndCodeCheck(14800029, "transUpdateWithReturning020", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800029, "transUpdateWithReturningSync020", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning021
     * @tc.desc 1. Data type error.
     */
    it('updateWithReturning021', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { "id": "abc" };
      let predicates = new relationalStore.RdbPredicates("test");
      await callAndCodeCheck(14800033, "batchInsertWithReturning021", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800033, "batchInsertWithReturningSync021", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800033, "transBatchInsertWithReturning021", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800033, "transBatchInsertWithReturningSync021", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning022
     * @tc.desc 1. illegal table name
     */
    it('updateWithReturning022', 0, async (done: Function) => {
      let illegalTableNames:Array<string> = ["123test", "te.s.t", ".test", "test.."];
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      for (let i = 0; i < illegalTableNames.length; ++i) {
        let predicates = new relationalStore.RdbPredicates(illegalTableNames[i]);
        await callAndCodeCheck('14800001', "updateWithReturning022-" + i, async () => {
          await rdbStore?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
        });
        await callAndCodeCheck('14800001', "updateWithReturningSync022-" + i, async () => {
          rdbStore?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('14800001', "transUpdateWithReturning022-" + i, async () => {
          await trans?.updateWithReturning(valueBucket, predicates, defaultReturningConfig);
        });
        await callAndCodeCheck('14800001', "transUpdateWithReturningSync022-" + i, async () => {
          trans?.updateWithReturningSync(valueBucket, predicates, defaultReturningConfig);
        });
        await trans?.rollback();
      }
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning023
     * @tc.desc 1. maxReturningCount <= 0 || maxReturningCount > 0x7ffe.
     */
    it('updateWithReturning023', 0, async (done: Function) => {
      const MAX_RETURNING_COUNT = 0x7fff; // 32767
      let predicates = new relationalStore.RdbPredicates("test");
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      let maxReturningCounts:Array<number> = [-2, 0, MAX_RETURNING_COUNT];
      for (let i = 0; i < maxReturningCounts.length; ++i) {
        const config: relationalStore.ReturningConfig = {
          columns: ['name', 'age'],
          maxReturningCount: maxReturningCounts[i]
        };
        await callAndCodeCheck('14800001', "updateWithReturning023-" + i, async () => {
          await rdbStore?.updateWithReturning(valueBucket, predicates, config);
        });
        await callAndCodeCheck('14800001', "updateWithReturningSync023-" + i, async () => {
          rdbStore?.updateWithReturningSync(valueBucket, predicates, config);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('14800001', "transUpdateWithReturning023-" + i, async () => {
          await trans?.updateWithReturning(valueBucket, predicates, config);
        });
        await callAndCodeCheck('14800001', "transUpdateWithReturningSync023-" + i, async () => {
          trans?.updateWithReturningSync(valueBucket, predicates, config);
        });
        await trans?.rollback();
      }
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning024
     * @tc.desc 1. valueBuckets.size < maxReturningCount < 0x7FFF.
     */
    it('updateWithReturning024', 0, async (done: Function) => {
      const valueBucket: relationalStore.ValuesBucket = { "name": "lisi" };
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.between('id', 1, 2);
      const config: relationalStore.ReturningConfig = { columns: ['name'], maxReturningCount: 5 };
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(2);
        expect(getRowCount(results?.resultSet)).assertEqual(2);
      };
      await call("updateWithReturning024", async () => {
        let results = await rdbStore?.updateWithReturning(valueBucket, predicates, config);
        await checkResult(results);
      });
      await resetRdbStore();
      await call("updateWithReturningSync024", async () => {
        let results = rdbStore?.updateWithReturningSync(valueBucket, predicates, config);
        await checkResult(results);
      });
      let trans = await getTrans();
      await call("transUpdateWithReturning024", async () => {
        let results = await trans?.updateWithReturning(valueBucket, predicates, config);
        await checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transUpdateWithReturningSync024", async () => {
        let results = trans?.updateWithReturningSync(valueBucket, predicates, config);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning025
     * @tc.desc 1. maxReturningCount < valueBuckets.size < 0x7FFF.
     */
    it('updateWithReturning025', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.between('id', 1, 10);
      const config: relationalStore.ReturningConfig = { columns: ['name'], maxReturningCount: 5 };
      const valueBucket: relationalStore.ValuesBucket = { "name": "lisi" };
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(10);
        expect(getRowCount(results?.resultSet)).assertEqual(5);
      };
      await call("updateWithReturning025", async () => {
        let results = await rdbStore?.updateWithReturning(valueBucket, predicates, config);
        await checkResult(results);
      });
      await resetRdbStore();
      await call("updateWithReturningSync025", async () => {
        let results = rdbStore?.updateWithReturningSync(valueBucket, predicates, config);
        await checkResult(results);
      });
      let trans = await getTrans();
      await call("transUpdateWithReturning025", async () => {
        let results = await trans?.updateWithReturning(valueBucket, predicates, config);
        await checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transUpdateWithReturningSync025", async () => {
        let results = trans?.updateWithReturningSync(valueBucket, predicates, config);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning026
     * @tc.desc 1. Pass special characters to field names.
     */
    it('updateWithReturning026', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = { columns: ['name?']};
      const valueBucket: relationalStore.ValuesBucket = { "name": "lisi" };
      await callAndCodeCheck(14800021, "updateWithReturning026", async () => {
        await rdbStore?.updateWithReturning(valueBucket, predicates, config);
      });
      await callAndCodeCheck(14800021, "updateWithReturningSync026", async () => {
        rdbStore?.updateWithReturningSync(valueBucket, predicates, config);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800021, "transUpdateWithReturning026", async () => {
        await trans?.updateWithReturning(valueBucket, predicates, config);
      });
      await callAndCodeCheck(14800021, "transUpdateWithReturningSync026", async () => {
        trans?.updateWithReturningSync(valueBucket, predicates, config);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning027
     * @tc.desc 1. A table in the database is locked.
     */
    it('updateWithReturning027', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      const defaultVb: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
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
      await callAndCodeCheck(14800025, "updateWithReturning027", async () => {
        await rdbStore?.updateWithReturning(defaultVb, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800025, "updateWithReturningSync027", async () => {
        rdbStore?.updateWithReturningSync(defaultVb, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800025, "transUpdateWithReturning027", async () => {
        await trans?.updateWithReturning(defaultVb, predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800025, "transUpdateWithReturningSync027", async () => {
        trans?.updateWithReturningSync(defaultVb, predicates, defaultReturningConfig);
      });
      await deferredTrans?.rollback();
      await trans?.rollback();
      done();
    })

        /**
     * @tc.name updateWithReturning test.
     * @tc.number updateWithReturning028
     * @tc.desc 1.args is null or undefined test.
     */
    it('updateWithReturning028', 0, async (done: Function) => {
      let defaultPredicate = new relationalStore.RdbPredicates("test");
      const defaultVb: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      let values = [null, undefined, defaultVb, defaultVb, defaultVb, defaultVb];
      let predicates = [defaultPredicate, defaultPredicate, null, undefined, defaultPredicate, defaultPredicate];
      let configs = [
        defaultReturningConfig, defaultReturningConfig, defaultReturningConfig, defaultReturningConfig, null, undefined
      ];
      for (let i = 0; i < values.length; ++i) {
        await callAndCodeCheck('401', "updateWithReturning028", async () => {
          await rdbStore?.updateWithReturning(values[i], predicates[i], configs[i]);
        });
        await callAndCodeCheck('401', "updateWithReturningSync028", async () => {
          rdbStore?.updateWithReturningSync(values[i], predicates[i], configs[i]);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('401', "transUpdateWithReturning028", async () => {
          await trans?.updateWithReturning(values[i], predicates[i], configs[i]);
        });
        await callAndCodeCheck('401', "transUpdateWithReturningSync028", async () => {
          trans?.updateWithReturningSync(values[i], predicates[i], configs[i]);
        });
        await trans?.rollback();
      }
      done();
    })
  })
}