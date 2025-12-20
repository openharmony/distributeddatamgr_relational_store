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
import { createCorruptDb, getRowCount, callAndCodeCheck, call, callAndReturnCode } from './TestUtils';
const TAG = "[RDB_STORE_DELETE_WITH_RETURNING_TEST]";
let rdbStore: relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "data ASSET, " + "data1 ASSETS," + "blobType BLOB," +
  "test_id INTEGER," + "FOREIGN KEY (test_id) REFERENCES test1(test_id)" + ");"

const CREATE_TABLE_TEST1 =
  "CREATE TABLE IF NOT EXISTS test1 (" + " test_id INTEGER PRIMARY KEY AUTOINCREMENT," + "test_name TEXT NOT NULL" +
    ");";

const FOREIGN_KEYS_ON = "PRAGMA foreign_keys = ON;";
const FOREIGN_KEYS_OFF = "PRAGMA foreign_keys = OFF;";

const dbName = "DeleteRdbStore.db";
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
    await rdbStore?.execute(CREATE_TABLE_TEST1);
    await rdbStore?.execute(CREATE_TABLE_TEST);
    let valueBuckets = new Array<relationalStore.ValuesBucket>();
    let valueBuckets1 = new Array<relationalStore.ValuesBucket>();
    const num = 10;
    for (let i = 0; i < num; i++) {
      const valueBucket: relationalStore.ValuesBucket = { 'test_name': 'lisi' + i };
      valueBuckets1.push(valueBucket);
    }
    let changeRows = await rdbStore?.batchInsert("test1", valueBuckets1);
    expect(changeRows).assertEqual(num);
    for (let i = 0; i < num; i++) {
      const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' + i, 'age': 18 + i, 'test_id': i };
      valueBuckets.push(valueBucket);
    }
    changeRows = await rdbStore?.batchInsert("test", valueBuckets);
    expect(changeRows).assertEqual(num);
  } catch (e) {
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

export default function RdbStoreDeleteWithReturning() {
  describe('rdbStoreDeleteWithReturning', () => {
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
      try {
        await rdbStore?.close();
      } catch (e) {
        console.info(TAG + 'afterAll close failed');
      }
      try {
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch(e) {
        console.error(TAG + `afterAll resetRdbStore failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning001
     * @tc.desc 1. Values is normal.
     */
    it('deleteWithReturning001', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan1');
      let checkResult = (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(1);
        results?.resultSet.goToNextRow();
        let row = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(row['name']).assertEqual("zhangsan1");
        expect(row['age']).assertEqual(19);
      };
      await call('deleteWithReturning001', async () => {
        let results = await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
        checkResult(results);
      });
      await resetRdbStore();
      await call('deleteWithReturningSync001', async () => {
        let results = rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
        checkResult(results);
      });
      let trans = await getTrans();
      await call('transDeleteWithReturning001', async () => {
        let results = await trans?.deleteWithReturning(predicates, defaultReturningConfig);
        checkResult(results);
        await trans.commit();
      });
      trans = await getTrans();
      await call('transDeleteWithReturningSync001', async () => {
        let results = trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
        checkResult(results);
        await trans.commit();
      });
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning002
     * @tc.desc 1. The tableName is wrong.
     */
    it('deleteWithReturning002', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("wrongTableName");
      await callAndCodeCheck(14800021, "deleteWithReturning002", async () => {
        await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800021, "deleteWithReturningSync002", async () => {
        rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      let trans = await getTrans();
      await callAndCodeCheck(14800021, "transDeleteWithReturning002", async () => {
        await trans?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800021, "transDeleteWithReturningSync002", async () => {
        trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning003
     * @tc.desc 1. There are spaces in the table name.
     */
    it('deleteWithReturning003', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test test1");
      await callAndCodeCheck("14800001", "deleteWithReturning003", async () => {
        await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "deleteWithReturningSync003", async () => {
        rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      let trans = await getTrans();
      await callAndCodeCheck("14800001", "transDeleteWithReturning003", async () => {
        await trans?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800001", "transDeleteWithReturningSync003", async () => {
        trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning004
     * @tc.desc 1. 0 < values.size <= 1024, The returned results can contain all the changed data.
     */
    it('deleteWithReturning004', 0, async (done: Function) => {
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 10; i < 1024; i++) {
        const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' + i };
        valueBuckets.push(valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.contains('name', 'zhangsan');
      let initData = async (store:relationalStore.RdbStore|relationalStore.Transaction|undefined) => {
        let results = await store?.batchInsertWithReturning("test", valueBuckets, defaultReturningConfig);
        expect(results?.changed).assertEqual(1014);
      };
      let checkResult = (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(1024);
        expect(getRowCount(results?.resultSet)).assertEqual(1024);
      };

      await call('deleteWithReturning004', async () => {
        await initData(rdbStore);
        let results = await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
        checkResult(results);
      });
      await resetRdbStore();
      await call('deleteWithReturningSync004', async () => {
        await initData(rdbStore);
        let results = rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
        checkResult(results);
      });
      let trans = await getTrans();
      await call('transDeleteWithReturning004', async () => {
        await initData(trans);
        let results = await trans?.deleteWithReturning(predicates, defaultReturningConfig);
        checkResult(results);
        await trans.commit();
      });
      trans = await getTrans();
      await call('transDeleteWithReturningSync004', async () => {
        await initData(trans);
        let results = trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
        checkResult(results);
        await trans.commit();
      });
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning005
     * @tc.desc 1. values.size > 1024, The returned results contains only 1024 entries.
     * Any excess entries are discarded, and the number of changed entries represents the actual number of modified rows.
     */
    it('deleteWithReturning005', 0, async (done: Function) => {
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 10; i < 1025; i++) {
        const valueBucket: relationalStore.ValuesBucket = { 'name': 'zhangsan' + i };
        valueBuckets.push(valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.contains('name', 'zhangsan');
      let initData = async (store:relationalStore.RdbStore|relationalStore.Transaction|undefined) => {
        let results = await store?.batchInsertWithReturning("test", valueBuckets, defaultReturningConfig);
        expect(results?.changed).assertEqual(1015);
      };
      let checkResult = (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(1025);
        expect(getRowCount(results?.resultSet)).assertEqual(1024);
      };

      await call('deleteWithReturning005', async () => {
        await initData(rdbStore);
        let results = await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
        checkResult(results);
      });
      await resetRdbStore();
      await call('deleteWithReturningSync005', async () => {
        await initData(rdbStore);
        let results = rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
        checkResult(results);
      });
      let trans = await getTrans();
      await call('transDeleteWithReturning005', async () => {
        await initData(trans);
        let results = await trans?.deleteWithReturning(predicates, defaultReturningConfig);
        checkResult(results);
        await trans.commit();
      });
      trans = await getTrans();
      await call('transDeleteWithReturningSync005', async () => {
        await initData(trans);
        let results = trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
        checkResult(results);
        await trans.commit();
      });
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning006
     * @tc.desc 1. 1 < columns.size <= 4, Return the results of the specified field.
     */
    it('deleteWithReturning006', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan4');
      let checkResult = (results:relationalStore.Result|undefined) => {
        results?.resultSet.goToNextRow();
        let row = results?.resultSet.getRow() as relationalStore.ValuesBucket;
        expect(row['name']).assertEqual("zhangsan4");
        expect(row['age']).assertEqual(22);
      };
      await call('deleteWithReturning006', async () => {
        let results = await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
        checkResult(results);
      });
      await resetRdbStore();
      await call('deleteWithReturningSync006', async () => {
        let results = rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
        checkResult(results);
      });
      let trans = await getTrans();
      await call('transDeleteWithReturning006', async () => {
        let results = await trans?.deleteWithReturning(predicates, defaultReturningConfig);
        checkResult(results);
        await trans.commit();
      });
      trans = await getTrans();
      await call('transDeleteWithReturningSync006', async () => {
        let results = trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
        checkResult(results);
        await trans.commit();
      });
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning007
     * @tc.desc 1. columns.size == 0, errCode 14800001.
     */
    it('deleteWithReturning007', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = { columns: [] };
      await callAndCodeCheck("14800001", "deleteWithReturning007", async () => {
        await rdbStore?.deleteWithReturning(predicates, config);
      });
      await callAndCodeCheck("14800001", "deleteWithReturningSync007", async () => {
        rdbStore?.deleteWithReturningSync(predicates, config);
      });
      let trans = await getTrans();
      await callAndCodeCheck("14800001", "transDeleteWithReturning007", async () => {
        await trans?.deleteWithReturning(predicates, config);
      });
      await callAndCodeCheck("14800001", "transDeleteWithReturningSync007", async () => {
        trans?.deleteWithReturningSync(predicates, config);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning008
     * @tc.desc 1. columns.size > 4, errCode 14800001.
     */
    it('deleteWithReturning008', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = { columns: ['name', 'age', 'salary', 'data', 'blobType'] };
      await callAndCodeCheck("14800001", "deleteWithReturning008", async () => {
        await rdbStore?.deleteWithReturning(predicates, config);
      });
      await callAndCodeCheck("14800001", "deleteWithReturningSync008", async () => {
        rdbStore?.deleteWithReturningSync(predicates, config);
      });
      let trans = await getTrans();
      await callAndCodeCheck("14800001", "transDeleteWithReturning008", async () => {
        await trans?.deleteWithReturning(predicates, config);
      });
      await callAndCodeCheck("14800001", "transDeleteWithReturningSync008", async () => {
        trans?.deleteWithReturningSync(predicates, config);
      });
      await trans.rollback();
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning009
     * @tc.desc 1. columns contain special characters: "*"," ",",".
     */
    it('deleteWithReturning009', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      let columnsCase = [['ab*'], ["a b"], ["a,b"] ];
      for (let i = 0; i < columnsCase.length; ++i) {
        const config: relationalStore.ReturningConfig = { columns: columnsCase[i] };
        await callAndCodeCheck('14800001', "deleteWithReturning009-" + i, async () => {
          await rdbStore?.deleteWithReturning(predicates, config);
        });
        await callAndCodeCheck('14800001', "deleteWithReturningSync009-" + i, async () => {
          rdbStore?.deleteWithReturningSync(predicates, config);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('14800001', "transDeleteWithReturning009-" + i, async () => {
          await trans?.deleteWithReturning(predicates, config);
        });
        await callAndCodeCheck('14800001', "transDeleteWithReturningSync009-" + i, async () => {
          trans?.deleteWithReturningSync(predicates, config);
        });
        await trans?.rollback();
      }
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning010
     * @tc.desc 1. Violation of constraint foreign key.
     */
    it('deleteWithReturning010', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test1");
      predicates.equalTo('test_id', 1);
      const config: relationalStore.ReturningConfig = { columns: ['test_name'] };
      await rdbStore?.execute(FOREIGN_KEYS_ON);
      await callAndCodeCheck(14800032, "deleteWithReturning010", async () => {
        await rdbStore?.deleteWithReturning(predicates, config);
      });
      await callAndCodeCheck(14800032, "deleteWithReturningSync010", async () => {
        rdbStore?.deleteWithReturningSync(predicates, config);
      });
      await rdbStore?.execute(FOREIGN_KEYS_OFF);
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning011
     * @tc.desc 1. Normal parameters, rdb already close.
     */
    it('deleteWithReturning011', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      await rdbStore?.close();
      await callAndCodeCheck("14800014", "deleteWithReturning011", async () => {
        await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck("14800014", "deleteWithReturningSync011", async () => {
        rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      let trans = await getTrans();
      await trans.rollback();
      await callAndCodeCheck(14800014, "transDeleteWithReturning011", async () => {
        await trans?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800014, "transDeleteWithReturningSync011", async () => {
        trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning012
     * @tc.desc 1. Abnormal parameters, rdb already close.
     */
    it('deleteWithReturning012', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = { columns: ['name?', 'age'] };
      await rdbStore?.close();
      await callAndCodeCheck("14800014", "deleteWithReturning012", async () => {
        await rdbStore?.deleteWithReturning(predicates, config);
      });
      await callAndCodeCheck("14800014", "deleteWithReturningSync012", async () => {
        rdbStore?.deleteWithReturningSync(predicates, config);
      });
      let trans = await getTrans();
      await trans.rollback();
      await callAndCodeCheck(14800014, "transDeleteWithReturning012", async () => {
        await trans?.deleteWithReturning(predicates, config);
      });
      await callAndCodeCheck(14800014, "transDeleteWithReturningSync012", async () => {
        trans?.deleteWithReturningSync(predicates, config);
      });
      done();
    })
    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning013
     * @tc.desc 1. Database corruption.
     */
    it('deleteWithReturning013', 0, async (done: Function) => {
      await createCorruptDb(context, STORE_CONFIG);
      let predicates = new relationalStore.RdbPredicates("test");
      await callAndCodeCheck(14800011, "deleteWithReturning013", async () => {
        await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800011, "deleteWithReturningSync013", async () => {
        rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      let trans = await getTrans();
      await createCorruptDb(context, STORE_CONFIG);
      await callAndCodeCheck(14800011, "transDeleteWithReturning013", async () => {
        await trans?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800011, "transDeleteWithReturningSync013", async () => {
        trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning014
     * @tc.desc 1. The database file is locked.
     */
    it('deleteWithReturning014', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      let deferredTrans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      let trans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      const defaultVb: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      await deferredTrans?.insert('test', defaultVb);
      await callAndCodeCheck(14800024, "deleteWithReturning014", async () => {
        await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800024, "deleteWithReturningSync014", async () => {
        rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800024, "transDeleteWithReturning014", async () => {
        await trans?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800024, "transDeleteWithReturningSync014", async () => {
        trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      await deferredTrans?.rollback();
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning015
     * @tc.desc 1. illegal table name
     */
    it('deleteWithReturning015', 0, async (done: Function) => {
      let illegalTableNames:Array<string> = ["123test", "te.s.t", ".test", "test.."];
      for (let i = 0; i < illegalTableNames.length; ++i) {
        let predicates = new relationalStore.RdbPredicates(illegalTableNames[i]);
        await callAndCodeCheck('14800001', "deleteWithReturning015-" + i, async () => {
          await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
        });
        await callAndCodeCheck('14800001', "deleteWithReturningSync015-" + i, async () => {
          rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('14800001', "transDeleteWithReturning015-" + i, async () => {
          await trans?.deleteWithReturning(predicates, defaultReturningConfig);
        });
        await callAndCodeCheck('14800001', "transDeleteWithReturningSync015-" + i, async () => {
          trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
        });
        await trans?.rollback();
      }
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning016
     * @tc.desc 1. maxReturningCount <= 0 || maxReturningCount > 0x7ffe.
     */
    it('deleteWithReturning016', 0, async (done: Function) => {
      const MAX_RETURNING_COUNT = 0x7fff; // 32767
      let predicates = new relationalStore.RdbPredicates("test");
      let maxReturningCounts:Array<number> = [-2, 0, MAX_RETURNING_COUNT];
      for (let i = 0; i < maxReturningCounts.length; ++i) {
        const config: relationalStore.ReturningConfig = {
          columns: ['name', 'age'],
          maxReturningCount: maxReturningCounts[i]
        };
        await callAndCodeCheck('14800001', "deleteWithReturning016-" + i, async () => {
          await rdbStore?.deleteWithReturning(predicates, config);
        });
        await callAndCodeCheck('14800001', "deleteWithReturningSync016-" + i, async () => {
          rdbStore?.deleteWithReturningSync(predicates, config);
        });
        let trans = await rdbStore?.createTransaction(options);
        await callAndCodeCheck('14800001', "transDeleteWithReturning016-" + i, async () => {
          await trans?.deleteWithReturning(predicates, config);
        });
        await callAndCodeCheck('14800001', "transDeleteWithReturningSync016-" + i, async () => {
          trans?.deleteWithReturningSync(predicates, config);
        });
        await trans?.rollback();
      }
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning017
     * @tc.desc 1. valueBuckets.size < maxReturningCount < 0x7FFF.
     */
    it('deleteWithReturning017', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning019 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.between('id', 1, 2);
      const config: relationalStore.ReturningConfig = { columns: ['name'], maxReturningCount: 5 };
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(2);
        expect(getRowCount(results?.resultSet)).assertEqual(2);
      };
      await call("deleteWithReturning017", async () => {
        let results = await rdbStore?.deleteWithReturning(predicates, config);
        await checkResult(results);
      });
      await resetRdbStore();
      await call("deleteWithReturningSync017", async () => {
        let results = rdbStore?.deleteWithReturningSync(predicates, config);
        await checkResult(results);
      });
      let trans = await getTrans();
      await call("transDeleteWithReturning017", async () => {
        let results = await trans?.deleteWithReturning(predicates, config);
        await checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transDeleteWithReturningSync017", async () => {
        let results = trans?.deleteWithReturningSync(predicates, config);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning018
     * @tc.desc 1. maxReturningCount < valueBuckets.size < 0x7FFF.
     */
    it('deleteWithReturning018', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.between('id', 1, 10);
      const config: relationalStore.ReturningConfig = { columns: ['name'], maxReturningCount: 5 };
      let checkResult = async (results:relationalStore.Result|undefined) => {
        expect(results?.changed).assertEqual(10);
        expect(getRowCount(results?.resultSet)).assertEqual(5);
      };
      await call("deleteWithReturning018", async () => {
        let results = await rdbStore?.deleteWithReturning(predicates, config);
        await checkResult(results);
      });
      await resetRdbStore();
      await call("deleteWithReturningSync018", async () => {
        let results = rdbStore?.deleteWithReturningSync(predicates, config);
        await checkResult(results);
      });
      let trans = await getTrans();
      await call("transDeleteWithReturning018", async () => {
        let results = await trans?.deleteWithReturning(predicates, config);
        await checkResult(results);
        await trans?.commit();
      });
      trans = await getTrans();
      await call("transDeleteWithReturningSync018", async () => {
        let results = trans?.deleteWithReturningSync(predicates, config);
        await checkResult(results);
        await trans?.commit();
      });
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning019
     * @tc.desc 1. Pass special characters to field names.
     */
    it('deleteWithReturning019', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = { columns: ['name?']};
      await callAndCodeCheck(14800021, "deleteWithReturning019", async () => {
        await rdbStore?.deleteWithReturning(predicates, config);
      });
      await callAndCodeCheck(14800021, "deleteWithReturningSync019", async () => {
        rdbStore?.deleteWithReturningSync(predicates, config);
      });
      let trans = await rdbStore?.createTransaction(options);
      await callAndCodeCheck(14800021, "transDeleteWithReturning019", async () => {
        await trans?.deleteWithReturning(predicates, config);
      });
      await callAndCodeCheck(14800021, "transDeleteWithReturningSync019", async () => {
        trans?.deleteWithReturningSync(predicates, config);
      });
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning020
     * @tc.desc 1. A table in the database is locked.
     */
    it('deleteWithReturning020', 0, async (done: Function) => {
      let predicates = new relationalStore.RdbPredicates("test");
      const defaultVb: relationalStore.ValuesBucket = { 'name': 'zhangsan' };
      const STORE_CONFIG1: relationalStore.StoreConfig = {
        name: dbName,
        securityLevel: relationalStore.SecurityLevel.S1,
        persist: false,
      };
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      await rdbStore?.execute(CREATE_TABLE_TEST);
      let deferredTrans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      let trans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      await deferredTrans?.insert("test", defaultVb);
      await callAndCodeCheck(14800025, "deleteWithReturning020", async () => {
        await rdbStore?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800025, "deleteWithReturningSync020", async () => {
        rdbStore?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800025, "transDeleteWithReturning020", async () => {
        await trans?.deleteWithReturning(predicates, defaultReturningConfig);
      });
      await callAndCodeCheck(14800025, "transDeleteWithReturningSync020", async () => {
        trans?.deleteWithReturningSync(predicates, defaultReturningConfig);
      });
      await deferredTrans?.rollback();
      await trans?.rollback();
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning021
     * @tc.desc 1.args is null or undefined test.
     */
    it('deleteWithReturning021', 0, async (done: Function) => {
      let defaultPredicate = new relationalStore.RdbPredicates("test");
      let predicates = [defaultPredicate, defaultPredicate, null, undefined];
      let configs = [null, undefined, defaultReturningConfig, defaultReturningConfig];
      for (let i = 0; i < predicates.length; ++i) {
        let code = await callAndReturnCode("deleteWithReturning021-" + i, async () => {
          await rdbStore?.deleteWithReturning(predicates[i], configs[i]);
        });
        expect(code).assertEqual('401');
        code = await callAndReturnCode("deleteWithReturningSync021-" + i, async () => {
          rdbStore?.deleteWithReturningSync(predicates[i], configs[i]);
        });
        expect(code).assertEqual('401');
        let trans = await rdbStore?.createTransaction(options);
        code = await callAndReturnCode("transDeleteWithReturning021-" + i, async () => {
          await trans?.deleteWithReturning(predicates[i], configs[i]);
        });
        expect(code).assertEqual('401');
        code = await callAndReturnCode("transDeleteWithReturningSync021-" + i, async () => {
          trans?.deleteWithReturningSync(predicates[i], configs[i]);
        });
        expect(code).assertEqual('401');
        await trans?.rollback();
      }
      done();
    })
  })
}