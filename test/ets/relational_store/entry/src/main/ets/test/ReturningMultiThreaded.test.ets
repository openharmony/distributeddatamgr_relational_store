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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, Level, Size, TestType } from "@ohos/hypium";
import relationalStore from '@ohos.data.relationalStore';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import { BusinessError } from '@ohos.base';
const TAG = "[RDB_STORE_RETURNING_MULTI_THREAD_TEST]";
let rdbStore: relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "data ASSET, " + "data1 ASSETS," + "blobType BLOB," +
  "test_id INTEGER," + "FOREIGN KEY (test_id) REFERENCES test1(test_id)" + ");"

const dbName = "DeleteRdbStore.db";
const STORE_CONFIG: relationalStore.StoreConfig = {
  name: dbName,
  securityLevel: relationalStore.SecurityLevel.S1,
}

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();
async function initData()
{
  let valueBuckets = new Array<relationalStore.ValuesBucket>();
  for (let i = 0; i < 200; ++i) {
    const valueBucket: relationalStore.ValuesBucket = {
      'name': 'zhangsan' + i,
    };
    valueBuckets.push(valueBucket);
  }
  await rdbStore?.batchInsert("test", valueBuckets);
}

function getRowCount(resultSet:relationalStore.LiteResultSet|undefined):number {
  let count = 0;
  while(resultSet?.goToNextRow()) {
    count++;
  }
  return count;
}

export default function ReturningMultiThreaded() {
  describe('returningMultiThreaded.test.ets', () => {
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
     * @tc.number batchInsertWithReturning
     * @tc.desc batchInsertWithReturning Multi threaded testing.
     */
    it('rdbBatchInsertWithReturningMultiThread', 0, async (done: Function) => {
      console.log(TAG + "************* rdbBatchInsertWithReturningMultiThread start *************");
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      let count:number = 200;
      for (let i = 0; i < 200; ++i) {
        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'zhangsan' + i,
        };
        rdbStore?.batchInsertWithReturning("test", [valueBucket], config)
          .then((result:relationalStore.Result)=>{
            expect(result.changed).assertEqual(1);
            expect(getRowCount(result.resultSet)).assertEqual(1);
            count--;
            if (count == 0) {
              done();
            }
          }).catch((e:BusinessError)=>{
          console.error(TAG + " rdbBatchInsertWithReturningMultiThread failed: " + e);
          done();
          expect(true).assertFail();
        });
      }
      console.log(TAG + "************* rdbBatchInsertWithReturningMultiThread end *************");
    })

    /**
     * @tc.name batchInsertWithReturning test.
     * @tc.number batchInsertWithReturning
     * @tc.desc trans batchInsertWithReturning Multi threaded testing.
     */
    it('transBatchInsertWithReturningMultiThread', 0, async (done: Function) => {
      console.log(TAG + "************* transBatchInsertWithReturningMultiThread start *************");
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      let count:number = 200;
      let trans = await rdbStore?.createTransaction();
      for (let i = 0; i < 200; ++i) {
        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'zhangsan' + i,
        };
        trans?.batchInsertWithReturning("test", [valueBucket], config)
          .then((result:relationalStore.Result)=>{
            expect(result.changed).assertEqual(1);
            expect(getRowCount(result?.resultSet)).assertEqual(1);
            count--;
            if (count == 0) {
              done();
            }
          }).catch((e:BusinessError)=>{
            console.error(TAG + " transBatchInsertWithReturningMultiThread failed: " + e);
            done();
            expect(true).assertFail();
        });
      }
      console.log(TAG + "************* transBatchInsertWithReturningMultiThread end *************");
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning
     * @tc.desc rdb deleteWithReturning Multi threaded testing.
     */
    it('rdbStoreDeleteWithReturningMultiThread', 0, async (done: Function) => {
      console.log(TAG + "************* rdbStoreDeleteWithReturningMultiThread start *************");
      await initData();
      let count:number = 200;
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      for (let i = 0; i < 200; ++i) {
        let predicates = new relationalStore.RdbPredicates("test");
        predicates.equalTo("name", 'zhangsan' + i);
        rdbStore?.deleteWithReturning(predicates, config)
          .then((result:relationalStore.Result)=>{
            expect(result.changed).assertEqual(1);
            expect(getRowCount(result?.resultSet)).assertEqual(1);
            count--;
            if (count == 0) {
              done();
            }
          }).catch((e:BusinessError)=>{
          console.error(TAG + " rdbStoreDeleteWithReturningMultiThread failed: " + e);
          done();
          expect(true).assertFail();
        });
      }
      console.log(TAG + "************* rdbStoreDeleteWithReturningMultiThread end *************");
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning
     * @tc.desc trans deleteWithReturning Multi threaded testing.
     */
    it('transStoreDeleteWithReturningMultiThread', 0, async (done: Function) => {
      console.log(TAG + "************* transStoreDeleteWithReturningMultiThread start *************");
      await initData();
      let count:number = 200;
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      let trans = await rdbStore?.createTransaction();
      for (let i = 0; i < 200; ++i) {
        let predicates = new relationalStore.RdbPredicates("test");
        predicates.equalTo("name", 'zhangsan' + i);
        trans?.deleteWithReturning(predicates, config)
          .then((result:relationalStore.Result)=>{
            expect(result.changed).assertEqual(1);
            expect(getRowCount(result?.resultSet)).assertEqual(1);
            count--;
            if (count == 0) {
              done();
            }
          }).catch((e:BusinessError)=>{
          console.error(TAG + " transStoreDeleteWithReturningMultiThread failed: " + e);
          done();
          expect(true).assertFail();
        });
      }
      console.log(TAG + "************* transStoreDeleteWithReturningMultiThread end *************");
    })

    /**
     * @tc.name uptateWithReturning test.
     * @tc.number uptateWithReturning
     * @tc.desc rdb deleteWithReturning Multi threaded testing.
     */
    it('rdbStoreUpdateWithReturningMultiThread', 0, async (done: Function) => {
      console.log(TAG + "************* rdbStoreUpdateWithReturningMultiThread start *************");
      await initData();
      let count:number = 200;
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'lisi',
      };
      for (let i = 0; i < 200; ++i) {
        let predicates = new relationalStore.RdbPredicates("test");
        predicates.equalTo("name", 'zhangsan' + i);
        rdbStore?.updateWithReturning(valueBucket, predicates, config)
          .then((result:relationalStore.Result)=>{
            expect(result.changed).assertEqual(1);
            result.resultSet.goToNextRow();
            expect(result.resultSet.getRow().name).assertEqual("lisi");
            expect(result.resultSet.goToNextRow()).assertFalse();
            count--;
            if (count == 0) {
              done();
            }
          }).catch((e:BusinessError)=>{
          console.error(TAG + " rdbStoreUpdateWithReturningMultiThread failed: " + e);
          done();
          expect(true).assertFail();
        });
      }
      console.log(TAG + "************* rdbStoreUpdateWithReturningMultiThread end *************");
    })

    /**
     * @tc.name uptateWithReturning test.
     * @tc.number uptateWithReturning
     * @tc.desc trans deleteWithReturning Multi threaded testing.
     */
    it('transStoreUpdateWithReturningMultiThread', 0, async (done: Function) => {
      console.log(TAG + "************* transStoreUpdateWithReturningMultiThread start *************");
      await initData();
      let count:number = 200;
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'lisi',
      };
      let trans = await rdbStore?.createTransaction();
      for (let i = 0; i < 200; ++i) {
        let predicates = new relationalStore.RdbPredicates("test");
        predicates.equalTo("name", 'zhangsan' + i);
        trans?.updateWithReturning(valueBucket, predicates, config)
          .then((result:relationalStore.Result)=>{
            expect(result.changed).assertEqual(1);
            result.resultSet.goToNextRow();
            expect(result.resultSet.getRow().name).assertEqual("lisi");
            expect(result.resultSet.goToNextRow()).assertFalse();
            count--;
            if (count == 0) {
              done();
            }
          }).catch((e:BusinessError)=>{
          console.error(TAG + " transStoreUpdateWithReturningMultiThread failed: " + e);
          done();
          expect(true).assertFail();
        });
      }
      console.log(TAG + "************* transStoreUpdateWithReturningMultiThread end *************");
    })
  })
}