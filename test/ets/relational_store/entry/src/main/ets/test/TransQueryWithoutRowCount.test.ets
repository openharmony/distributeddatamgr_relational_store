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
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import { relationalStore } from '@ohos.data.relationalStore';

const TAG = "[RELATIONAL_STORE_TEST]";
let rdbStore:relationalStore.RdbStore | undefined = undefined;
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "data1 text," + "data2 long, " + "data3 real," + "data4 blob)";

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "transQuery.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

async function checkResultSetForNormalGet(resultSet : relationalStore.LiteResultSet){

  try {
    resultSet?.goToNextRow();
    let index = resultSet.getColumnIndex("id");
    expect(index).assertEqual(0);
    let id = resultSet.getLong(index);
    expect(id).assertEqual(1);
    index = resultSet.getColumnIndex("data1");
    let data1 = resultSet.getString(index);
    expect(data1).assertEqual('zhangsan');
    index = resultSet.getColumnIndex("data2");
    let data2 = resultSet.getLong(index);
    expect(data2).assertEqual(18);
    index = resultSet.getColumnIndex("data3");
    let data3 = resultSet.getDouble(index);
    expect(data3).assertEqual(25000.0);
    index = resultSet.getColumnIndex("data4");
    let data4 = resultSet.getBlob(index);
    expect(data4[0]).assertEqual(1);
    expect(data4[1]).assertEqual(2);
    expect(data4[2]).assertEqual(3);

    resultSet.goToNextRow();
    index = resultSet.getColumnIndex("id");
    expect(index).assertEqual(0);
    id = resultSet?.getLong(index);
    expect(id).assertEqual(2);
    index = resultSet.getColumnIndex("data1");
    data1 = resultSet?.getString(index);
    expect(data1).assertEqual('lisi');
    index = resultSet.getColumnIndex("data2");
    data2 = resultSet?.getLong(index);
    expect(data2).assertEqual(20);
    index = resultSet.getColumnIndex("data3");
    data3 = resultSet?.getDouble(index);
    expect(data3).assertEqual(20000.0);
    index = resultSet.getColumnIndex("data4");
    data4 = resultSet?.getBlob(index);
    expect(data4[0]).assertEqual(1);
    expect(data4[1]).assertEqual(2);
    expect(data4[2]).assertEqual(3);
    resultSet?.close();
  } catch(e) {
    console.error(`checkResultSetForNormalGet failed message:${e.message} code:${e.code}`);
    expect().assertFail();
  }
}

export default function transQueryWithoutRowCount() {
  describe('transQueryWithoutRowCount', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
      try {
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        expect(rdbStore != undefined).assertTrue();
        await rdbStore?.executeSql(CREATE_TABLE_TEST);
        let u8 = new Uint8Array([1, 2, 3])
        const valueBucket: relationalStore.ValuesBucket = {
          'data1': 'zhangsan',
          'data2': 18,
          'data3': 25000.0,
          'data4': u8,
        };
        const valueBucket1: relationalStore.ValuesBucket = {
          'data1': 'lisi',
          'data2': 20,
          'data3': 20000.0,
          'data4': u8,
        };
        await rdbStore?.insert('test', valueBucket);
        await rdbStore?.insert('test', valueBucket1);
      } catch(error) {
        console.error(TAG + 'beforeEach failed');
        expect().assertFail();
      }
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
    })
    afterEach(async () => {
      console.info(TAG + 'afterEach');
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
      try {
        rdbStore?.close();
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch(error) {
        console.error(TAG + 'afterAll failed');
        expect().assertFail();
      }
    })

    /**
     * @tc.number queryWithoutRowCount_001_normal_columns
     * @tc.name Normal test case of queryWithoutRowCount
     * @tc.desc 1.The optional parameters columns are not transferred.
     *          2.Set columns to ["data1"].
     */
    it('queryWithoutRowCount_001_normal_columns',  0, async  () => {
      console.log(TAG + "************* queryWithoutRowCount_001_normal_columns start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
        await rdbTrans?.commit();
      } catch(e) {
        console.error(`queryWithoutRowCount_001_normal_columns failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect().assertFail();
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates, ["data1"]);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(resultSet.getColumnIndex("data1"));
        expect(data1).assertEqual('zhangsan');
        resultSet?.close();
        await rdbTrans?.commit();
      } catch(e) {
        console.error(`queryWithoutRowCount_001_normal_columns failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect().assertFail();
      }
      console.log(TAG + "************* queryWithoutRowCount_001_normal_columns end *************");
    })

    /**
     * @tc.number queryWithoutRowCount_002_normal_columns
     * @tc.name Normal test case of queryWithoutRowCount
     * @tc.desc 1.Set columns to null
     *          2.Set columns to undefined
     */
    it('queryWithoutRowCount_002_normal_columns',  0, async  () => {
      console.log(TAG + "************* queryWithoutRowCount_002_normal_columns start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates, null);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet)
        }
        await rdbTrans?.commit();
      } catch(e) {
        console.error(`queryWithoutRowCount_002_normal_columns failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect().assertFail();
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates, undefined);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet)
        }
        await rdbTrans?.commit();
      } catch(e) {
        console.error(`queryWithoutRowCount_002_normal_columns failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect().assertFail();
      }
      console.log(TAG + "************* queryWithoutRowCount_002_normal_columns end *************");
    })

    /**
     * @tc.number queryWithoutRowCount_003_Abnormal_columns
     * @tc.name Abnormal test case of queryWithoutRowCount
     * @tc.desc 1.Set columns to [null]
     *          2.Set columns to [undefined]
     */
    it('queryWithoutRowCount_003_Abnormal_columns',  0, async  () => {
      console.log(TAG + "************* queryWithoutRowCount_003_Abnormal_columns start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates, [null]);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_003_Abnormal_columns failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 401).assertTrue();
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates, [undefined]);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_003_Abnormal_columns failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 401).assertTrue();
      }
      console.log(TAG + "************* queryWithoutRowCount_003_Abnormal_columns end *************");
    })

    /**
     * @tc.number queryWithoutRowCount_004_Abnormal_columns
     * @tc.name Normal test case of queryWithoutRowCount
     * @tc.desc 1.Set columns to [].
     *          2.Set columns to [""].
     *          3.Set columns to ["", "data1"].
     */
    it('queryWithoutRowCount_004_Abnormal_columns',  0, async  () => {
      console.log(TAG + "************* queryWithoutRowCount_004_Abnormal_columns start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates, []);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
        await rdbTrans?.commit();
      } catch(e) {
        console.error(`queryWithoutRowCount_004_Abnormal_columns failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect().assertFail();
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates, [""]);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(0);
      } catch(e) {
        console.error(`queryWithoutRowCount_004_Abnormal_columns failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect(e.code == 14800021).assertTrue();
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates, ["", "data1"]);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(resultSet.getColumnIndex("data1"));
        expect(data1).assertEqual('zhangsan');
        resultSet?.close();
        await rdbTrans?.commit();
      } catch(e) {
        console.error(`queryWithoutRowCount_004_Abnormal_columns failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect().assertFail();
      }
      console.log(TAG + "************* queryWithoutRowCount_004_Abnormal_columns end *************");
    })

    /**
     * @tc.number queryWithoutRowCount_005_abnormal_predicates
     * @tc.name Abnormal test case of queryWithoutRowCount
     * @tc.desc 1.Set RdbPredicates to [null]
     *          2.Set RdbPredicates to [undefined]
     */
    it('queryWithoutRowCount_005_abnormal_predicates',  0, async  () => {
      console.log(TAG + "************* queryWithoutRowCount_005_abnormal_predicates start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_005_abnormal_predicates failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 401).assertTrue();
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.queryWithoutRowCount(null);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_005_abnormal_predicates failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 401).assertTrue();
      }
      console.log(TAG + "************* queryWithoutRowCount_005_abnormal_predicates end *************");
    })

    /**
     * @tc.number queryWithoutRowCount_006_abnormal_rdbStoreIsClose
     * @tc.name Abnormal test case of queryWithoutRowCount
     * @tc.desc Query when the store is closed
     */
    it('queryWithoutRowCount_006_abnormal_rdbStoreIsClose',  0, async  () => {
      console.log(TAG + "************* queryWithoutRowCount_006_abnormal_rdbStoreIsClose start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      try {
        await rdbStore?.close();
        let predicates = new relationalStore.RdbPredicates('test');
        resultSet = await rdbTrans?.queryWithoutRowCount(predicates);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_006_abnormal_rdbStoreIsClose failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        expect(e.code == 14800014).assertTrue();
      }
      console.log(TAG + "************* queryWithoutRowCount_006_abnormal_rdbStoreIsClose end *************");
    })

    /**
     * @tc.number querySqlWithoutRowCount_001_normal_bindArgs
     * @tc.name Normal test case of querySqlWithoutRowCount
     * @tc.desc 1.The optional parameters bindArgs are not transferred.
     *          2.Set bindArgs to [""], sql is select * from test where data2 = 20
     *          3.Set bindArgs to [18], sql is select * from test where data2 = ?
     */
    it('querySqlWithoutRowCount_001_normal_bindArgs',  0, async  () => {
      console.log(TAG + "************* querySqlWithoutRowCount_0001 start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      const sql = "select * from test";
      try {
        resultSet = await rdbTrans?.querySqlWithoutRowCount(sql);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
        resultSet?.close();
        await rdbTrans?.commit();
      } catch(e) {
        console.error(`querySqlWithoutRowCount failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect().assertFail();
      }

      rdbTrans = await rdbStore?.createTransaction();
      const sql1 = "select * from test where data2 = 20";
      try {
        resultSet = await rdbTrans?.querySqlWithoutRowCount(sql1, []);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(resultSet?.getColumnIndex("data1"));
        expect("lisi").assertEqual(data1);
        resultSet?.close();
        await rdbTrans?.commit();
      } catch(e) {
        console.error(`querySqlWithoutRowCount failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect().assertFail();
      }

      rdbTrans = await rdbStore?.createTransaction();
      const sql2 = "select * from test where data2 = ?";
      try {
        resultSet = await rdbTrans?.querySqlWithoutRowCount(sql2, [18]);
        resultSet?.goToNextRow();
        let data2 = resultSet?.getLong(resultSet.getColumnIndex("data2"));
        expect(18).assertEqual(data2);
        resultSet?.close();
        await rdbTrans?.commit();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_0001 failed message:${e.message} code:${e.code}`);
        await rdbTrans?.rollback();
        expect().assertFail();
      }
      console.log(TAG + "************* querySqlWithoutRowCount_0001 end *************");
    })

    /**
     * @tc.number querySqlWithoutRowCount_002_Abnormal_bindArgs
     * @tc.name Normal test case of querySqlWithoutRowCount
     * @tc.desc 1.sql is select * from test where data2 = ?
     *          2.Set bindArgs to [null]
     *          3.Set bindArgs to [undefined]
     */
    it('querySqlWithoutRowCount_002_Abnormal_bindArgs',  0, async  () => {
      console.log(TAG + "************* querySqlWithoutRowCount_002_Abnormal_bindArgs start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      const valueBucket: relationalStore.ValuesBucket = {
        'data1': "wangwu",
        'data2': null,
      };
      await rdbStore?.insert('test', valueBucket);

      const sql = "select * from test where data2 = ?";
      try {
        resultSet = await rdbTrans?.querySqlWithoutRowCount(sql, [null]);
        resultSet?.goToNextRow();
        let data2 = resultSet?.getLong(resultSet.getColumnIndex("data2"));
        expect().assertFail();
      } catch (e) {
        console.error(`querySqlWithoutRowCount_002 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 14800012).assertTrue();
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.querySqlWithoutRowCount(sql, [undefined]);
        expect().assertFail();
      } catch (e) {
        console.error(`querySqlWithoutRowCount_002 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 401).assertTrue();
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.querySqlWithoutRowCount(sql, []);
        resultSet?.goToNextRow();
        let data2 = resultSet?.getLong(resultSet.getColumnIndex("data2"));
        expect().assertFail();
      } catch (e) {
        console.error(`querySqlWithoutRowCount_002 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 14800012).assertTrue();
      }

      console.log(TAG + "************* querySqlWithoutRowCount_002_Abnormal_bindArgs end *************");
    })

    /**
     * @tc.number querySqlWithoutRowCount_003_Abnormal_sql
     * @tc.name Normal test case of querySqlWithoutRowCount
     * @tc.desc 1.sql is undefined
     *          2.sql is null
     *          3.sql is ""
     */
    it('querySqlWithoutRowCount_003_Abnormal_sql',  0, async  () => {
      console.log(TAG + "************* querySqlWithoutRowCount_003_Abnormal_sql start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      try {
        resultSet = await rdbTrans?.querySqlWithoutRowCount(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_003 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 401).assertTrue()
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.querySqlWithoutRowCount(null);
        expect().assertFail();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_003 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 401).assertTrue()
      }

      rdbTrans = await rdbStore?.createTransaction();
      try {
        resultSet = await rdbTrans?.querySqlWithoutRowCount("");
        expect().assertFail();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_003 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        await rdbTrans?.rollback();
        expect(e.code == 14800001).assertTrue()
      }
      console.log(TAG + "************* querySqlWithoutRowCount_003_Abnormal_sql end *************");
    })

    /**
     * @tc.number querySqlWithoutRowCount_004_abnormal_rdbStoreIsClose
     * @tc.name Abnormal test case of querySqlWithoutRowCount
     * @tc.desc Query when the store is closed
     */
    it('querySqlWithoutRowCount_004_abnormal_rdbStoreIsClose',  0, async  () => {
      console.log(TAG + "************* querySqlWithoutRowCount_004_abnormal_rdbStoreIsClose start *************");
      let rdbTrans = await rdbStore?.createTransaction();
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      const sql = "select * from test";
      try {
        await rdbStore?.close();
        resultSet = await rdbTrans?.querySqlWithoutRowCount(sql);
        expect().assertFail();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_004 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code == 14800014).assertTrue();
      }
      console.log(TAG + "************* querySqlWithoutRowCount_004_abnormal_rdbStoreIsClose end *************");
    })
  })
}