/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
import relationalStore from '@ohos.data.relationalStore';
import { BusinessError } from '@ohos.base';

const TAG = "[RELATIONAL_STORE_TEST]";
let rdbStore : relationalStore.RdbStore | undefined = undefined;
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "data1 text," + "data2 long, " + "data3 real," + "data4 blob)";

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "rdbQueryByStep.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}


function checkResultSetForNormalGet(resultSet : relationalStore.ResultSet){
  let count = 0;
  try {
    while(resultSet.goToNextRow()) {
      count++;
      if(count === 1) {
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
      }
      if(count === 2) {
        let index = resultSet.getColumnIndex("id");
        expect(index).assertEqual(0);
        let id = resultSet.getLong(index);
        expect(id).assertEqual(2);
        index = resultSet.getColumnIndex("data1");
        let data1 = resultSet.getString(index);
        expect(data1).assertEqual('lisi');
        index = resultSet.getColumnIndex("data2");
        let data2 = resultSet.getLong(index);
        expect(data2).assertEqual(20);
        index = resultSet.getColumnIndex("data3");
        let data3 = resultSet.getDouble(index);
        expect(data3).assertEqual(20000.0);
        index = resultSet.getColumnIndex("data4");
        let data4 = resultSet.getBlob(index);
        expect(data4[0]).assertEqual(1);
        expect(data4[1]).assertEqual(2);
        expect(data4[2]).assertEqual(3);
      }
      if(count === 3) {
        expect().assertFail();
      }
    }
  } catch(e) {
    const err = e as BusinessError;
    console.error(`checkResultSetForNormalGet failed message:${err.message} code:${err.code}`);
    expect().assertFail();
  }
}

export default function RdbQueryByStep() : void {
  describe('rdbQueryByStep', () => {
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
        await rdbStore?.close();
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch(error) {
        console.error(TAG + 'afterAll failed');
        expect().assertFail();
      }
    })

    /**
     * @tc.number queryByStep_001_normal_columns
     * @tc.name Normal test case of queryByStep
     * @tc.desc 1.The optional parameters columns are not transferred.
     *          2.Set columns to ["data1"].
     */
    it('queryByStep_001_normal_columns',  0, async  () => {
      console.log(TAG + "************* queryByStep_001_normal_columns start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.queryByStep(predicates);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_001_normal_columns failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep(predicates, ["data1"]);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(resultSet?.getColumnIndex("data1"));
        expect(data1).assertEqual('zhangsan');
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_001_normal_columns failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      } finally {
        resultSet?.close();
      }
      console.log(TAG + "************* queryByStep_001_normal_columns end *************");
    })

    /**
     * @tc.number queryByStep_002_normal_columns
     * @tc.name Normal test case of queryByStep
     * @tc.desc 1.Set columns to null
     *          2.Set columns to undefined
     */
    it('queryByStep_002_normal_columns',  0, async  () => {
      console.log(TAG + "************* queryByStep_002_normal_columns start *************");
      let resultSet : relationalStore.ResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.queryByStep(predicates, null);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_002_normal_columns failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep(predicates, undefined);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet)
        }
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_002_normal_columns failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      } finally {
        resultSet?.close();
      }
      console.log(TAG + "************* queryByStep_002_normal_columns end *************");
    })

    /**
     * @tc.number queryByStep_003_Abnormal_columns
     * @tc.name Abnormal test case of queryByStep
     * @tc.desc 1.Set columns to [null]
     *          2.Set columns to [undefined]
     */
    it('queryByStep_003_Abnormal_columns',  0, async  () => {
      console.log(TAG + "************* queryByStep_003_Abnormal_columns start *************");
      let resultSet : relationalStore.ResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.queryByStep(predicates, [null]);
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_003_Abnormal_columns failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("401");
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep(predicates, [undefined]);
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_003_Abnormal_columns failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("401");
      } finally {
        resultSet?.close();
      }
      console.log(TAG + "************* queryByStep_003_Abnormal_columns end *************");
    })

    /**
     * @tc.number queryByStep_004_Abnormal_columns
     * @tc.name Abnormal test case of queryByStep
     * @tc.desc 1.Set columns to [].
     *          2.Set columns to [""].
     *          3.Set columns to ["", "data1"].
     */
    it('queryByStep_004_Abnormal_columns',  0, async  () => {
      console.log(TAG + "************* queryByStep_004_Abnormal_columns start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.queryByStep(predicates, []);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_004_Abnormal_columns failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep(predicates, [""]);
        let res = resultSet?.goToNextRow();
        expect(res).assertFalse();
        // goToNextRow does not throw error codes, SQL statement error, so getString throws out of bounds line
        let data1 = resultSet?.getString(0);
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_004_Abnormal_columns failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("14800012");
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep(predicates, ["", "data1"]);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(resultSet?.getColumnIndex("data1"));
        expect(data1).assertEqual('zhangsan');
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_004_Abnormal_columns failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      } finally {
        resultSet?.close();
      }
      console.log(TAG + "************* queryByStep_004_Abnormal_columns end *************");
    })

    /**
     * @tc.number queryByStep_005_abnormal_predicates
     * @tc.name Abnormal test case of queryByStep
     * @tc.desc 1.Set RdbPredicates to [null]
     *          2.Set RdbPredicates to [undefined]
     */
    it('queryByStep_005_abnormal_predicates',  0, async  () => {
      console.log(TAG + "************* queryByStep_005_abnormal_predicates start *************");
      let resultSet : relationalStore.ResultSet | undefined = undefined;
      try {
        resultSet = await rdbStore?.queryByStep(undefined);
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_005_abnormal_predicates failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("401");
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep(null);
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_005_abnormal_predicates failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("401");
      } finally {
        resultSet?.close();
      }
      console.log(TAG + "************* queryByStep_005_abnormal_predicates end *************");
    })

    /**
     * @tc.number queryByStep_006_abnormal_rdbStoreIsClose
     * @tc.name Abnormal test case of queryByStep
     * @tc.desc Query when the store is closed
     */
    it('queryByStep_006_abnormal_rdbStoreIsClose',  0, async  () => {
      console.log(TAG + "************* queryByStep_006_abnormal_rdbStoreIsClose start *************");
      let resultSet : relationalStore.ResultSet | undefined = undefined;
      try {
        await rdbStore?.close();
        let predicates = new relationalStore.RdbPredicates('test');
        resultSet = await rdbStore?.queryByStep(predicates);
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_006_abnormal_rdbStoreIsClose failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("14800014");
      } finally {
        resultSet?.close();
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      }
      console.log(TAG + "************* queryByStep_006_abnormal_rdbStoreIsClose end *************");
    })

    /**
     * @tc.number queryByStep_001_normal_bindArgs
     * @tc.name Normal test case of queryByStep
     * @tc.desc 1.The optional parameters bindArgs are not transferred.
     *          2.Set bindArgs to [""], sql is select * from test where data2 = 20
     *          3.Set bindArgs to [18], sql is select * from test where data2 = ?
     */
    it('queryByStep_001_normal_bindArgs',  0, async  () => {
      console.log(TAG + "************* queryByStep_001_normal_bindArgs start *************");
      let resultSet : relationalStore.ResultSet | undefined = undefined;
      const sql = "select * from test";
      try {
        resultSet = await rdbStore?.queryByStep(sql);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_001_normal_bindArgs failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      } finally {
        resultSet?.close();
      }

      const sql1 = "select * from test where data2 = 20";
      try {
        resultSet = await rdbStore?.queryByStep(sql1, []);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(resultSet?.getColumnIndex("data1"));
        expect("lisi").assertEqual(data1);
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_001_normal_bindArgs failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      } finally {
        resultSet?.close();
      }

      const sql2 = "select * from test where data2 = ?";
      try {
        resultSet = await rdbStore?.queryByStep(sql2, [18]);
        resultSet?.goToNextRow();
        let data2 : number | undefined = resultSet?.getLong(resultSet?.getColumnIndex("data2"));
        expect(18).assertEqual(data2);
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_001_normal_bindArgs failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      } finally {
        resultSet?.close();
      }
      console.log(TAG + "************* queryByStep_001_normal_bindArgs end *************");
    })

    /**
     * @tc.number queryByStep_002_Abnormal_bindArgs
     * @tc.name Abnormal test case of queryByStep
     * @tc.desc 1.sql is select * from test where data2 = ?
     *          2.Set bindArgs to [null]
     *          3.Set bindArgs to [undefined]
     */
    it('queryByStep_002_Abnormal_bindArgs',  0, async  () => {
      console.log(TAG + "************* queryByStep_002_Abnormal_bindArgs start *************");
      let resultSet : relationalStore.ResultSet | undefined = undefined;
      const valueBucket: relationalStore.ValuesBucket = {
        'data1': "wangwu",
        'data2': null,
      };

      try {
        await rdbStore?.insert('test', valueBucket);
      } catch (e) {
        const err = e as BusinessError;
        console.error(`queryByStep_002_Abnormal_bindArgs insert failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }

      const sql = "select * from test where data2 = ?";
      try {
        resultSet = await rdbStore?.queryByStep(sql, [null]);
        let res = resultSet?.goToNextRow();
        expect(res).assertFalse();
        // goToNextRow does not throw error codes, SQL statement error, so getString throws out of bounds line
        let data2 : number | undefined = resultSet?.getLong(resultSet?.getColumnIndex("data2"));
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        console.error(`queryByStep_002_Abnormal_bindArgs failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("14800012");
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep(sql, [undefined]);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        console.error(`queryByStep_002_Abnormal_bindArgs failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("401");
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep(sql, []);
        let res = resultSet?.goToNextRow();
        expect(res).assertFalse();
        // goToNextRow does not throw error codes, SQL statement error, so getString throws out of bounds line
        let data2 : number | undefined = resultSet?.getLong(resultSet?.getColumnIndex("data2"));
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        console.error(`queryByStep_002_Abnormal_bindArgs failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("14800012");
      } finally {
        resultSet?.close();
      }

      try {
        let predicates = new relationalStore.RdbPredicates('test');
        predicates.equalTo('data1', 'wangwu');
        await rdbStore?.delete(predicates);
      } catch (e) {
        const err = e as BusinessError;
        console.error(`queryByStep_002_Abnormal_bindArgs delete failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }

      console.log(TAG + "************* queryByStep_002_Abnormal_bindArgs end *************");
    })

    /**
     * @tc.number queryByStep_003_Abnormal_sql
     * @tc.name Abnormal test case of queryByStep
     * @tc.desc 1.sql is undefined
     *          2.sql is null
     *          3.sql is ""
     */
    it('queryByStep_003_Abnormal_sql',  0, async  () => {
      console.log(TAG + "************* queryByStep_003_Abnormal_sql start *************");
      let resultSet : relationalStore.ResultSet | undefined = undefined;
      try {
        resultSet = await rdbStore?.queryByStep(undefined);
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_003_Abnormal_sql failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("401");
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep(null);
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_003_Abnormal_sql failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("401");
      } finally {
        resultSet?.close();
      }

      try {
        resultSet = await rdbStore?.queryByStep("");
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_003_Abnormal_sql failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("401");
      } finally {
        resultSet?.close();
      }
      console.log(TAG + "************* queryByStep_003_Abnormal_sql end *************");
    })

    /**
     * @tc.number queryByStep_004_abnormal_rdbStoreIsClose
     * @tc.name Abnormal test case of queryByStep
     * @tc.desc Query when the store is closed
     */
    it('queryByStep_004_abnormal_rdbStoreIsClose',  0, async  () => {
      console.log(TAG + "************* queryByStep_004_abnormal_rdbStoreIsClose start *************");
      let resultSet : relationalStore.ResultSet | undefined = undefined;
      const sql = "select * from test";
      try {
        await rdbStore?.close();
        resultSet = await rdbStore?.queryByStep(sql);
        expect().assertFail();
      } catch(e) {
        const err = e as BusinessError;
        console.error(`queryByStep_004_abnormal_rdbStoreIsClose failed message:${err.message} code:${err.code}`);
        expect(e.code).assertEqual("14800014");
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      } finally {
        resultSet?.close();
      }
      console.log(TAG + "************* queryByStep_004_abnormal_rdbStoreIsClose end *************");
    })
  })
}