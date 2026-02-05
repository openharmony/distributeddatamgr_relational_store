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
import relationalStore from '@ohos.data.relationalStore';

const TAG = "[RELATIONAL_STORE_TEST]";
let rdbStore:relationalStore.RdbStore | undefined = undefined;
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "data1 text," + "data2 long, " + "data3 real," + "data4 blob)";

const CREATE_ASSERT_TABLE_TEST = "CREATE TABLE IF NOT EXISTS asset_table (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "data1 asset," + "data2 assets)";

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "rdbQuery.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

const asset1 : relationalStore.Asset = {
  name: "name1",
  uri: "uri1",
  createTime: "createTime1",
  modifyTime: "modifyTime1",
  size: "size1",
  path: "path1",
  status: relationalStore.AssetStatus.ASSET_NORMAL,
}
const asset2 : relationalStore.Asset = {
  name: "name2",
  uri: "uri2",
  createTime: "createTime2",
  modifyTime: "modifyTime2",
  size: "size2",
  path: "path2",
  status: relationalStore.AssetStatus.ASSET_NORMAL,
}

async function checkResultSetForNormalGet(resultSet : relationalStore.LiteResultSet){
  let count = 0;
  try {
    while(resultSet?.goToNextRow())
    {
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
        let id = resultSet?.getLong(index);
        expect(id).assertEqual(2);
        index = resultSet.getColumnIndex("data1");
        let data1 = resultSet?.getString(index);
        expect(data1).assertEqual('lisi');
        index = resultSet.getColumnIndex("data2");
        let data2 = resultSet?.getLong(index);
        expect(data2).assertEqual(20);
        index = resultSet.getColumnIndex("data3");
        let data3 = resultSet?.getDouble(index);
        expect(data3).assertEqual(20000.0);
        index = resultSet.getColumnIndex("data4");
        let data4 = resultSet?.getBlob(index);
        expect(data4[0]).assertEqual(1);
        expect(data4[1]).assertEqual(2);
        expect(data4[2]).assertEqual(3);
      }
      if(count === 3) {
        expect().assertFail();
      }
    }
    resultSet.close();
  } catch(e) {
    console.error(`checkResultSetForNormalGet failed message:${e.message} code:${e.code}`);
    expect().assertFail();
  }
}

export default function rdbQueryWithoutRowCount() {
  describe('rdbQueryWithoutRowCount', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
      try {
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        expect(rdbStore != undefined).assertTrue();
        await rdbStore?.executeSql(CREATE_TABLE_TEST);
        await rdbStore?.executeSql(CREATE_ASSERT_TABLE_TEST);
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
        const assets1 = [asset1];
        const assets2 = [asset1, asset2];
        const valueBucket2: relationalStore.ValuesBucket = {
          'data1': asset1,
          'data2':assets1
        };
        const valueBucket3: relationalStore.ValuesBucket = {
          'data1': asset2,
          'data2':assets2
        };
        await rdbStore?.insert('test', valueBucket);
        await rdbStore?.insert('test', valueBucket1);
        await rdbStore?.insert('asset_table', valueBucket2);
        await rdbStore?.insert('asset_table', valueBucket3);
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
      let resultSet : relationalStore.LiteResultSet | undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
      } catch(e) {
        console.error(`queryWithoutRowCount_001_normal_columns failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates, ["data1"]);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(resultSet.getColumnIndex("data1"));
        expect(data1).assertEqual('zhangsan');
        resultSet?.close();
      } catch(e) {
        console.error(`queryWithoutRowCount_001_normal_columns failed message:${e.message} code:${e.code}`);
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
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates, null);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet)
        }
      } catch(e) {
        console.error(`queryWithoutRowCount_002_normal_columns failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates, undefined);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet)
        }
      } catch(e) {
        console.error(`queryWithoutRowCount_002_normal_columns failed message:${e.message} code:${e.code}`);
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
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates, [null]);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_003_Abnormal_columns failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates, [undefined]);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_003_Abnormal_columns failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
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
      let resultSet : relationalStore.LiteResultSet | undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates, []);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
      } catch(e) {
        console.error(`queryWithoutRowCount_004_Abnormal_columns failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates, [""]);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(0);
      } catch(e) {
        console.error(`queryWithoutRowCount_004_Abnormal_columns failed message:${e.message} code:${e.code}`);
        expect(e.code === 14800021).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates, ["", "data1"]);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(resultSet.getColumnIndex("data1"));
        expect(data1).assertEqual('zhangsan');
        resultSet?.close();
      } catch(e) {
        console.error(`queryWithoutRowCount_004_Abnormal_columns failed message:${e.message} code:${e.code}`);
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
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      try {
        resultSet = await rdbStore?.queryWithoutRowCount(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_005_abnormal_predicates failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(null);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_005_abnormal_predicates failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
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
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      try {
        await rdbStore?.close();
        let predicates = new relationalStore.RdbPredicates('test');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        expect().assertFail();
      } catch(e) {
        console.error(`queryWithoutRowCount_006_abnormal_rdbStoreIsClose failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        expect(e.code === 14800014).assertTrue();
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
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      const sql = "select * from test";
      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount(sql);
        if (resultSet) {
          checkResultSetForNormalGet(resultSet);
        }
        resultSet?.close();
      } catch(e) {
        console.error(`querySqlWithoutRowCount failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }

      const sql1 = "select * from test where data2 = 20";
      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount(sql1, []);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(resultSet?.getColumnIndex("data1"));
        expect("lisi").assertEqual(data1);
        resultSet?.close();
      } catch(e) {
        console.error(`querySqlWithoutRowCount failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }

      const sql2 = "select * from test where data2 = ?";
      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount(sql2, [18]);
        resultSet?.goToNextRow();
        let data2 = resultSet?.getLong(resultSet.getColumnIndex("data2"));
        expect(18).assertEqual(data2);
        resultSet?.close();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_0001 failed message:${e.message} code:${e.code}`);
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
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      const valueBucket: relationalStore.ValuesBucket = {
        'data1': "wangwu",
        'data2': null,
      };
      await rdbStore?.insert('test', valueBucket);

      const sql = "select * from test where data2 = ?";
      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount(sql, [null]);
        resultSet?.goToNextRow();
        let data2 = resultSet?.getLong(resultSet.getColumnIndex("data2"));
        expect().assertFail();
      } catch (e) {
        console.error(`querySqlWithoutRowCount_002 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount(sql, [undefined]);
        expect().assertFail();
      } catch (e) {
        console.error(`querySqlWithoutRowCount_002 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount(sql, []);
        resultSet?.goToNextRow();
        let data2 = resultSet?.getLong(resultSet.getColumnIndex("data2"));
        expect().assertFail();
      } catch (e) {
        console.error(`querySqlWithoutRowCount_002 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
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
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_003 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue()
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount(null);
        expect().assertFail();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_003 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue()
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("");
        expect().assertFail();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_003 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
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
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      const sql = "select * from test";
      try {
        await rdbStore?.close();
        resultSet = await rdbStore?.querySqlWithoutRowCount(sql);
        expect().assertFail();
      } catch(e) {
        console.error(`querySqlWithoutRowCount_004 failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800014).assertTrue();
      }
      console.log(TAG + "************* querySqlWithoutRowCount_004_abnormal_rdbStoreIsClose end *************");
    })

    /**
     * @tc.number LiteResultSet_001_Abnormal_gotoNextRow
     * @tc.name Abnormal test case of gotoNextRow after queryWithoutRowCount
     * @tc.desc 1.The SQL statement for query is too short，return 14800001
     *          2.resultSet is closed, return 14800014
     *          3.Enter the inserted SQL statement through the query interface, return 14800019
     *          4.The query statement is incorrect, return 14800021
     */
    it('LiteResultSet_001_Abnormal_gotoNextRow',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_001_Abnormal_gotoNextRow start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("se");
        resultSet?.goToNextRow();
        expect().assertFail();
      } catch(e) {
        console.error(`goToNextRow failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
      }

      try {
        let predicates = new relationalStore.RdbPredicates('test');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        resultSet?.goToNextRow();
        expect().assertFail();
      } catch(e) {
        console.error(`goToNextRow failed2 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue()
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("insert into test (data1) values ('wangwu')");
        resultSet?.goToNextRow();
        expect().assertFail();
      } catch(e) {
        console.error(`goToNextRow failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800019).assertTrue()
      }

      try {
        let predicates = new relationalStore.RdbPredicates('test1');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        expect().assertFail();
      } catch(e) {
        console.error(`goToNextRow failed4 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800021).assertTrue()
      }
      console.log(TAG + "************* LiteResultSet_001_Abnormal_gotoNextRow end *************");
    })

    /**
     * @tc.number LiteResultSet_002_Abnormal_getColumnIndex
     * @tc.name Abnormal test case of getColumnIndex after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.The parameter is empty, return 14800001
     *          3.The SQL statement for query is too short，return 14800001
     *          4.resultSet is closed, return 14800014
     *          5.Enter the inserted SQL statement through the query interface, return 14800019
     *          6.The query statement is incorrect, return 14800021
     */
    it('LiteResultSet_002_Abnormal_getColumnIndex',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_002_Abnormal_getColumnIndex start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.getColumnIndex(undefined);
        expect().assertFail();
      } catch (e){
        console.error(`getColumnIndex failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.getColumnIndex("");
        expect().assertFail();
      } catch (e){
        console.error(`getColumnIndex failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("se");
        resultSet?.getColumnIndex("data1")
        expect().assertFail();
      }catch (e){
        console.error(`getColumnIndex failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.getColumnIndex("data5")
        expect().assertFail();
      }catch (e){
        console.error(`getColumnIndex failed4 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        resultSet?.getColumnIndex("data1")
        expect().assertFail();
      }catch (e){
        console.error(`getColumnIndex failed5 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue()
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("insert into test (data1) values ('wangwu')");
        resultSet?.getColumnIndex("data1")
        expect().assertFail();
      }catch (e){
        console.error(`getColumnIndex failed6 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800019).assertTrue()
      }

      try {
        let predicates = new relationalStore.RdbPredicates('test1');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.getColumnIndex("data1");
        expect().assertFail();
      }catch (e){
        console.error(`getColumnIndex failed7 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800021).assertTrue()
      }
      console.log(TAG + "************* LiteResultSet_002_Abnormal_getColumnIndex end *************");
    })

    /**
     * @tc.number LiteResultSet_003_Abnormal_getColumnName
     * @tc.name Abnormal test case of getColumnName after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.The SQL statement for query is too short，return 14800001
     *          3.The parameter value is greater than or less than the number of columns，return 14800013
     *          4.resultSet is closed, return 14800014
     *          5.Enter the inserted SQL statement through the query interface, return 14800019
     *          6.The query statement is incorrect, return 14800021
     */
    it('LiteResultSet_003_Abnormal_getColumnName',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_003_Abnormal_getColumnName start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.getColumnName(undefined);
        expect().assertFail();
      }catch (e){
        console.error(`getColumnName failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue()
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("se");
        resultSet?.getColumnName(1)
        expect().assertFail();
      }catch (e){
        console.error(`getColumnName failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.getColumnName(-1)
        expect().assertFail();
      }catch (e){
        console.error(`getColumnName failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.getColumnName(5)
        expect().assertFail();
      }catch (e){
        console.error(`getColumnName failed4 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        resultSet?.getColumnName(1)
        expect().assertFail();
      }catch (e){
        console.error(`getColumnName failed5 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue()
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("insert into test (data1) values ('wangwu')");
        resultSet?.getColumnName(1)
        expect().assertFail();
      }catch (e){
        console.error(`getColumnName failed6 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800019).assertTrue()
      }

      try {
        let predicates = new relationalStore.RdbPredicates('test1');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.getColumnName(1)
        expect().assertFail();
      }catch (e){
        console.error(`getColumnName failed7 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800021).assertTrue()
      }
      console.log(TAG + "************* LiteResultSet_003_Abnormal_getColumnName end *************");
    })

    /**
     * @tc.number LiteResultSet_004_Normal_getColumnType
     * @tc.name Normal test case of getColumnType after queryWithoutRowCount
     * @tc.desc Transfer the column name or column index to obtain the current column type.
     */
    it('LiteResultSet_004_Normal_getColumnType',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_004_Normal_getColumnType start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let type = await resultSet?.getColumnType(resultSet?.getColumnIndex("id"))
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = await resultSet?.getColumnType(resultSet?.getColumnIndex("data1"));
        expect(type).assertEqual(relationalStore.ColumnType.TEXT);
        type = await resultSet?.getColumnType(resultSet?.getColumnIndex("data2"));
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = await resultSet?.getColumnType(resultSet?.getColumnIndex("data3"));
        expect(type).assertEqual(relationalStore.ColumnType.REAL);
        type = await resultSet?.getColumnType(resultSet?.getColumnIndex("data4"));
        expect(type).assertEqual(relationalStore.ColumnType.BLOB);
      } catch(e) {
        console.error(`getColumnType failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect().assertFail();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let type = await resultSet?.getColumnType("id")
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = await resultSet?.getColumnType("data1");
        expect(type).assertEqual(relationalStore.ColumnType.TEXT);
        type = await resultSet?.getColumnType("data2");
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = await resultSet?.getColumnType("data3");
        expect(type).assertEqual(relationalStore.ColumnType.REAL);
        type = await resultSet?.getColumnType("data4");
        expect(type).assertEqual(relationalStore.ColumnType.BLOB);
      } catch(e) {
        console.error(`getColumnType failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect().assertFail();
      }

      try {
        const valueBucket: relationalStore.ValuesBucket = {
          'data1': null,
          'data2': null,
          'data3': null,
          'data4': null,
        };
        await rdbStore?.insert("test", valueBucket);
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        resultSet?.goToNextRow();
        resultSet?.goToNextRow();
        let type = await resultSet?.getColumnType("id")
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = await resultSet?.getColumnType("data1");
        expect(type).assertEqual(relationalStore.ColumnType.NULL);
        type = await resultSet?.getColumnType("data2");
        expect(type).assertEqual(relationalStore.ColumnType.NULL);
      } catch(e) {
        console.error(`getColumnType failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect().assertFail();
      }
      console.log(TAG + "************* LiteResultSet_004_Normal_getColumnType end *************");
    })

    /**
     * @tc.number LiteResultSet_005_Normal_getColumnType
     * @tc.name Normal test case of getColumnType after queryWithoutRowCount
     * @tc.desc Transfer the column name or column index to obtain the current column type.
     */
    it('LiteResultSet_005_Normal_getColumnType',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_005_Normal_getColumnType start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('asset_table');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let type = await resultSet?.getColumnType(resultSet?.getColumnIndex("id"))
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = await resultSet?.getColumnType(resultSet?.getColumnIndex("data1"));
        expect(type).assertEqual(relationalStore.ColumnType.ASSET);
        type = await resultSet?.getColumnType(resultSet?.getColumnIndex("data2"));
        expect(type).assertEqual(relationalStore.ColumnType.ASSETS);
      } catch(e) {
        console.error(`getColumnType failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect().assertFail();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let type = await resultSet?.getColumnType("id")
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = await resultSet?.getColumnType("data1");
        console.error(`mmy type:${type}`);
        expect(type).assertEqual(relationalStore.ColumnType.ASSET);
        type = await resultSet?.getColumnType("data2");
        expect(type).assertEqual(relationalStore.ColumnType.ASSETS);
      } catch(e) {
        console.error(`getColumnType failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect().assertFail();
      }

      console.log(TAG + "************* LiteResultSet_005_Normal_getColumnType end *************");
    })

    /**
     * @tc.number LiteResultSet_006_Abnormal_getColumnType
     * @tc.name Abnormal test case of getColumnType after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.The SQL statement for query is too short，return 14800001
     *          3.The parameter is empty, return 14800001
     *          4.The parameter value is greater than or less than the number of columns，return 14800013
     *          5.resultSet is closed, return 14800014
     *          6.Enter the inserted SQL statement through the query interface, return 14800019
     *          7.The query statement is incorrect, return 14800021
     */
    it('LiteResultSet_006_Abnormal_getColumnType',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_006_Abnormal_getColumnType start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');
      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("se");
        await resultSet?.getColumnType("id")
        expect().assertFail();
      } catch(e) {
        console.error(`getColumnType failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        await resultSet?.getColumnType(-1)
      } catch(e) {
        console.error(`getColumnType failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code == 14800001).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        await resultSet?.getColumnType("")
      } catch(e) {
        console.error(`getColumnType failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        await resultSet?.getColumnType("data5")
      } catch(e) {
        console.error(`getColumnType failed4 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        await resultSet?.getColumnType("id")
      } catch(e) {
        console.error(`getColumnType failed5 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        await resultSet?.getColumnType(0)
      } catch(e) {
        console.error(`getColumnType failed6 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        if (resultSet) {
          resultSet?.goToNextRow();
          await resultSet?.getColumnType(5);
        }
      } catch(e) {
        console.error(`getColumnType failed7 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        await resultSet?.getColumnType("id");
      } catch(e) {
        console.error(`getColumnType failed8 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800014).assertTrue();
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("insert into test (data1) values ('wangwu')");
        await resultSet?.getColumnType("id");
        expect().assertFail();
      }catch (e){
        console.error(`getColumnType failed9 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800019).assertTrue()
      }

      try {
        let predicates = new relationalStore.RdbPredicates('test1');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        await resultSet?.getColumnType("id");
        expect().assertFail();
      }catch (e){
        console.error(`getColumnType failed10 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800021).assertTrue()
      }

      console.log(TAG + "************* LiteResultSet_006_Abnormal_getColumnType end *************");
    })

    /**
     * @tc.number LiteResultSet_007_Normal_getColumnTypeSync
     * @tc.name Normal test case of queryWithoutRowCount
     * @tc.desc Test the getColumnTypeSync test case after the query.
     */
    it('LiteResultSet_007_Normal_getColumnTypeSync',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_007_Normal_getColumnTypeSync start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let type = resultSet?.getColumnTypeSync(resultSet?.getColumnIndex("id"))
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = resultSet?.getColumnTypeSync(resultSet?.getColumnIndex("data1"));
        expect(type).assertEqual(relationalStore.ColumnType.TEXT);
        type = resultSet?.getColumnTypeSync(resultSet?.getColumnIndex("data2"));
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = resultSet?.getColumnTypeSync(resultSet?.getColumnIndex("data3"));
        expect(type).assertEqual(relationalStore.ColumnType.REAL);
        type = resultSet?.getColumnTypeSync(resultSet?.getColumnIndex("data4"));
        expect(type).assertEqual(relationalStore.ColumnType.BLOB);
      } catch(e) {
        console.error(`getColumnTypeSync failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect().assertFail();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let type = await resultSet?.getColumnType("id")
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = resultSet?.getColumnTypeSync("data1");
        expect(type).assertEqual(relationalStore.ColumnType.TEXT);
        type = resultSet?.getColumnTypeSync("data2");
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = resultSet?.getColumnTypeSync("data3");
        expect(type).assertEqual(relationalStore.ColumnType.REAL);
        type = resultSet?.getColumnTypeSync("data4");
        expect(type).assertEqual(relationalStore.ColumnType.BLOB);
      } catch(e) {
        console.error(`getColumnTypeSync failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect().assertFail();
      }

      try {
        const valueBucket: relationalStore.ValuesBucket = {
          'data1': null,
          'data2': null,
          'data3': null,
          'data4': null,
        };
        await rdbStore?.insert("test", valueBucket);
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        resultSet?.goToNextRow();
        resultSet?.goToNextRow();
        let type = await resultSet?.getColumnType("id")
        expect(type).assertEqual(relationalStore.ColumnType.INTEGER);
        type = await resultSet?.getColumnType("data1");
        expect(type).assertEqual(relationalStore.ColumnType.NULL);
        type = await resultSet?.getColumnType("data2");
        expect(type).assertEqual(relationalStore.ColumnType.NULL);
      } catch(e) {
        console.error(`getColumnType failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect().assertFail();
      }

      console.log(TAG + "************* LiteResultSet_007_Normal_getColumnTypeSync end *************");
    })

    /**
     * @tc.number LiteResultSet_008_Abnormal_getLong
     * @tc.name Abnormal test case of getLong after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.Line out of bounds，return 14800012
     *          3.The parameter value is greater than or less than the number of columns，return 14800013
     *          4.resultSet is closed, return 14800014
     *          5.Type mismatch, return 14800041
     */
    it('LiteResultSet_008_Abnormal_getLong',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_008_Abnormal_getLong start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let id = resultSet?.getLong(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`getLong failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let id = resultSet?.getLong(0);
        expect().assertFail();
      } catch(e) {
        console.error(`getLong failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let id = resultSet?.getLong(-1);
        expect().assertFail();
      } catch(e) {
        console.error(`getLong failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        let id = resultSet?.getLong(0);
        expect().assertFail();
      } catch(e) {
        console.error(`getLong failed4 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue();
      }

      try {
        predicates = new relationalStore.RdbPredicates('asset_table');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let id = resultSet?.getLong(1);
        expect().assertFail();
      } catch(e) {
        console.error(`getLong failed5 message:${e.message} code:${e.code}`);
        expect(e.code === 14800041).assertTrue();
      }
      console.log(TAG + "************* LiteResultSet_008_Abnormal_getLong end *************");
    })

    /**
     * @tc.number LiteResultSet_009_Abnormal_getString
     * @tc.name Abnormal test case of getString after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.Line out of bounds，return 14800012
     *          3.The parameter value is greater than or less than the number of columns，return 14800013
     *          4.resultSet is closed, return 14800014
     *          5.Type mismatch, return 14800041
     */
    it('LiteResultSet_009_Abnormal_getString',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_009_Abnormal_getString start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data1 = resultSet?.getString(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`getString failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data1 = resultSet?.getString(1);
        expect().assertFail();
      } catch(e) {
        console.error(`getString failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(-1);
        expect().assertFail();
      } catch(e) {
        console.error(`getString failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        let data1 = resultSet?.getString(1);
        expect().assertFail();
      } catch(e) {
        console.error(`getString failed4 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue();
      }

      try {
        predicates = new relationalStore.RdbPredicates('asset_table');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getString(1);
        expect().assertFail();
      } catch(e) {
        console.error(`getString failed5 message:${e.message} code:${e.code}`);
        expect(e.code === 14800041).assertTrue();
      }

      console.log(TAG + "************* LiteResultSet_009_Abnormal_getString end *************");
    })

    /**
     * @tc.number LiteResultSet_010_Abnormal_getDouble
     * @tc.name Abnormal test case of getDouble after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.Line out of bounds，return 14800012
     *          3.The parameter value is greater than or less than the number of columns，return 14800013
     *          4.resultSet is closed, return 14800014
     *          5.Type mismatch, return 14800041
     */
    it('LiteResultSet_010_Abnormal_getDouble',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_010_Abnormal_getDouble start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data3 = resultSet?.getDouble(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`getDouble failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data3 = resultSet?.getDouble(3);
        expect().assertFail();
      } catch(e) {
        console.error(`getDouble failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data3 = resultSet?.getDouble(-1);
        expect().assertFail();
      } catch(e) {
        console.error(`getDouble failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        let data3 = resultSet?.getDouble(3);
        expect().assertFail();
      } catch(e) {
        console.error(`getDouble failed4 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue();
      }

      try {
        predicates = new relationalStore.RdbPredicates('asset_table');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data3 = resultSet?.getDouble(1);
        expect().assertFail();
      } catch(e) {
        console.error(`getDouble failed5 message:${e.message} code:${e.code}`);
        expect(e.code === 14800041).assertTrue();
      }

      console.log(TAG + "************* LiteResultSet_010_Abnormal_getDouble end *************");
    })

    /**
     * @tc.number LiteResultSet_011_Abnormal_getBlob
     * @tc.name Abnormal test case of getBlob after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.Line out of bounds，return 14800012
     *          3.The parameter value is greater than or less than the number of columns，return 14800013
     *          4.resultSet is closed, return 14800014
     *          5.Type mismatch, return 14800041
     */
    it('LiteResultSet_011_Abnormal_getBlob',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_011_Abnormal_getBlob start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data3 = resultSet?.getBlob(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data4 = resultSet?.getBlob(4);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data4 = resultSet?.getBlob(-1);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        let data4 = resultSet?.getBlob(4);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed4 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue();
      }

      try {
        predicates = new relationalStore.RdbPredicates('asset_table');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data4 = resultSet?.getBlob(1);
        expect().assertFail();
      } catch(e) {
        console.error(`getDouble failed5 message:${e.message} code:${e.code}`);
        expect(e.code === 14800041).assertTrue();
      }

      console.log(TAG + "************* LiteResultSet_011_Abnormal_getBlob end *************");
    })

    /**
     * @tc.number LiteResultSet_012_Abnormal_getValue
     * @tc.name Abnormal test case of getValue after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.Line out of bounds，return 14800012
     *          3.The parameter value is greater than or less than the number of columns，return 14800013
     *          4.resultSet is closed, return 14800014
     */
    it('LiteResultSet_012_Abnormal_getValue',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_012_Abnormal_getValue start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data3 = resultSet?.getValue(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`getValue failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data1 = resultSet?.getValue(1);
      } catch(e) {
        console.error(`getValue failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = rdbStore?.querySync(predicates);
        resultSet?.goToNextRow();
        let data3 = resultSet?.getValue(1);
      } catch(e) {
        console.error(`getValue failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue();
      }
      console.log(TAG + "************* LiteResultSet_012_Abnormal_getValue end *************");
    })

    /**
     * @tc.number LiteResultSet_013_Abnormal_getAsset
     * @tc.name Abnormal test case of getAsset after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.Line out of bounds，return 14800012
     *          3.The parameter value is greater than or less than the number of columns，return 14800013
     *          4.resultSet is closed, return 14800014
     *          5.Type mismatch, return 14800041
     */
    it('LiteResultSet_013_Abnormal_getAsset',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_013_Abnormal_getAsset start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('asset_table');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data1 = resultSet?.getAsset(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data1 = resultSet?.getAsset(1);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getAsset(-1);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        let data1 = resultSet?.getAsset(1);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed4 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data1 = resultSet?.getAsset(0);
        expect().assertFail();
      } catch(e) {
        console.error(`getDouble failed5 message:${e.message} code:${e.code}`);
        expect(e.code === 14800041).assertTrue();
      }

      console.log(TAG + "************* LiteResultSet_013_Abnormal_getAsset end *************");
    })

    /**
     * @tc.number LiteResultSet_014_Abnormal_getAssets
     * @tc.name Abnormal test case of getAssets after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.Line out of bounds，return 14800012
     *          3.The parameter value is greater than or less than the number of columns，return 14800013
     *          4.resultSet is closed, return 14800014
     *          5.Type mismatch, return 14800041
     */
    it('LiteResultSet_014_Abnormal_getAssets',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_014_Abnormal_getAssets start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('asset_table');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data2 = resultSet?.getAssets(undefined);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let data2 = resultSet?.getAssets(2);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data2 = resultSet?.getAssets(-1);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        let data2 = resultSet?.getAssets(2);
        expect().assertFail();
      } catch(e) {
        console.error(`getBlob failed4 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data2 = resultSet?.getAssets(0);
        expect().assertFail();
      } catch(e) {
        console.error(`getDouble failed5 message:${e.message} code:${e.code}`);
        expect(e.code === 14800041).assertTrue();
      }

      console.log(TAG + "************* LiteResultSet_014_Abnormal_getAssets end *************");
    })

    /**
     * @tc.number LiteResultSet_015_Normal_getRow
     * @tc.name Normal test case of getRow after queryWithoutRowCount
     * @tc.desc Test the getRow test case after the query.
     */
    it('LiteResultSet_015_Normal_getRow',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_015_Normal_getRow start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let valueBucket_ret = resultSet?.getRow();
        if (valueBucket_ret) {
          expect(1).assertEqual(valueBucket_ret.id);
          expect('zhangsan').assertEqual(valueBucket_ret.data1);
          expect(18).assertEqual(valueBucket_ret.data2);
          expect(25000.0).assertEqual(valueBucket_ret.data3);
          expect([1, 2, 3].toString()).assertEqual(valueBucket_ret.data4?.toString());
        }
        resultSet?.close();
      } catch(e) {
        console.error(`getRow failed message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect().assertFail();
      }
      console.log(TAG + "************* LiteResultSet_015_Normal_getRow end *************");
    })

    /**
     * @tc.number LiteResultSet_016_Abnormal_getRow
     * @tc.name Abnormal test case of getRow after queryWithoutRowCount
     * @tc.desc 1.The SQL statement for query is too short，return 14800001
     *          2.Line out of bounds，return 14800012
     *          3.resultSet is closed, return 14800014
     *          4.Enter the inserted SQL statement through the query interface, return 14800019
     *          5.The query statement is incorrect, return 14800021
     */
    it('LiteResultSet_016_Abnormal_getRow',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_016_Abnormal_getRow start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("se");
        let data3 = resultSet?.getRow();
        expect().assertFail();
      }catch (e){
        console.error(`getRow failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let valueBucket_ret = resultSet?.getRow();
        expect().assertFail();
      } catch(e) {
        console.error(`getRow failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        let valueBucket_ret = resultSet?.getRow();
        expect().assertFail();
      } catch(e) {
        console.error(`getRow failed3 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue();
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("insert into test (data1) values ('wangwu')");
        let valueBucket_ret = resultSet?.getRow();
        expect().assertFail();
      }catch (e){
        console.error(`getRow failed4 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800019).assertTrue()
      }

      try {
        let predicates = new relationalStore.RdbPredicates('test1');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let valueBucket_ret = resultSet?.getRow();
        expect().assertFail();
      } catch (e){
        console.error(`getRow failed5 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800021).assertTrue()
      }

      console.log(TAG + "************* LiteResultSet_016_Abnormal_getRow end *************");
    })

    /**
     * @tc.number LiteResultSet_017_Abnormal_getRows
     * @tc.name Abnormal test case of getRows after queryWithoutRowCount
     * @tc.desc 1.The SQL statement for query is too short，return 14800001
     *          2.Line out of bounds，return 14800012
     *          3.resultSet is closed, return 14800014
     *          4.Enter the inserted SQL statement through the query interface, return 14800019
     *          5.The query statement is incorrect, return 14800021
     */
    it('LiteResultSet_017_Abnormal_getRows',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_017_Abnormal_getRows start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("se");
        let data3 = await resultSet?.getRows(2);
        expect().assertFail();
      }catch (e){
        console.error(`getRows failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let valueBucket_ret = await resultSet?.getRows(-1);
        expect().assertFail();
      } catch(e) {
        console.error(`getRows failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        await resultSet?.getRows(2, -1);
        expect().assertFail();
      } catch(e) {
        console.error(`getRows failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        await resultSet?.getRows(2, 4);
        expect().assertFail();
      } catch(e) {
        console.error(`getRows failed4 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        await resultSet?.getRows(2);
        expect().assertFail();
      } catch(e) {
        console.error(`getRows failed5 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue();
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("insert into test (data1) values ('wangwu')");
        await resultSet?.getRows(2);
        expect().assertFail();
      }catch (e){
        console.error(`getRows failed6 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800019).assertTrue()
      }

      try {
        let predicates = new relationalStore.RdbPredicates('test1');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        await resultSet?.getRows(2);
        expect().assertFail();
      } catch (e){
        console.error(`getRows failed7 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800021).assertTrue()
      }

      console.log(TAG + "************* LiteResultSet_017_Abnormal_getRows end *************");
    })


    /**
     * @tc.number LiteResultSet_018_Abnormal_isColumnNull
     * @tc.name Abnormal test case of isColumnNull after queryWithoutRowCount
     * @tc.desc 1.The parameter is undefined, return 401.
     *          2.The SQL statement for query is too short，return 14800001
     *          3.Line out of bounds，return 14800012
     *          4.The parameter value is greater than or less than the number of columns，return 14800013
     *          5.resultSet is closed, return 14800014
     *          6.Enter the inserted SQL statement through the query interface, return 14800019
     *          7.The query statement is incorrect, return 14800021
     */
    it('LiteResultSet_018_Abnormal_isColumnNull',  0, async  () => {
      console.log(TAG + "************* LiteResultSet_018_Abnormal_isColumnNull start *************");
      let resultSet : relationalStore.LiteResultSet | undefined = undefined;
      let predicates = new relationalStore.RdbPredicates('test');

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.isColumnNull(undefined);
        expect().assertFail();
      }catch (e){
        console.error(`isColumnNull failed1 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 401).assertTrue()
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("se");
        let data3 = resultSet?.isColumnNull(0);
        expect().assertFail();
      }catch (e){
        console.error(`isColumnNull failed2 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800001).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let valueBucket_ret = resultSet?.isColumnNull(0);
        expect().assertFail();
      } catch(e) {
        console.error(`isColumnNull failed3 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800012).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let data3 = resultSet?.isColumnNull(-1);
        expect().assertFail();
      }catch (e){
        console.error(`isColumnNull failed4 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue()
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.goToNextRow();
        let valueBucket_ret = resultSet?.isColumnNull(5);
        expect().assertFail();
      } catch(e) {
        console.error(`isColumnNull failed5 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800013).assertTrue();
      }

      try {
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        resultSet?.close();
        let valueBucket_ret = resultSet?.isColumnNull(0);
        expect().assertFail();
      } catch(e) {
        console.error(`isColumnNull failed6 message:${e.message} code:${e.code}`);
        expect(e.code === 14800014).assertTrue();
      }

      try {
        resultSet = await rdbStore?.querySqlWithoutRowCount("insert into test (data1) values ('wangwu')");
        let valueBucket_ret = resultSet?.isColumnNull(0);
        expect().assertFail();
      }catch (e){
        console.error(`isColumnNull failed7 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800019).assertTrue()
      }

      try {
        let predicates = new relationalStore.RdbPredicates('test1');
        resultSet = await rdbStore?.queryWithoutRowCount(predicates);
        let valueBucket_ret = resultSet?.isColumnNull(0);
        expect().assertFail();
      } catch (e){
        console.error(`isColumnNull failed8 message:${e.message} code:${e.code}`);
        resultSet?.close();
        expect(e.code === 14800021).assertTrue()
      }

      console.log(TAG + "************* LiteResultSet_018_Abnormal_isColumnNull end *************");
    })
  })
}