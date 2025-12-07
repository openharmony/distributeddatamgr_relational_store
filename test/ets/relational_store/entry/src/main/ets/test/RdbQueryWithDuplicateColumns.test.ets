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
import fs from '@ohos.file.fs';

const TAG = "[RELATIONAL_STORE_TEST]";
let rdbStore:relationalStore.RdbStore | undefined = undefined;
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name text," + "age long, " + "data1 real," + "data2 blob)";

const CREATE_TABLE_TEST1 = "CREATE TABLE IF NOT EXISTS test1 (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name text," + "age long, " + "data3 asset," + "data4 assets)";

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "rdbQueryResultSet.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG1: relationalStore.StoreConfig = {
  name: "rdbQueryAttach.db",
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

function checkAssetEqual(assetEq1 : relationalStore.Asset, assetEq2 : relationalStore.Asset) : boolean
{
  return assetEq1.name == assetEq2.name && assetEq1.uri == assetEq2.uri &&
    assetEq1.createTime == assetEq2.createTime && assetEq1.modifyTime == assetEq2.modifyTime &&
    assetEq1.size == assetEq2.size && assetEq1.path == assetEq2.path;
}

function checkAssetsEqual(assetsEq1 : relationalStore.Assets, assetsEq2 : relationalStore.Assets) : boolean
{
  if (assetsEq1.length == assetsEq2.length) {
    for (let i = 0; i < assetsEq1.length; ++i) {
      if (!checkAssetEqual(assetsEq1[i], assetsEq2[i])) {
        return false;
      }
    }
    return true;
  }
  return false;
}

export default function RdbQueryWithDuplicateColumns() {
  describe('rdbQueryWithDuplicateColumns', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
      try {
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        expect(rdbStore != undefined).assertTrue();
        await rdbStore?.executeSql(CREATE_TABLE_TEST);
        await rdbStore?.executeSql(CREATE_TABLE_TEST1);
        let u8 = new Uint8Array([1, 2, 3])
        const assets2 = [asset1, asset2];
        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'zhangsan',
          'age': 18,
          'data1': 25000.0,
          'data2': u8,
        };
        const valueBucket1: relationalStore.ValuesBucket = {
          'name': 'lisi',
          'age': 20,
          'data1': 20000.0,
          'data2': u8,
        };
        const valueBucket2: relationalStore.ValuesBucket = {
          'name': 'liming',
          'age': 22,
          'data3': asset1,
          'data4': assets2,
        };
        const valueBucket3: relationalStore.ValuesBucket = {
          'name': 'lifei',
          'age': 24,
          'data3': asset1,
          'data4': assets2,
        };
        await rdbStore?.insert('test', valueBucket);
        await rdbStore?.insert('test', valueBucket1);
        await rdbStore?.insert('test1', valueBucket2);
        await rdbStore?.insert('test1', valueBucket3);
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
     * @tc.number queryCurrentRowData_001
     * @tc.name normal test case of getCurrentRowData
     * @tc.desc multi-table querySql with getCurrentRowData and getRow comparison test
     */
    it('queryCurrentRowData_001',  0, async  () => {
      console.log(TAG + "************* queryCurrentRowData_001 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (resultSet?.goToFirstRow()) {
          let u8 = new Uint8Array([1, 2, 3])
          const assets2 = [asset1, asset2];
          let row = resultSet.getRow();
          expect(row["name"] == "zhangsan").assertTrue();
          expect(row["age"] == 18).assertTrue();
          expect(row["data1"] == 25000.0).assertTrue();
          let rowU8 = row["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(checkAssetEqual(row["data3"], asset1)).assertTrue();
          expect(checkAssetsEqual(row["data4"], assets2)).assertTrue();
          let rowData = resultSet.getCurrentRowData();
          expect(rowData[0] == 1).assertTrue();
          expect(rowData[1] == "zhangsan").assertTrue();
          expect(rowData[2] == 18).assertTrue();
          expect(rowData[3] == 25000.0).assertTrue();
          rowU8 = rowData[4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rowData[5] == 1).assertTrue();
          expect(rowData[6] == "liming").assertTrue();
          expect(rowData[7] == 22).assertTrue();
          expect(checkAssetEqual(rowData[8], asset1)).assertTrue();
          expect(checkAssetsEqual(rowData[9], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`queryCurrentRowData_001 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + "************* queryCurrentRowData_001 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_002
     * @tc.name normal test case of getCurrentRowData
     * @tc.desc multi-table querySql with getCurrentRowData and getRow comparison test
     */
    it('queryCurrentRowData_002',  0, async  () => {
      console.log(TAG + "************* queryCurrentRowData_002 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        let querySQL = "SELECT test.id AS test_id, test.name AS test_name, test.age AS test_age, " +
          "test.data1, test.data2, test1.id AS test1_id, test1.name AS test1_name, test1.age AS test1_age, " +
          "test1.data3, test1.data4 FROM test INNER JOIN test1 ON test.id = test1.id;"
        resultSet = await rdbStore?.querySql(querySQL);
        if (resultSet?.goToFirstRow()) {
          let u8 = new Uint8Array([1, 2, 3]);
          const assets2 = [asset1, asset2];
          let asRowData = resultSet.getCurrentRowData();
          expect(asRowData[0] == 1).assertTrue();
          expect(asRowData[1] == "zhangsan").assertTrue();
          expect(asRowData[2] == 18).assertTrue();
          expect(asRowData[3] == 25000.0).assertTrue();
          let rowU8 = asRowData[4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(asRowData[5] == 1).assertTrue();
          expect(asRowData[6] == "liming").assertTrue();
          expect(asRowData[7] == 22).assertTrue();
          expect(checkAssetEqual(asRowData[8], asset1)).assertTrue();
          expect(checkAssetsEqual(asRowData[9], assets2)).assertTrue();
          let asRow = resultSet.getRow();
          expect(asRow["test_name"] == "zhangsan").assertTrue();
          expect(asRow["test_age"] == 18).assertTrue();
          expect(asRow["data1"] == 25000.0).assertTrue();
          rowU8 = asRow["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(asRow["test1_name"] == "liming").assertTrue();
          expect(asRow["test1_age"] == 22).assertTrue();
          expect(checkAssetEqual(asRow["data3"], asset1)).assertTrue();
          expect(checkAssetsEqual(asRow["data4"], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`queryCurrentRowData_002 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + "************* queryCurrentRowData_002 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_003
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet already close.
     */
    it('queryCurrentRowData_003',  0, async  () => {
      console.log(TAG + "************* queryCurrentRowData_003 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (resultSet) {
          resultSet.close();
          resultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryCurrentRowData_003 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800014).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryCurrentRowData_003 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_004
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet querySql no such table.
     */
    it('queryCurrentRowData_004',  0, async  () => {
      console.log(TAG + "************* queryCurrentRowData_004 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test2");
        if (resultSet) {
          resultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryCurrentRowData_004 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800021).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryCurrentRowData_004 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_005
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet querySql input create table sql.
     */
    it('queryCurrentRowData_005',  0, async  () => {
      console.log(TAG + "************* queryCurrentRowData_005 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql(CREATE_TABLE_TEST);
        if (resultSet) {
          resultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryCurrentRowData_005 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800019).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryCurrentRowData_005 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_006
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet querySql input sql size less then 3.
     */
    it('queryCurrentRowData_006',  0, async  () => {
      console.log(TAG + "************* queryCurrentRowData_006 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("se");
        if (resultSet) {
          resultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryCurrentRowData_006 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryCurrentRowData_006 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_007
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet is empty.
     */
    it('queryCurrentRowData_007',  0, async  () => {
      console.log(TAG + "************* queryCurrentRowData_007 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test where id = 2");
        if (resultSet) {
          resultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryCurrentRowData_007 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800012).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryCurrentRowData_007 end *************");
    })

    /**
     * @tc.number queryGetCurrentRowData_008
     * @tc.name abnormal attach db test case of CurrentRowData
     * @tc.desc ResultSet.CurrentRowData test with attach db querySql.
     */
    it('queryGetCurrentRowData_008',  0, async  () => {
      console.log(TAG + "************* queryGetCurrentRowData_008 start *************");
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach("/data/storage/el2/database/rdb/rdbQueryResultSet.db", "attachDB1");
      expect(count == 1).assertTrue();
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStoreAttach?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3])
        const assets2 = [asset1, asset2];
        if (resultSet) {
          resultSet.goToFirstRow();
          let rowData = resultSet.getCurrentRowData();
          expect(rowData[0] == 1).assertTrue();
          expect(rowData[1] == "zhangsan").assertTrue();
          expect(rowData[2] == 18).assertTrue();
          expect(rowData[3] == 25000.0).assertTrue();
          let rowU8 = rowData[4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rowData[5] == 1).assertTrue();
          expect(rowData[6] == "liming").assertTrue();
          expect(rowData[7] == 22).assertTrue();
          expect(checkAssetEqual(rowData[8], asset1)).assertTrue();
          expect(checkAssetsEqual(rowData[9], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`queryGetCurrentRowData_008 failed message:${e.message} code:${e.code}`);
        expect().assertFalse();
      }
      resultSet?.close();
      await rdbStoreAttach.detach("attachDB1");
      await rdbStoreAttach.close();
      console.log(TAG + "************* queryGetCurrentRowData_008 end *************");
    })

    /**
     * @tc.number queryGetRowsData_001
     * @tc.name normal test case of getRowsData
     * @tc.desc multi-table querySql with getRowsData and getRows comparison test
     */
    it('queryGetRowsData_001', 0, async  () => {
      console.log(TAG + "************* queryGetRowsData_001 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        if (resultSet) {
          let rowsData = await resultSet?.getRowsData(1);
          expect(rowsData[0][0] == 1).assertTrue();
          expect(rowsData[0][1] == "zhangsan").assertTrue();
          expect(rowsData[0][2] == 18).assertTrue();
          expect(rowsData[0][3] == 25000.0).assertTrue();
          let rowU8 = rowsData[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rowsData[0][5] == 1).assertTrue();
          expect(rowsData[0][6] == "liming").assertTrue();
          expect(rowsData[0][7] == 22).assertTrue();
          expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();
          let rows = await resultSet.getRows(1, 0);
          expect(rows[0]["name"] == "zhangsan").assertTrue();
          expect(rows[0]["age"] == 18).assertTrue();
          expect(rows[0]["data1"] == 25000.0).assertTrue();
          rowU8 = rows[0]["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(checkAssetEqual(rows[0]["data3"], asset1)).assertTrue();
          expect(checkAssetsEqual(rows[0]["data4"], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`queryGetRowsData_001 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_001 end *************");
    })

    /**
     * @tc.number queryGetRowsData_002
     * @tc.name normal test case of getRowsData
     * @tc.desc multi-table querySql with getRowsData and getRows comparison test
     */
    it('queryGetRowsData_002', 0, async  () => {
      console.log(TAG + "************* queryGetRowsData_002 start *************");
      let u8 = new Uint8Array([1, 2, 3]);
      const assets2 = [asset1, asset2];
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        let querySQL = "SELECT test.id AS test_id, test.name AS test_name, test.age AS test_age, " +
          "test.data1, test.data2, test1.id AS test1_id, test1.name AS test1_name, test1.age AS test1_age, " +
          "test1.data3, test1.data4 FROM test INNER JOIN test1 ON test.id = test1.id;"
        resultSet = await rdbStore?.querySql(querySQL);
        if (resultSet) {
          let asRowsData = await resultSet?.getRowsData(1);
          expect(asRowsData[0][0] == 1).assertTrue();
          expect(asRowsData[0][1] == "zhangsan").assertTrue();
          expect(asRowsData[0][2] == 18).assertTrue();
          expect(asRowsData[0][3] == 25000.0).assertTrue();
          let rowU8 = asRowsData[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(asRowsData[0][5] == 1).assertTrue();
          expect(asRowsData[0][6] == "liming").assertTrue();
          expect(asRowsData[0][7] == 22).assertTrue();
          expect(checkAssetEqual(asRowsData[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(asRowsData[0][9], assets2)).assertTrue();
          let asRows = await resultSet.getRows(1, 0);
          expect(asRows[0]["test_name"] == "zhangsan").assertTrue();
          expect(asRows[0]["test_age"] == 18).assertTrue();
          expect(asRows[0]["data1"] == 25000.0).assertTrue();
          rowU8 = asRows[0]["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(asRows[0]["test1_name"] == "liming").assertTrue();
          expect(asRows[0]["test1_age"] == 22).assertTrue();
          expect(checkAssetEqual(asRows[0]["data3"], asset1)).assertTrue();
          expect(checkAssetsEqual(asRows[0]["data4"], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`queryGetRowsData_002 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_002 end *************");
    })

    /**
     * @tc.number queryGetRowsData_003
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet already close.
     */
    it('queryGetRowsData_003', 0, async  () => {
      console.log(TAG + "************* queryGetRowsData_003 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (resultSet) {
          resultSet.close();
          await resultSet.getRowsData(1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetRowsData_003 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800014).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_003 end *************");
    })

    /**
     * @tc.number queryGetRowsData_004
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet querySql no such table.
     */
    it('queryGetRowsData_004', 0, async  () => {
      console.log(TAG + "************* queryGetRowsData_004 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test2");
        if (resultSet) {
          await resultSet.getRowsData(1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetRowsData_004 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800021).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_004 end *************");
    })

    /**
     * @tc.number queryGetRowsData_005
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet querySql input create table sql.
     */
    it('queryGetRowsData_005', 0, async  () => {
      console.log(TAG + "************* queryGetRowsData_005 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql(CREATE_TABLE_TEST);
        if (resultSet) {
          await resultSet.getRowsData(1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetRowsData_005 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800019).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_005 end *************");
    })

    /**
     * @tc.number queryGetRowsData_006
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet querySql input sql size less then 3.
     */
    it('queryGetRowsData_006', 0, async  () => {
      console.log(TAG + "************* queryGetRowsData_006 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("se");
        if (resultSet) {
          await resultSet.getRowsData(1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetRowsData_006 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_006 end *************");
    })

    /**
     * @tc.number queryGetRowsData_007
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet is empty.
     */
    it('queryGetRowsData_007',  0, async  () => {
      console.log(TAG + "************* queryGetRowsData_007 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test where id = 3");
        if (resultSet) {
          await resultSet.getRowsData(1,1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetRowsData_007 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800012).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_007 end *************");
    })

    /**
     * @tc.number queryGetRowsData_008
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount out of resultSet rows.
     */
    it('queryGetRowsData_008',  0, async  () => {
      console.log(TAG + "************* queryGetRowsData_008 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        if (resultSet) {
          let rowsDataAll = await resultSet.getRowsData(4);
          expect(rowsDataAll.length == 2).assertTrue();
          expect(rowsDataAll[0][0] == 1).assertTrue();
          expect(rowsDataAll[0][1] == "zhangsan").assertTrue();
          expect(rowsDataAll[0][2] == 18).assertTrue();
          expect(rowsDataAll[0][3] == 25000.0).assertTrue();
          let rowU8 = rowsDataAll[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rowsDataAll[0][5] == 1).assertTrue();
          expect(rowsDataAll[0][6] == "liming").assertTrue();
          expect(rowsDataAll[0][7] == 22).assertTrue();
          expect(checkAssetEqual(rowsDataAll[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(rowsDataAll[0][9], assets2)).assertTrue();
          expect(rowsDataAll[1][0] == 2).assertTrue();
          expect(rowsDataAll[1][1] == "lisi").assertTrue();
          expect(rowsDataAll[1][2] == 20).assertTrue();
          expect(rowsDataAll[1][3] == 20000.0).assertTrue();
          rowU8 = rowsDataAll[1][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rowsDataAll[1][5] == 2).assertTrue();
          expect(rowsDataAll[1][6] == "lifei").assertTrue();
          expect(rowsDataAll[1][7] == 24).assertTrue();
          expect(checkAssetEqual(rowsDataAll[1][8], asset1)).assertTrue();
          expect(checkAssetsEqual(rowsDataAll[1][9], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`queryGetRowsData_008 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_008 end *************");
    })

    /**
     * @tc.number queryGetRowsData_009
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount is -1.
     */
    it('queryGetRowsData_009',  0, async  () => {
      console.log(TAG + "************* queryGetRowsData_009 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test where id = 1");
        if (resultSet) {
          await resultSet.getRowsData(-1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetRowsData_009 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_009 end *************");
    })

    /**
     * @tc.number queryGetRowsData_010
     * @tc.name abnormal attach db test case of getRowsData
     * @tc.desc ResultSet.getRowsData test with attach db querySql.
     */
    it('queryGetRowsData_010',  0, async  () => {
      console.log(TAG + "************* queryGetRowsData_010 start *************");
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach("/data/storage/el2/database/rdb/rdbQueryResultSet.db", "attachDB2");
      expect(count == 1).assertTrue();
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStoreAttach?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3])
        const assets2 = [asset1, asset2];
        if (resultSet) {
          let rowsData = await resultSet.getRowsData(1, 0);
          expect(rowsData[0][0] == 1).assertTrue();
          expect(rowsData[0][1] == "zhangsan").assertTrue();
          expect(rowsData[0][2] == 18).assertTrue();
          expect(rowsData[0][3] == 25000.0).assertTrue();
          let rowU8 = rowsData[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rowsData[0][5] == 1).assertTrue();
          expect(rowsData[0][6] == "liming").assertTrue();
          expect(rowsData[0][7] == 22).assertTrue();
          expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`queryGetRowsData_010 failed message:${e.message} code:${e.code}`);
        expect().assertFalse();
      }
      resultSet?.close();
      await rdbStoreAttach.detach("attachDB2");
      await rdbStoreAttach.close();
      console.log(TAG + "************* queryGetRowsData_010 end *************");
    })

    /**
     * @tc.number queryGetRowsData_011
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount and position are -1.
     */
    it('queryGetRowsData_011',  0, async  () => {
      console.log(TAG + "************* queryGetRowsData_011 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test where id = 1");
        if (resultSet) {
          await resultSet.getRowsData(-1, -1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetRowsData_011 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_011 end *************");
    })

    /**
     * @tc.number queryGetRowsData_012
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount -1 and position is 0.
     */
    it('queryGetRowsData_012',  0, async  () => {
      console.log(TAG + "************* queryGetRowsData_012 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test where id = 1");
        if (resultSet) {
          await resultSet.getRowsData(-1, 0);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetRowsData_012 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_012 end *************");
    })

    /**
     * @tc.number queryGetRowsData_013
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input 1 resultSet position.
     */
    it('queryGetRowsData_013',  0, async  () => {
      console.log(TAG + "************* queryGetRowsData_013 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        if (resultSet) {
          let rowsData = await resultSet.getRowsData(1, 1);
          expect(rowsData.length == 1).assertTrue();
          expect(rowsData[0][0] == 2).assertTrue();
          expect(rowsData[0][1] == "lisi").assertTrue();
          expect(rowsData[0][2] == 20).assertTrue();
          expect(rowsData[0][3] == 20000.0).assertTrue();
          let rowU8 = rowsData[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rowsData[0][5] == 2).assertTrue();
          expect(rowsData[0][6] == "lifei").assertTrue();
          expect(rowsData[0][7] == 24).assertTrue();
          expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`queryGetRowsData_013 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetRowsData_013 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_001
     * @tc.name normal test case of getColumnNames
     * @tc.desc multi-table querySql with queryGetColumnNames test
     */
    it('queryGetColumnNames_001', 0, async  () => {
      console.log(TAG + "************* queryGetColumnNames_001 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (resultSet) {
          let columnNames = resultSet.getColumnNames();
          console.log(`columnNames is ${columnNames}`)
          expect(columnNames[0] == "id").assertTrue();
          expect(columnNames[1] == "name").assertTrue();
          expect(columnNames[2] == "age").assertTrue();
          expect(columnNames[3] == "data1").assertTrue();
          expect(columnNames[4] == "data2").assertTrue();
          expect(columnNames[5] == "id").assertTrue();
          expect(columnNames[6] == "name").assertTrue();
          expect(columnNames[7] == "age").assertTrue();
          expect(columnNames[8] == "data3").assertTrue();
          expect(columnNames[9] == "data4").assertTrue();
        }
      } catch(e) {
        console.error(`queryGetColumnNames_001 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetColumnNames_001 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_002
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc getColumnNames test with resultSet already close.
     */
    it('queryGetColumnNames_002', 0, async  () => {
      console.log(TAG + "************* queryGetColumnNames_002 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (resultSet) {
          resultSet.close();
          resultSet.getColumnNames();
          console.error(`queryGetColumnNames_002 success`);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetColumnNames_002 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800014).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetColumnNames_002 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_003
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc getColumnNames test with resultSet querySql no such table.
     */
    it('queryGetColumnNames_003', 0, async  () => {
      console.log(TAG + "************* queryGetColumnNames_003 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test2");
        if (resultSet) {
          resultSet.getColumnNames();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetColumnNames_003 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800021).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetColumnNames_003 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_004
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc getColumnNames test with resultSet querySql input create table sql.
     */
    it('queryGetColumnNames_004', 0, async  () => {
      console.log(TAG + "************* queryGetColumnNames_004 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql(CREATE_TABLE_TEST);
        if (resultSet) {
          resultSet.getColumnNames();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetColumnNames_004 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800019).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetColumnNames_004 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_005
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc getColumnNames test with resultSet querySql input sql size less then 3.
     */
    it('queryGetColumnNames_005', 0, async  () => {
      console.log(TAG + "************* queryGetColumnNames_005 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("se");
        if (resultSet) {
          resultSet.getColumnNames();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`queryGetColumnNames_005 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      resultSet?.close();
      console.log(TAG + "************* queryGetColumnNames_005 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_006
     * @tc.name abnormal attach db test case of getColumnNames
     * @tc.desc ResultSet.getColumnNames test with attach db querySql.
     */
    it('queryGetColumnNames_006', 0, async  () => {
      console.log(TAG + "************* queryGetColumnNames_006 start *************");
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach("/data/storage/el2/database/rdb/rdbQueryResultSet.db", "attachDB3");
      expect(count == 1).assertTrue();
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStoreAttach?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (resultSet) {
          let columnNames = resultSet.getColumnNames();
          console.log(`columnNames is ${columnNames}`)
          expect(columnNames[0] == "id").assertTrue();
          expect(columnNames[1] == "name").assertTrue();
          expect(columnNames[2] == "age").assertTrue();
          expect(columnNames[3] == "data1").assertTrue();
          expect(columnNames[4] == "data2").assertTrue();
          expect(columnNames[5] == "id").assertTrue();
          expect(columnNames[6] == "name").assertTrue();
          expect(columnNames[7] == "age").assertTrue();
          expect(columnNames[8] == "data3").assertTrue();
          expect(columnNames[9] == "data4").assertTrue();
        }
      } catch(e) {
        console.error(`queryGetColumnNames_006 failed message:${e.message} code:${e.code}`);
        expect().assertFalse();
      }
      resultSet?.close();
      await rdbStoreAttach.detach("attachDB3");
      await rdbStoreAttach.close();
      console.log(TAG + "************* queryGetColumnNames_006 end *************");
    })

    /**
     * @tc.number lite_queryCurrentRowData_001
     * @tc.name normal test case of getCurrentRowData
     * @tc.desc multi-table querySqlWithoutRowCount with getCurrentRowData and getRow comparison test
     */
    it('lite_queryCurrentRowData_001',  0, async  () => {
      console.log(TAG + "************* lite_queryCurrentRowData_001 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        if (liteResultSet) {
          liteResultSet.goToNextRow();
          let liteRow = liteResultSet.getRow();
          expect(liteRow["name"] == "zhangsan").assertTrue();
          expect(liteRow["age"] == 18).assertTrue();
          expect(liteRow["data1"] == 25000.0).assertTrue();
          let rowU8 = liteRow["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(checkAssetEqual(liteRow["data3"], asset1)).assertTrue();
          expect(checkAssetsEqual(liteRow["data4"], assets2)).assertTrue();
          let liteRowData = liteResultSet?.getCurrentRowData();
          expect(liteRowData[0] == 1).assertTrue();
          expect(liteRowData[1] == "zhangsan").assertTrue();
          expect(liteRowData[2] == 18).assertTrue();
          expect(liteRowData[3] == 25000.0).assertTrue();
          rowU8 = liteRowData[4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(liteRowData[5] == 1).assertTrue();
          expect(liteRowData[6] == "liming").assertTrue();
          expect(liteRowData[7] == 22).assertTrue();
          expect(checkAssetEqual(liteRowData[8], asset1)).assertTrue();
          expect(checkAssetsEqual(liteRowData[9], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`lite_queryCurrentRowData_001 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryCurrentRowData_001 end *************");
    })

    /**
     * @tc.number lite_queryCurrentRowData_002
     * @tc.name normal test case of getCurrentRowData
     * @tc.desc multi-table querySqlWithoutRowCount with getCurrentRowData and getRow comparison test
     */
    it('lite_queryCurrentRowData_002',  0, async  () => {
      console.log(TAG + "************* lite_queryCurrentRowData_002 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        let querySQL = "SELECT test.id AS test_id, test.name AS test_name, test.age AS test_age, " +
          "test.data1, test.data2, test1.id AS test1_id, test1.name AS test1_name, test1.age AS test1_age, " +
          "test1.data3, test1.data4 FROM test INNER JOIN test1 ON test.id = test1.id;"
        liteResultSet = await rdbStore?.querySqlWithoutRowCount(querySQL);
        if (liteResultSet) {
          liteResultSet.goToNextRow();
          let u8 = new Uint8Array([1, 2, 3]);
          const assets2 = [asset1, asset2];
          let asLiteRowData = liteResultSet?.getCurrentRowData();
          expect(asLiteRowData[0] == 1).assertTrue();
          expect(asLiteRowData[1] == "zhangsan").assertTrue();
          expect(asLiteRowData[2] == 18).assertTrue();
          expect(asLiteRowData[3] == 25000.0).assertTrue();
          let rowU8 = asLiteRowData[4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(asLiteRowData[5] == 1).assertTrue();
          expect(asLiteRowData[6] == "liming").assertTrue();
          expect(asLiteRowData[7] == 22).assertTrue();
          expect(checkAssetEqual(asLiteRowData[8], asset1)).assertTrue();
          expect(checkAssetsEqual(asLiteRowData[9], assets2)).assertTrue();
          let asLiteRow = liteResultSet.getRow();
          expect(asLiteRow["test_name"] == "zhangsan").assertTrue();
          expect(asLiteRow["test_age"] == 18).assertTrue();
          expect(asLiteRow["data1"] == 25000.0).assertTrue();
          rowU8 = asLiteRow["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(asLiteRow["test1_name"] == "liming").assertTrue();
          expect(asLiteRow["test1_age"] == 22).assertTrue();
          expect(checkAssetEqual(asLiteRow["data3"], asset1)).assertTrue();
          expect(checkAssetsEqual(asLiteRow["data4"], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`lite_queryCurrentRowData_002 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryCurrentRowData_002 end *************");
    })

    /**
     * @tc.number lite_queryCurrentRowData_003
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc liteResultSet.getCurrentRowData test with liteResultSet already close.
     */
    it('lite_queryCurrentRowData_003',  0, async  () => {
      console.log(TAG + "************* lite_queryCurrentRowData_003 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (liteResultSet) {
          liteResultSet.close();
          liteResultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryCurrentRowData_003 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800014).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryCurrentRowData_003 end *************");
    })

    /**
     * @tc.number lite_queryCurrentRowData_004
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc liteResultSet.getCurrentRowData test with querySqlWithoutRowCount no such table.
     */
    it('lite_queryCurrentRowData_004',  0, async  () => {
      console.log(TAG + "************* lite_queryCurrentRowData_004 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test2");
        if (liteResultSet) {
          liteResultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryCurrentRowData_004 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800021).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryCurrentRowData_004 end *************");
    })

    /**
     * @tc.number lite_queryCurrentRowData_005
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc liteResultSet.getCurrentRowData test with querySqlWithoutRowCount input create table sql.
     */
    it('lite_queryCurrentRowData_005',  0, async  () => {
      console.log(TAG + "************* lite_queryCurrentRowData_005 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount(CREATE_TABLE_TEST);
        if (liteResultSet) {
          liteResultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryCurrentRowData_005 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800019).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryCurrentRowData_005 end *************");
    })

    /**
     * @tc.number lite_queryCurrentRowData_006
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc liteResultSet.getCurrentRowData test with querySqlWithoutRowCount input sql size less then 3.
     */
    it('lite_queryCurrentRowData_006',  0, async  () => {
      console.log(TAG + "************* lite_queryCurrentRowData_006 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("se");
        if (liteResultSet) {
          liteResultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryCurrentRowData_006 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryCurrentRowData_006 end *************");
    })

    /**
     * @tc.number lite_queryCurrentRowData_007
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with liteResultSet is empty.
     */
    it('lite_queryCurrentRowData_007',  0, async  () => {
      console.log(TAG + "************* lite_queryCurrentRowData_007 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test where id = 2");
        if (liteResultSet) {
          liteResultSet.getCurrentRowData();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryCurrentRowData_007 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800012).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryCurrentRowData_007 end *************");
    })
    
    /**
     * @tc.number lite_queryGetRowsData_001
     * @tc.name normal test case of getRowsData
     * @tc.desc multi-table querySqlWithoutRowCount with getRowsData and getRows comparison test
     */
    it('lite_queryGetRowsData_001', 0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_001 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await
        rdbStore?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        if (liteResultSet) {
          let liteRowsData = await liteResultSet?.getRowsData(1, 0);
          expect(liteRowsData[0][0] == 1).assertTrue();
          expect(liteRowsData[0][1] == "zhangsan").assertTrue();
          expect(liteRowsData[0][2] == 18).assertTrue();
          expect(liteRowsData[0][3] == 25000.0).assertTrue();
          let rowU8 = liteRowsData[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(liteRowsData[0][5] == 1).assertTrue();
          expect(liteRowsData[0][6] == "liming").assertTrue();
          expect(liteRowsData[0][7] == 22).assertTrue();
          expect(checkAssetEqual(liteRowsData[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(liteRowsData[0][9], assets2)).assertTrue();
          let liteRows = await liteResultSet.getRows(1, 0);
          expect(liteRows[0]["id"] == 1).assertTrue();
          expect(liteRows[0]["name"] == "zhangsan").assertTrue();
          expect(liteRows[0]["age"] == 18).assertTrue();
          expect(liteRows[0]["data1"] == 25000.0).assertTrue();
          rowU8 = liteRows[0]["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(checkAssetEqual(liteRows[0]["data3"], asset1)).assertTrue();
          expect(checkAssetsEqual(liteRows[0]["data4"], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_001 failed message:${e.message} code:${e.code}`);
        liteResultSet?.close();
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_001 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_002
     * @tc.name normal test case of getRowsData
     * @tc.desc multi-table querySqlWithoutRowCount with getRowsData and getRows comparison test
     */
    it('lite_queryGetRowsData_002', 0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_002 start *************");
      let u8 = new Uint8Array([1, 2, 3]);
      const assets2 = [asset1, asset2];
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        let querySQL = "SELECT test.id AS test_id, test.name AS test_name, test.age AS test_age, " +
          "test.data1, test.data2, test1.id AS test1_id, test1.name AS test1_name, test1.age AS test1_age, " +
          "test1.data3, test1.data4 FROM test INNER JOIN test1 ON test.id = test1.id;"
        liteResultSet = await rdbStore?.querySqlWithoutRowCount(querySQL);
        if (liteResultSet) {
          let liteAsRowsData = await liteResultSet?.getRowsData(1);
          expect(liteAsRowsData[0][0] == 1).assertTrue();
          expect(liteAsRowsData[0][1] == "zhangsan").assertTrue();
          expect(liteAsRowsData[0][2] == 18).assertTrue();
          expect(liteAsRowsData[0][3] == 25000.0).assertTrue();
          let rowU8 = liteAsRowsData[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(liteAsRowsData[0][5] == 1).assertTrue();
          expect(liteAsRowsData[0][6] == "liming").assertTrue();
          expect(liteAsRowsData[0][7] == 22).assertTrue();
          expect(checkAssetEqual(liteAsRowsData[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(liteAsRowsData[0][9], assets2)).assertTrue();
          let liteAsRows = await liteResultSet.getRows(1, 0);
          expect(liteAsRows[0]["test_name"] == "zhangsan").assertTrue();
          expect(liteAsRows[0]["test_age"] == 18).assertTrue();
          expect(liteAsRows[0]["data1"] == 25000.0).assertTrue();
          rowU8 = liteAsRows[0]["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(liteAsRows[0]["test1_name"] == "liming").assertTrue();
          expect(liteAsRows[0]["test1_age"] == 22).assertTrue();
          expect(checkAssetEqual(liteAsRows[0]["data3"], asset1)).assertTrue();
          expect(checkAssetsEqual(liteAsRows[0]["data4"], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_002 failed message:${e.message} code:${e.code}`);
        liteResultSet?.close();
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_002 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_003
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with liteResultSet already close.
     */
    it('lite_queryGetRowsData_003', 0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_003 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (liteResultSet) {
          liteResultSet.close();
          await liteResultSet.getRowsData(1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_003 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800014).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_003 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_004
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with querySqlWithoutRowCount no such table.
     */
    it('lite_queryGetRowsData_004', 0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_004 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test2");
        if (liteResultSet) {
          await liteResultSet.getRowsData(1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_004 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800021).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_004 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_005
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with querySqlWithoutRowCount input create table sql.
     */
    it('lite_queryGetRowsData_005', 0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_005 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount(CREATE_TABLE_TEST);
        if (liteResultSet) {
          await liteResultSet.getRowsData(1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_005 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800019).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_005 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_006
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with querySqlWithoutRowCount input sql size less then 3.
     */
    it('lite_queryGetRowsData_006', 0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_006 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("se");
        if (liteResultSet) {
          await liteResultSet.getRowsData(1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_006 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_006 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_007
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with resultSet is empty.
     */
    it('lite_queryGetRowsData_007', 0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_007 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test where id = 3");
        if (liteResultSet) {
          await liteResultSet.getRowsData(1,1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_007 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800012).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_006 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_008
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount out of liteResultSet rows.
     */
    it('lite_queryGetRowsData_008',  0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_008 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        if (liteResultSet) {
          let liteRowsDataAll = await liteResultSet.getRowsData(4);
          expect(liteRowsDataAll.length == 2).assertTrue();
          expect(liteRowsDataAll[0][0] == 1).assertTrue();
          expect(liteRowsDataAll[0][1] == "zhangsan").assertTrue();
          expect(liteRowsDataAll[0][2] == 18).assertTrue();
          expect(liteRowsDataAll[0][3] == 25000.0).assertTrue();
          let rowU8 = liteRowsDataAll[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(liteRowsDataAll[0][5] == 1).assertTrue();
          expect(liteRowsDataAll[0][6] == "liming").assertTrue();
          expect(liteRowsDataAll[0][7] == 22).assertTrue();
          expect(checkAssetEqual(liteRowsDataAll[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(liteRowsDataAll[0][9], assets2)).assertTrue();
          expect(liteRowsDataAll[1][0] == 2).assertTrue();
          expect(liteRowsDataAll[1][1] == "lisi").assertTrue();
          expect(liteRowsDataAll[1][2] == 20).assertTrue();
          expect(liteRowsDataAll[1][3] == 20000.0).assertTrue();
          rowU8 = liteRowsDataAll[1][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(liteRowsDataAll[1][5] == 2).assertTrue();
          expect(liteRowsDataAll[1][6] == "lifei").assertTrue();
          expect(liteRowsDataAll[1][7] == 24).assertTrue();
          expect(checkAssetEqual(liteRowsDataAll[1][8], asset1)).assertTrue();
          expect(checkAssetsEqual(liteRowsDataAll[1][9], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_008 failed message:${e.message} code:${e.code}`);
        liteResultSet?.close();
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_008 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_009
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount is -1.
     */
    it('lite_queryGetRowsData_009',  0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_009 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test where id = 1");
        if (liteResultSet) {
          await liteResultSet.getRowsData(-1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_009 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_009 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_010
     * @tc.name abnormal attach db test case of getRowsData
     * @tc.desc LiteResultSet.getRowsData test with attach db querySqlWithoutRowCount.
     */
    it('lite_queryGetRowsData_010',  0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_010 start *************");
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach("/data/storage/el2/database/rdb/rdbQueryResultSet.db", "attachDB5");
      expect(count == 1).assertTrue();
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStoreAttach?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3])
        const assets2 = [asset1, asset2];
        if (liteResultSet) {
          let rowsData = await liteResultSet.getRowsData(1, 0);
          expect(rowsData[0][0] == 1).assertTrue();
          expect(rowsData[0][1] == "zhangsan").assertTrue();
          expect(rowsData[0][2] == 18).assertTrue();
          expect(rowsData[0][3] == 25000.0).assertTrue();
          let rowU8 = rowsData[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rowsData[0][5] == 1).assertTrue();
          expect(rowsData[0][6] == "liming").assertTrue();
          expect(rowsData[0][7] == 22).assertTrue();
          expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_010 failed message:${e.message} code:${e.code}`);
        liteResultSet?.close();
        await rdbStoreAttach.detach("attachDB5");
        await rdbStoreAttach.close();
        expect().assertFalse();
      }
      liteResultSet?.close();
      await rdbStoreAttach.detach("attachDB5");
      await rdbStoreAttach.close();
      console.log(TAG + "************* lite_queryGetRowsData_010 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_011
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount and position are -1.
     */
    it('lite_queryGetRowsData_011',  0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_011 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test where id = 1");
        if (liteResultSet) {
          await liteResultSet.getRowsData(-1, -1);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_011 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_011 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_012
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount -1 and position is 0.
     */
    it('lite_queryGetRowsData_012',  0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_012 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test where id = 1");
        if (liteResultSet) {
          await liteResultSet.getRowsData(-1, 0);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_012 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_012 end *************");
    })

    /**
     * @tc.number lite_queryGetRowsData_013
     * @tc.name normal test case of getRowsData
     * @tc.desc getRowsData test with input 1 liteResultSet position.
     */
    it('lite_queryGetRowsData_013',  0, async  () => {
      console.log(TAG + "************* lite_queryGetRowsData_013 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        if (liteResultSet) {
          let rowsData = await liteResultSet.getRowsData(1,1);
          expect(rowsData.length == 1).assertTrue();
          expect(rowsData[0][0] == 2).assertTrue();
          expect(rowsData[0][1] == "lisi").assertTrue();
          expect(rowsData[0][2] == 20).assertTrue();
          expect(rowsData[0][3] == 20000.0).assertTrue();
          let rowU8 = rowsData[0][4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rowsData[0][5] == 2).assertTrue();
          expect(rowsData[0][6] == "lifei").assertTrue();
          expect(rowsData[0][7] == 24).assertTrue();
          expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
          expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();
        }
      } catch(e) {
        console.error(`lite_queryGetRowsData_013 failed message:${e.message} code:${e.code}`);
        liteResultSet?.close();
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetRowsData_013 end *************");
    })

    /**
     * @tc.number lite_queryGetColumnNames_001
     * @tc.name normal test case of getColumnNames
     * @tc.desc multi-table querySqlWithoutRowCount with getColumnNames test
     */
    it('lite_queryGetColumnNames_001', 0, async  () => {
      console.log(TAG + "************* lite_queryGetColumnNames_001 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (liteResultSet) {
          let columnNames = liteResultSet.getColumnNames();
          console.log(`columnNames is ${columnNames}`)
          expect(columnNames[0] == "id").assertTrue();
          expect(columnNames[1] == "name").assertTrue();
          expect(columnNames[2] == "age").assertTrue();
          expect(columnNames[3] == "data1").assertTrue();
          expect(columnNames[4] == "data2").assertTrue();
          expect(columnNames[5] == "id").assertTrue();
          expect(columnNames[6] == "name").assertTrue();
          expect(columnNames[7] == "age").assertTrue();
          expect(columnNames[8] == "data3").assertTrue();
          expect(columnNames[9] == "data4").assertTrue();
          console.log(`columnNames is ${columnNames[0]}`)
        }
      } catch(e) {
        console.error(`lite_queryGetColumnNames_001 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetColumnNames_001 end *************");
    })

    /**
     * @tc.number lite_queryGetColumnNames_002
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc liteResultSet.getColumnNames test with liteResultSet already close.
     */
    it('lite_queryGetColumnNames_002', 0, async  () => {
      console.log(TAG + "************* lite_queryGetColumnNames_002 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (liteResultSet) {
          liteResultSet.close();
          liteResultSet.getColumnNames();
          console.error(`lite_queryGetColumnNames_002 success`);
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetColumnNames_002 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800014).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetColumnNames_002 end *************");
    })

    /**
     * @tc.number lite_queryGetColumnNames_003
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc liteResultSet.getColumnNames test with querySqlWithoutRowCount no such table.
     */
    it('lite_queryGetColumnNames_003', 0, async  () => {
      console.log(TAG + "************* lite_queryGetColumnNames_003 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test2");
        if (liteResultSet) {
          liteResultSet.getColumnNames();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetColumnNames_003 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800021).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetColumnNames_003 end *************");
    })

    /**
     * @tc.number lite_queryGetColumnNames_004
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc liteResultSet.getColumnNames test with querySqlWithoutRowCount input create table sql.
     */
    it('lite_queryGetColumnNames_004', 0, async  () => {
      console.log(TAG + "************* lite_queryGetColumnNames_004 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount(CREATE_TABLE_TEST);
        if (liteResultSet) {
          liteResultSet.getColumnNames();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetColumnNames_004 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800019).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetColumnNames_004 end *************");
    })

    /**
     * @tc.number lite_queryGetColumnNames_005
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc liteResultSet.getColumnNames test with querySqlWithoutRowCount input sql size less then 3.
     */
    it('lite_queryGetColumnNames_005', 0, async  () => {
      console.log(TAG + "************* lite_queryGetColumnNames_005 start *************");
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore?.querySqlWithoutRowCount("se");
        if (liteResultSet) {
          liteResultSet.getColumnNames();
          expect().assertFail();
        }
      } catch(e) {
        console.error(`lite_queryGetColumnNames_005 failed message:${e.message} code:${e.code}`);
        expect(e.code == 14800001).assertTrue();
      }
      liteResultSet?.close();
      console.log(TAG + "************* lite_queryGetColumnNames_005 end *************");
    })

    /**
     * @tc.number lite_queryGetColumnNames_006
     * @tc.name abnormal attach db test case of getColumnNames
     * @tc.desc LiteResultSet.getColumnNames test with attach db querySqlWithoutRowCount.
     */
    it('lite_queryGetColumnNames_006', 0, async  () => {
      console.log(TAG + "************* lite_queryGetColumnNames_006 start *************");
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach("/data/storage/el2/database/rdb/rdbQueryResultSet.db", "attachDB6");
      expect(count == 1).assertTrue();
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore?.querySqlWithoutRowCount("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (liteResultSet) {
          let columnNames = liteResultSet.getColumnNames();
          console.log(`columnNames is ${columnNames}`)
          expect(columnNames[0] == "id").assertTrue();
          expect(columnNames[1] == "name").assertTrue();
          expect(columnNames[2] == "age").assertTrue();
          expect(columnNames[3] == "data1").assertTrue();
          expect(columnNames[4] == "data2").assertTrue();
          expect(columnNames[5] == "id").assertTrue();
          expect(columnNames[6] == "name").assertTrue();
          expect(columnNames[7] == "age").assertTrue();
          expect(columnNames[8] == "data3").assertTrue();
          expect(columnNames[9] == "data4").assertTrue();
        }
      } catch(e) {
        console.error(`lite_queryGetColumnNames_006 failed message:${e.message} code:${e.code}`);
        expect().assertFalse();
      }
      liteResultSet?.close();
      await rdbStoreAttach.detach("attachDB6");
      await rdbStoreAttach.close();
      console.log(TAG + "************* lite_queryGetColumnNames_006 end *************");
    })
  })
}