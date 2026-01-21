/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import relationalStore from '@ohos.data.relationalStore';

const TAG = '[RELATIONAL_STORE_TEST]';
let rdbStore: relationalStore.RdbStore;
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const CREATE_TABLE_TEST = 'CREATE TABLE IF NOT EXISTS test ' +
  '(id INTEGER PRIMARY KEY AUTOINCREMENT, name text, age long, data1 real, data2 blob)';

const CREATE_TABLE_TEST1 = 'CREATE TABLE IF NOT EXISTS test1 ' +
  '(id INTEGER PRIMARY KEY AUTOINCREMENT, name text, age long, data3 asset, data4 assets)';

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: 'rdbQueryResultSet.db',
  securityLevel: relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG1: relationalStore.StoreConfig = {
  name: 'rdbQueryAttach.db',
  securityLevel: relationalStore.SecurityLevel.S1,
}

const asset1 : relationalStore.Asset = {
  name: 'name1',
  uri: 'uri1',
  createTime: 'createTime1',
  modifyTime: 'modifyTime1',
  size: 'size1',
  path: 'path1',
  status: relationalStore.AssetStatus.ASSET_NORMAL,
}
const asset2 : relationalStore.Asset = {
  name: 'name2',
  uri: 'uri2',
  createTime: 'createTime2',
  modifyTime: 'modifyTime2',
  size: 'size2',
  path: 'path2',
  status: relationalStore.AssetStatus.ASSET_NORMAL,
}

function checkAssetEqual(assetEq1: relationalStore.Asset, assetEq2: relationalStore.Asset) : boolean
{
  return assetEq1.name == assetEq2.name && assetEq1.uri == assetEq2.uri &&
    assetEq1.createTime == assetEq2.createTime && assetEq1.modifyTime == assetEq2.modifyTime &&
    assetEq1.size == assetEq2.size && assetEq1.path == assetEq2.path;
}

function checkAssetsEqual(assetsEq1: relationalStore.Assets, assetsEq2: relationalStore.Assets) : boolean
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
        await rdbStore.executeSql(CREATE_TABLE_TEST);
        await rdbStore.executeSql(CREATE_TABLE_TEST1);
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
        await rdbStore.insert('test', valueBucket);
        await rdbStore.insert('test', valueBucket1);
        await rdbStore.insert('test1', valueBucket2);
        await rdbStore.insert('test1', valueBucket3);
      } catch(error) {
        console.error(TAG + `beforeAll failed, code:${error.code}, message:${error.message}`);
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
        await rdbStore.close();
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch(error) {
        console.error(TAG + `afterAll failed, code:${error.code}, message:${error.message}`);
        expect().assertFail();
      }
    })

    /**
     * @tc.number queryCurrentRowData_001
     * @tc.name normal test case of getCurrentRowData
     * @tc.desc multi-table querySql with getCurrentRowData and getRow comparison test
     *          1. query all data
     *          2. execute getCurrentRowData and getRow
     *          3. compare the values returned by the two methods
     */
    it('queryCurrentRowData_001',  0, async  () => {
      console.log(TAG + '************* queryCurrentRowData_001 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        expect(resultSet.goToFirstRow()).assertTrue();
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];

        let row = resultSet.getRow();
        expect('zhangsan').assertEqual(row.name);
        expect(18).assertEqual(row.age);
        expect(25000.0).assertEqual(row.data1);
        let rowU8 = row.data2 as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(checkAssetEqual(row.data3, asset1)).assertTrue();
        expect(checkAssetsEqual(row.data4, assets2)).assertTrue();

        let rowData = resultSet.getCurrentRowData();
        expect(10).assertEqual(rowData.length);
        expect(1).assertEqual(rowData[0]);
        expect('zhangsan').assertEqual(rowData[1]);
        expect(18).assertEqual(rowData[2]);
        expect(25000.0).assertEqual(rowData[3]);
        rowU8 = rowData[4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(rowData[5]);
        expect('liming').assertEqual(rowData[6]);
        expect(22).assertEqual(rowData[7]);
        expect(checkAssetEqual(rowData[8], asset1)).assertTrue();
        expect(checkAssetsEqual(rowData[9], assets2)).assertTrue();
      } catch(err) {
        console.error(`queryCurrentRowData_001 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + '************* queryCurrentRowData_001 end *************');
    })

    /**
     * @tc.number queryCurrentRowData_002
     * @tc.name normal test case of getCurrentRowData
     * @tc.desc multi-table querySql with getCurrentRowData and getRow comparison test
     *          1. query all data
     *          2. execute getCurrentRowData and getRow
     *          3. compare the values returned by the two methods
     */
    it('queryCurrentRowData_002',  0, async  () => {
      console.log(TAG + '************* queryCurrentRowData_002 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        let querySQL = 'SELECT test.id AS test_id, test.name AS test_name, test.age AS test_age, ' +
          'test.data1, test.data2, test1.id AS test1_id, test1.name AS test1_name, test1.age AS test1_age, ' +
          'test1.data3, test1.data4 FROM test INNER JOIN test1 ON test.id = test1.id;'
        resultSet = await rdbStore.querySql(querySQL);
        expect(resultSet.goToFirstRow()).assertTrue();
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];

        let asRowData = resultSet.getCurrentRowData();
        expect(10).assertEqual(asRowData.length);
        expect(1).assertEqual(asRowData[0]);
        expect('zhangsan').assertEqual(asRowData[1]);
        expect(18).assertEqual(asRowData[2]);
        expect(25000.0).assertEqual(asRowData[3]);
        let rowU8 = asRowData[4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(asRowData[5]);
        expect('liming').assertEqual(asRowData[6]);
        expect(22).assertEqual(asRowData[7]);
        expect(checkAssetEqual(asRowData[8], asset1)).assertTrue();
        expect(checkAssetsEqual(asRowData[9], assets2)).assertTrue();

        let asRow = resultSet.getRow();
        expect('zhangsan').assertEqual(asRow.test_name);
        expect(18).assertEqual(asRow.test_age);
        expect(25000.0).assertEqual(asRow.data1);
        rowU8 = asRow.data2 as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect('liming').assertEqual(asRow.test1_name);
        expect(22).assertEqual(asRow.test1_age);
        expect(checkAssetEqual(asRow.data3, asset1)).assertTrue();
        expect(checkAssetsEqual(asRow.data4, assets2)).assertTrue();
      } catch(err) {
        console.error(`queryCurrentRowData_002 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + '************* queryCurrentRowData_002 end *************');
    })

    /**
     * @tc.number queryCurrentRowData_003
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet already close.
     *          1. query all data
     *          2. close resultSet
     *          3. execute getCurrentRowData and return 14800014
     */
    it('queryCurrentRowData_003',  0, async  () => {
      console.log(TAG + '************* queryCurrentRowData_003 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        resultSet.close();
        resultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`queryCurrentRowData_003 failed message:${err.message} code:${err.code}`);
        expect('14800014').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryCurrentRowData_003 end *************');
    })

    /**
     * @tc.number queryCurrentRowData_004
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet querySql no such table.
     *          1. query all data from table test2 that is not exist
     *          2. execute getCurrentRowData and return 14800021
     */
    it('queryCurrentRowData_004',  0, async  () => {
      console.log(TAG + '************* queryCurrentRowData_004 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test2');
        resultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`queryCurrentRowData_004 failed message:${err.message} code:${err.code}`);
        expect('14800021').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryCurrentRowData_004 end *************');
    })

    /**
     * @tc.number queryCurrentRowData_005
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet querySql input create table sql.
     *          1. create table using querySql
     *          2. execute getCurrentRowData and return 14800019
     */
    it('queryCurrentRowData_005',  0, async  () => {
      console.log(TAG + '************* queryCurrentRowData_005 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql(CREATE_TABLE_TEST);
        resultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`queryCurrentRowData_005 failed message:${err.message} code:${err.code}`);
        expect('14800019').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryCurrentRowData_005 end *************');
    })

    /**
     * @tc.number queryCurrentRowData_006
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet querySql input sql size less then 3.
     *          1. input incomplete SQL statement
     *          2. execute getCurrentRowData and return 14800001
     */
    it('queryCurrentRowData_006',  0, async  () => {
      console.log(TAG + '************* queryCurrentRowData_006 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('se');
        resultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`queryCurrentRowData_006 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryCurrentRowData_006 end *************');
    })

    /**
     * @tc.number queryCurrentRowData_007
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with resultSet is empty.
     *          1. not execute goToFirstRow
     *          2. execute getCurrentRowData and return 14800012
     */
    it('queryCurrentRowData_007',  0, async  () => {
      console.log(TAG + '************* queryCurrentRowData_007 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test where id = 2');
        resultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`queryCurrentRowData_007 failed message:${err.message} code:${err.code}`);
        expect('14800012').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryCurrentRowData_007 end *************');
    })

    /**
     * @tc.number queryCurrentRowData_008
     * @tc.name abnormal attach db test case of CurrentRowData
     * @tc.desc ResultSet.CurrentRowData test with attach db querySql.
     *          1. execute attach and querySql
     *          2. get all values
     */
    it('queryCurrentRowData_008',  0, async  () => {
      console.log(TAG + '************* queryCurrentRowData_008 start *************');
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach('/data/storage/el2/database/rdb/rdbQueryResultSet.db', 'attachDB1');
      expect(1).assertEqual(count);
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStoreAttach.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3])
        const assets2 = [asset1, asset2];
        expect(resultSet.goToFirstRow()).assertTrue();

        let rowData = resultSet.getCurrentRowData();
        expect(10).assertEqual(rowData.length);
        expect(1).assertEqual(rowData[0]);
        expect('zhangsan').assertEqual(rowData[1]);
        expect(18).assertEqual(rowData[2]);
        expect(25000.0).assertEqual(rowData[3]);
        let rowU8 = rowData[4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(rowData[5]);
        expect('liming').assertEqual(rowData[6]);
        expect(22).assertEqual(rowData[7]);
        expect(checkAssetEqual(rowData[8], asset1)).assertTrue();
        expect(checkAssetsEqual(rowData[9], assets2)).assertTrue();
      } catch(err) {
        console.error(`queryCurrentRowData_008 failed message:${err.message} code:${err.code}`);
        expect().assertFalse();
      }
      resultSet?.close();
      await rdbStoreAttach.detach('attachDB1');
      await rdbStoreAttach.close();
      console.log(TAG + '************* queryCurrentRowData_008 end *************');
    })

    /**
     * @tc.number queryGetRowsData_001
     * @tc.name normal test case of getRowsData
     * @tc.desc multi-table querySql with getRowsData and getRows comparison test
     *          1. query all data
     *          2. execute getRowsData and getRows
     *          3. compare the values returned by the two methods
     */
    it('queryGetRowsData_001', 0, async  () => {
      console.log(TAG + '************* queryGetRowsData_001 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        let rowsData = await resultSet.getRowsData(1);
        expect(1).assertEqual(rowsData.length);
        expect(10).assertEqual(rowsData[0].length);
        expect(1).assertEqual(rowsData[0][0]);
        expect('zhangsan').assertEqual(rowsData[0][1]);
        expect(18).assertEqual(rowsData[0][2]);
        expect(25000.0).assertEqual(rowsData[0][3]);
        let rowU8 = rowsData[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(rowsData[0][5]);
        expect('liming').assertEqual(rowsData[0][6]);
        expect(22).assertEqual(rowsData[0][7]);
        expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();

        let rows = await resultSet.getRows(1, 0);
        expect('zhangsan').assertEqual(rows[0].name);
        expect(18).assertEqual(rows[0].age);
        expect(25000.0).assertEqual(rows[0].data1);
        rowU8 = rows[0].data2 as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(checkAssetEqual(rows[0].data3, asset1)).assertTrue();
        expect(checkAssetsEqual(rows[0].data4, assets2)).assertTrue();
      } catch(err) {
        console.error(`queryGetRowsData_001 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_001 end *************');
    })

    /**
     * @tc.number queryGetRowsData_002
     * @tc.name normal test case of getRowsData
     * @tc.desc multi-table querySql with getRowsData and getRows comparison test
     *          1. query all data
     *          2. execute getRowsData and getRows
     *          3. compare the values returned by the two methods
     */
    it('queryGetRowsData_002', 0, async  () => {
      console.log(TAG + '************* queryGetRowsData_002 start *************');
      let u8 = new Uint8Array([1, 2, 3]);
      const assets2 = [asset1, asset2];
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        let querySQL = 'SELECT test.id AS test_id, test.name AS test_name, test.age AS test_age, ' +
          'test.data1, test.data2, test1.id AS test1_id, test1.name AS test1_name, test1.age AS test1_age, ' +
          'test1.data3, test1.data4 FROM test INNER JOIN test1 ON test.id = test1.id;'
        resultSet = await rdbStore.querySql(querySQL);
        let asRowsData = await resultSet.getRowsData(1);
        expect(1).assertEqual(asRowsData.length);
        expect(10).assertEqual(asRowsData[0].length);
        expect(1).assertEqual(asRowsData[0][0]);
        expect('zhangsan').assertEqual(asRowsData[0][1]);
        expect(18).assertEqual(asRowsData[0][2]);
        expect(25000.0).assertEqual(asRowsData[0][3]);
        let rowU8 = asRowsData[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(asRowsData[0][5]);
        expect('liming').assertEqual(asRowsData[0][6]);
        expect(22).assertEqual(asRowsData[0][7]);
        expect(checkAssetEqual(asRowsData[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(asRowsData[0][9], assets2)).assertTrue();
        let asRows = await resultSet.getRows(1, 0);
        expect('zhangsan').assertEqual(asRows[0].test_name);
        expect(18).assertEqual(asRows[0].test_age);
        expect(25000.0).assertEqual(asRows[0].data1);
        rowU8 = asRows[0].data2 as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect('liming').assertEqual(asRows[0].test1_name);
        expect(22).assertEqual(asRows[0].test1_age);
        expect(checkAssetEqual(asRows[0].data3, asset1)).assertTrue();
        expect(checkAssetsEqual(asRows[0].data4, assets2)).assertTrue();
      } catch(err) {
        console.error(`queryGetRowsData_002 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_002 end *************');
    })

    /**
     * @tc.number queryGetRowsData_003
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet already close.
     *          1. execute querySql and close resultSet
     *          2. return 14800014
     */
    it('queryGetRowsData_003', 0, async  () => {
      console.log(TAG + '************* queryGetRowsData_003 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        resultSet?.close();
        await resultSet.getRowsData(1);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetRowsData_003 failed message:${err.message} code:${err.code}`);
        expect('14800014').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_003 end *************');
    })

    /**
     * @tc.number queryGetRowsData_004
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet querySql no such table.
     *          1. not create table and execute querySql
     *          2. return 14800021
     */
    it('queryGetRowsData_004', 0, async  () => {
      console.log(TAG + '************* queryGetRowsData_004 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test2');
        await resultSet.getRowsData(1);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetRowsData_004 failed message:${err.message} code:${err.code}`);
        expect(14800021).assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_004 end *************');
    })

    /**
     * @tc.number queryGetRowsData_005
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet querySql input create table sql.
     *          1. create table by querySql method
     *          2. return 14800021
     */
    it('queryGetRowsData_005', 0, async  () => {
      console.log(TAG + '************* queryGetRowsData_005 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql(CREATE_TABLE_TEST);
        await resultSet.getRowsData(1);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetRowsData_005 failed message:${err.message} code:${err.code}`);
        expect(14800019).assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_005 end *************');
    })

    /**
     * @tc.number queryGetRowsData_006
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet querySql input sql size less then 3.
     *          1. execute querySql, SQL length is less than 3
     *          2. return 14800001
     */
    it('queryGetRowsData_006', 0, async  () => {
      console.log(TAG + '************* queryGetRowsData_006 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('se');
        await resultSet.getRowsData(1);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetRowsData_006 failed message:${err.message} code:${err.code}`);
        expect(14800001).assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_006 end *************');
    })

    /**
     * @tc.number queryGetRowsData_007
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with resultSet is empty.
     *          1. execute querySql
     *          2. no data and return 14800012
     */
    it('queryGetRowsData_007',  0, async  () => {
      console.log(TAG + '************* queryGetRowsData_007 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test where id = 3');
        await resultSet.getRowsData(1, 1);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetRowsData_007 failed message:${err.message} code:${err.code}`);
        expect(14800012).assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_007 end *************');
    })

    /**
     * @tc.number queryGetRowsData_008
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount out of resultSet rows.
     */
    it('queryGetRowsData_008',  0, async  () => {
      console.log(TAG + '************* queryGetRowsData_008 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        let rowsDataAll = await resultSet.getRowsData(4);
        expect(2).assertEqual(rowsDataAll.length);
        expect(10).assertEqual(rowsDataAll[0].length);
        expect(10).assertEqual(rowsDataAll[1].length);
        expect(1).assertEqual(rowsDataAll[0][0]);
        expect('zhangsan').assertEqual(rowsDataAll[0][1]);
        expect(18).assertEqual(rowsDataAll[0][2]);
        expect(25000.0).assertEqual(rowsDataAll[0][3]);
        let rowU8 = rowsDataAll[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(rowsDataAll[0][5]);
        expect('liming').assertEqual(rowsDataAll[0][6]);
        expect(22).assertEqual(rowsDataAll[0][7]);
        expect(checkAssetEqual(rowsDataAll[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(rowsDataAll[0][9], assets2)).assertTrue();
        expect(2).assertEqual(rowsDataAll[1][0]);
        expect('lisi').assertEqual(rowsDataAll[1][1]);
        expect(20).assertEqual(rowsDataAll[1][2]);
        expect(20000.0).assertEqual(rowsDataAll[1][3]);
        rowU8 = rowsDataAll[1][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(2).assertEqual(rowsDataAll[1][5]);
        expect('lifei').assertEqual(rowsDataAll[1][6]);
        expect(24).assertEqual(rowsDataAll[1][7]);
        expect(checkAssetEqual(rowsDataAll[1][8], asset1)).assertTrue();
        expect(checkAssetsEqual(rowsDataAll[1][9], assets2)).assertTrue();
      } catch(err) {
        console.error(`queryGetRowsData_008 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_008 end *************');
    })

    /**
     * @tc.number queryGetRowsData_009
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount is -1.
     *          1. maxCount is less than 0
     *          2. return 14800001
     */
    it('queryGetRowsData_009',  0, async  () => {
      console.log(TAG + '************* queryGetRowsData_009 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test where id = 1');
        await resultSet.getRowsData(-1);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetRowsData_009 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_009 end *************');
    })

    /**
     * @tc.number queryGetRowsData_010
     * @tc.name abnormal attach db test case of getRowsData
     * @tc.desc ResultSet.getRowsData test with attach db querySql.
     */
    it('queryGetRowsData_010',  0, async  () => {
      console.log(TAG + '************* queryGetRowsData_010 start *************');
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach('/data/storage/el2/database/rdb/rdbQueryResultSet.db', 'attachDB2');
      expect(count == 1).assertTrue();
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStoreAttach.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3])
        const assets2 = [asset1, asset2];
        let rowsData = await resultSet.getRowsData(1, 0);
        expect(1).assertEqual(rowsData.length);
        expect(10).assertEqual(rowsData[0].length);
        expect(1).assertEqual(rowsData[0][0]);
        expect('zhangsan').assertEqual(rowsData[0][1]);
        expect(18).assertEqual(rowsData[0][2]);
        expect(25000.0).assertEqual(rowsData[0][3]);
        let rowU8 = rowsData[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(rowsData[0][5]);
        expect('liming').assertEqual(rowsData[0][6]);
        expect(22).assertEqual(rowsData[0][7]);
        expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();
      } catch(err) {
        console.error(`queryGetRowsData_010 failed message:${err.message} code:${err.code}`);
        expect().assertFalse();
      }
      resultSet?.close();
      await rdbStoreAttach.detach('attachDB2');
      await rdbStoreAttach.close();
      console.log(TAG + '************* queryGetRowsData_010 end *************');
    })

    /**
     * @tc.number queryGetRowsData_011
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount and position are -1.
     *          1. both maxCount and position are less than 0
     *          2. return 14800001
     */
    it('queryGetRowsData_011',  0, async  () => {
      console.log(TAG + '************* queryGetRowsData_011 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test where id = 1');
        await resultSet.getRowsData(-1, -1);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetRowsData_011 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_011 end *************');
    })

    /**
     * @tc.number queryGetRowsData_012
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount -1 and position is 0.
     */
    it('queryGetRowsData_012',  0, async  () => {
      console.log(TAG + '************* queryGetRowsData_012 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test where id = 1');
        await resultSet.getRowsData(-1, 0);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetRowsData_012 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_012 end *************');
    })

    /**
     * @tc.number queryGetRowsData_013
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test, maxCount is 1, position is 1.
     */
    it('queryGetRowsData_013',  0, async  () => {
      console.log(TAG + '************* queryGetRowsData_013 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        let rowsData = await resultSet.getRowsData(1, 1);
        expect(1).assertEqual(rowsData.length);
        expect(10).assertEqual(rowsData[0].length);
        expect(1).assertEqual(rowsData.length);
        expect(2).assertEqual(rowsData[0][0]);
        expect('lisi').assertEqual(rowsData[0][1]);
        expect(20).assertEqual(rowsData[0][2]);
        expect(20000.0).assertEqual(rowsData[0][3]);
        let rowU8 = rowsData[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(2).assertEqual(rowsData[0][5]);
        expect('lifei').assertEqual(rowsData[0][6]);
        expect(24).assertEqual(rowsData[0][7]);
        expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();
      } catch(err) {
        console.error(`queryGetRowsData_013 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_013 end *************');
    })

    /**
     * @tc.number queryGetRowsData_014
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount 0.
     */
    it('queryGetRowsData_014',  0, async  () => {
      console.log(TAG + '************* queryGetRowsData_014 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test where id = 1');
        await resultSet.getRowsData(0);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetRowsData_014 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetRowsData_014 end *************');
    })

    /**
     * @tc.number queryGetColumnNames_001
     * @tc.name normal test case of getColumnNames
     * @tc.desc multi-table for query all column names by getColumnNames
     */
    it('queryGetColumnNames_001', 0, async  () => {
      console.log(TAG + '************* queryGetColumnNames_001 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let columnNames = resultSet.getColumnNames();
        expect(10).assertEqual(columnNames.length);
        expect('id').assertEqual(columnNames[0]);
        expect('name').assertEqual(columnNames[1]);
        expect('age').assertEqual(columnNames[2]);
        expect('data1').assertEqual(columnNames[3]);
        expect('data2').assertEqual(columnNames[4]);
        expect('id').assertEqual(columnNames[5]);
        expect('name').assertEqual(columnNames[6]);
        expect('age').assertEqual(columnNames[7]);
        expect('data3').assertEqual(columnNames[8]);
        expect('data4').assertEqual(columnNames[9]);
      } catch(err) {
        console.error(`queryGetColumnNames_001 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetColumnNames_001 end *************');
    })

    /**
     * @tc.number queryGetColumnNames_002
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc getColumnNames test with resultSet already close.
     *          1. close resultSet and execute getColumnNames
     *          2. return 14800014
     */
    it('queryGetColumnNames_002', 0, async  () => {
      console.log(TAG + '************* queryGetColumnNames_002 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        resultSet?.close();
        resultSet.getColumnNames();
        console.error(`queryGetColumnNames_002 success`);
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetColumnNames_002 failed message:${err.message} code:${err.code}`);
        expect('14800014').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetColumnNames_002 end *************');
    })

    /**
     * @tc.number queryGetColumnNames_003
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc getColumnNames test with resultSet querySql no such table.
     *          1. not create table and execute getColumnNames
     *          2. return 14800021
     */
    it('queryGetColumnNames_003', 0, async  () => {
      console.log(TAG + '************* queryGetColumnNames_003 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('SELECT * FROM test2');
        resultSet.getColumnNames();
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetColumnNames_003 failed message:${err.message} code:${err.code}`);
        expect('14800021').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetColumnNames_003 end *************');
    })

    /**
     * @tc.number queryGetColumnNames_004
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc getColumnNames test with resultSet querySql input create table sql.
     *          1. create table by querySql and execute getColumnNames
     *          2. return 14800019
     */
    it('queryGetColumnNames_004', 0, async  () => {
      console.log(TAG + '************* queryGetColumnNames_004 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql(CREATE_TABLE_TEST);
        resultSet.getColumnNames();
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetColumnNames_004 failed message:${err.message} code:${err.code}`);
        expect('14800019').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetColumnNames_004 end *************');
    })

    /**
     * @tc.number queryGetColumnNames_005
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc getColumnNames test with resultSet querySql input sql size less then 3.
     *          1. SQL length is less than 3
     *          2. execute getColumnNames and return 14800001
     */
    it('queryGetColumnNames_005', 0, async  () => {
      console.log(TAG + '************* queryGetColumnNames_005 start *************');
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore.querySql('se');
        resultSet.getColumnNames();
        expect().assertFail();
      } catch(err) {
        console.error(`queryGetColumnNames_005 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      resultSet?.close();
      console.log(TAG + '************* queryGetColumnNames_005 end *************');
    })

    /**
     * @tc.number queryGetColumnNames_006
     * @tc.name normal attach db test case of getColumnNames
     * @tc.desc ResultSet.getColumnNames test with attach db querySql.
     */
    it('queryGetColumnNames_006', 0, async  () => {
      console.log(TAG + '************* queryGetColumnNames_006 start *************');
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach('/data/storage/el2/database/rdb/rdbQueryResultSet.db', 'attachDB3');
      expect(count == 1).assertTrue();
      let resultSet: relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStoreAttach.querySql('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let columnNames = resultSet.getColumnNames();
        expect(10).assertEqual(columnNames.length);
        expect('id').assertEqual(columnNames[0]);
        expect('name').assertEqual(columnNames[1]);
        expect('age').assertEqual(columnNames[2]);
        expect('data1').assertEqual(columnNames[3]);
        expect('data2').assertEqual(columnNames[4]);
        expect('id').assertEqual(columnNames[5]);
        expect('name').assertEqual(columnNames[6]);
        expect('age').assertEqual(columnNames[7]);
        expect('data3').assertEqual(columnNames[8]);
        expect('data4').assertEqual(columnNames[9]);
      } catch(err) {
        console.error(`queryGetColumnNames_006 failed message:${err.message} code:${err.code}`);
        expect().assertFalse();
      }
      resultSet?.close();
      await rdbStoreAttach.detach('attachDB3');
      await rdbStoreAttach.close();
      console.log(TAG + '************* queryGetColumnNames_006 end *************');
    })

    /**
     * @tc.number lite_queryCurrentRowData_001
     * @tc.name normal test case of getCurrentRowData
     * @tc.desc multi-table querySqlWithoutRowCount with getCurrentRowData and getRow comparison test
     *          1. query all data, using 'select * from ....'
     *          2. execute getCurrentRowData and getRow
     *          3. compare the values returned by the two methods
     */
    it('lite_queryCurrentRowData_001',  0, async  () => {
      console.log(TAG + '************* lite_queryCurrentRowData_001 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await
          rdbStore.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        expect(liteResultSet.goToNextRow()).assertTrue();

        let liteRow = liteResultSet.getRow();
        expect('zhangsan').assertEqual(liteRow.name);
        expect(18).assertEqual(liteRow.age);
        expect(25000.0).assertEqual(liteRow.data1);
        let rowU8 = liteRow.data2 as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(checkAssetEqual(liteRow.data3, asset1)).assertTrue();
        expect(checkAssetsEqual(liteRow.data4, assets2)).assertTrue();

        let liteRowData = liteResultSet.getCurrentRowData();
        expect(10).assertEqual(liteRowData.length);
        expect(1).assertEqual(liteRowData[0]);
        expect('zhangsan').assertEqual(liteRowData[1]);
        expect(18).assertEqual(liteRowData[2]);
        expect(25000.0).assertEqual(liteRowData[3]);
        rowU8 = liteRowData[4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(liteRowData[5]);
        expect('liming').assertEqual(liteRowData[6]);
        expect(22).assertEqual(liteRowData[7]);
        expect(checkAssetEqual(liteRowData[8], asset1)).assertTrue();
        expect(checkAssetsEqual(liteRowData[9], assets2)).assertTrue();
      } catch(err) {
        console.error(`lite_queryCurrentRowData_001 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryCurrentRowData_001 end *************');
    })

    /**
     * @tc.number lite_queryCurrentRowData_002
     * @tc.name normal test case of getCurrentRowData
     * @tc.desc multi-table querySqlWithoutRowCount with getCurrentRowData and getRow comparison test
     *          1. query all data
     *          2. execute getCurrentRowData and getRow
     *          3. compare the values returned by the two methods
     */
    it('lite_queryCurrentRowData_002',  0, async  () => {
      console.log(TAG + '************* lite_queryCurrentRowData_002 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        let querySQL = 'SELECT test.id AS test_id, test.name AS test_name, test.age AS test_age, ' +
          'test.data1, test.data2, test1.id AS test1_id, test1.name AS test1_name, test1.age AS test1_age, ' +
          'test1.data3, test1.data4 FROM test INNER JOIN test1 ON test.id = test1.id;'
        liteResultSet = await rdbStore.querySqlWithoutRowCount(querySQL);
        liteResultSet.goToNextRow();
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];

        let asLiteRowData = liteResultSet.getCurrentRowData();
        expect(10).assertEqual(asLiteRowData.length);
        expect(1).assertEqual(asLiteRowData[0]);
        expect('zhangsan').assertEqual(asLiteRowData[1]);
        expect(18).assertEqual(asLiteRowData[2]);
        expect(25000.0).assertEqual(asLiteRowData[3]);
        let rowU8 = asLiteRowData[4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(asLiteRowData[5]);
        expect('liming').assertEqual(asLiteRowData[6]);
        expect(22).assertEqual(asLiteRowData[7]);
        expect(checkAssetEqual(asLiteRowData[8], asset1)).assertTrue();
        expect(checkAssetsEqual(asLiteRowData[9], assets2)).assertTrue();

        let asLiteRow = liteResultSet.getRow();
        expect('zhangsan').assertEqual(asLiteRow.test_name);
        expect(18).assertEqual(asLiteRow.test_age);
        expect(25000.0).assertEqual(asLiteRow.data1);
        rowU8 = asLiteRow.data2 as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect('liming').assertEqual(asLiteRow.test1_name);
        expect(22).assertEqual(asLiteRow.test1_age);
        expect(checkAssetEqual(asLiteRow.data3, asset1)).assertTrue();
        expect(checkAssetsEqual(asLiteRow.data4, assets2)).assertTrue();
      } catch(err) {
        console.error(`lite_queryCurrentRowData_002 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryCurrentRowData_002 end *************');
    })

    /**
     * @tc.number lite_queryCurrentRowData_003
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc liteResultSet.getCurrentRowData test with liteResultSet already close.
     *          1. close resultSet and execute getCurrentRowData
     *          2. return 14800014
     */
    it('lite_queryCurrentRowData_003',  0, async  () => {
      console.log(TAG + '************* lite_queryCurrentRowData_003 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await
          rdbStore.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        liteResultSet?.close();
        liteResultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryCurrentRowData_003 failed message:${err.message} code:${err.code}`);
        expect('14800014').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryCurrentRowData_003 end *************');
    })

    /**
     * @tc.number lite_queryCurrentRowData_004
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc liteResultSet.getCurrentRowData test with querySqlWithoutRowCount no such table.
     *          1. not create table and execute getCurrentRowData
     *          2. return 14800021
     */
    it('lite_queryCurrentRowData_004',  0, async  () => {
      console.log(TAG + '************* lite_queryCurrentRowData_004 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('SELECT * FROM test2');
        liteResultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryCurrentRowData_004 failed message:${err.message} code:${err.code}`);
        expect('14800021').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryCurrentRowData_004 end *************');
    })

    /**
     * @tc.number lite_queryCurrentRowData_005
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc liteResultSet.getCurrentRowData test with querySqlWithoutRowCount input create table sql.
     *          1. create table by querySqlWithoutRowCount
     *          2. execute getCurrentRowData and return 14800021
     */
    it('lite_queryCurrentRowData_005',  0, async  () => {
      console.log(TAG + '************* lite_queryCurrentRowData_005 start *************');
      let liteResultSet : relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount(CREATE_TABLE_TEST);
        liteResultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryCurrentRowData_005 failed message:${err.message} code:${err.code}`);
        expect('14800019').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryCurrentRowData_005 end *************');
    })

    /**
     * @tc.number lite_queryCurrentRowData_006
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc liteResultSet.getCurrentRowData test with querySqlWithoutRowCount input sql size less then 3.
     *          1. SQL length is less than 3
     *          2. execute getCurrentRowData and return 14800021
     */
    it('lite_queryCurrentRowData_006',  0, async  () => {
      console.log(TAG + '************* lite_queryCurrentRowData_006 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('se');
        liteResultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryCurrentRowData_006 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryCurrentRowData_006 end *************');
    })

    /**
     * @tc.number lite_queryCurrentRowData_007
     * @tc.name abnormal test case of getCurrentRowData
     * @tc.desc getCurrentRowData test with liteResultSet is empty.
     *          1. no data and execute getCurrentRowData
     *          2. return 14800012
     */
    it('lite_queryCurrentRowData_007',  0, async  () => {
      console.log(TAG + '************* lite_queryCurrentRowData_007 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('SELECT * FROM test where id = 2');
        liteResultSet.getCurrentRowData();
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryCurrentRowData_007 failed message:${err.message} code:${err.code}`);
        expect('14800012').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryCurrentRowData_007 end *************');
    })

    /**
     * @tc.number lite_queryCurrentRowData_008
     * @tc.name abnormal attach db test case of CurrentRowData
     * @tc.desc ResultSet.CurrentRowData test with attach db querySql.
     *          1. execute attach and querySql
     *          2. get all values
     */
    it('lite_queryCurrentRowData_008',  0, async  () => {
      console.log(TAG + '************* lite_queryCurrentRowData_008 start *************');
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach('/data/storage/el2/database/rdb/rdbQueryResultSet.db', 'attachDB4');
      expect(1).assertEqual(count);
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await
          rdbStoreAttach.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3])
        const assets2 = [asset1, asset2];
        expect(true).assertEqual(liteResultSet.goToNextRow());

        let liteRowData = liteResultSet.getCurrentRowData();
        expect(10).assertEqual(liteRowData.length);
        expect(1).assertEqual(liteRowData[0]);
        expect('zhangsan').assertEqual(liteRowData[1]);
        expect(18).assertEqual(liteRowData[2]);
        expect(25000.0).assertEqual(liteRowData[3]);
        let rowU8 = liteRowData[4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(liteRowData[5]);
        expect('liming').assertEqual(liteRowData[6]);
        expect(22).assertEqual(liteRowData[7]);
        expect(checkAssetEqual(liteRowData[8], asset1)).assertTrue();
        expect(checkAssetsEqual(liteRowData[9], assets2)).assertTrue();
      } catch(err) {
        console.error(`lite_queryCurrentRowData_008 failed message:${err.message} code:${err.code}`);
        expect().assertFalse();
      }
      liteResultSet?.close();
      await rdbStoreAttach.detach('attachDB4');
      await rdbStoreAttach.close();
      console.log(TAG + '************* lite_queryCurrentRowData_008 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_001
     * @tc.name normal test case of getRowsData
     * @tc.desc multi-table querySqlWithoutRowCount with getRowsData and getRows comparison test
     *          1. query all data, using 'select * from ...'
     *          2. execute getRows and getRowsData
     *          3. compare the values returned by the two methods
     */
    it('lite_queryGetRowsData_001', 0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_001 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];

        let liteRowsData = await liteResultSet.getRowsData(1, 0);
        expect(1).assertEqual(liteRowsData.length);
        expect(10).assertEqual(liteRowsData[0].length);
        expect(1).assertEqual(liteRowsData[0][0]);
        expect('zhangsan').assertEqual(liteRowsData[0][1]);
        expect(18).assertEqual(liteRowsData[0][2]);
        expect(25000.0).assertEqual(liteRowsData[0][3]);
        let rowU8 = liteRowsData[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(liteRowsData[0][5]);
        expect('liming').assertEqual(liteRowsData[0][6]);
        expect(22).assertEqual(liteRowsData[0][7]);
        expect(checkAssetEqual(liteRowsData[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(liteRowsData[0][9], assets2)).assertTrue();

        let liteRows = await liteResultSet.getRows(1, 0);
        expect(1).assertEqual(liteRows[0].id);
        expect('zhangsan').assertEqual(liteRows[0].name);
        expect(18).assertEqual(liteRows[0].age);
        expect(25000.0).assertEqual(liteRows[0].data1);
        rowU8 = liteRows[0].data2 as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(checkAssetEqual(liteRows[0].data3, asset1)).assertTrue();
        expect(checkAssetsEqual(liteRows[0].data4, assets2)).assertTrue();
      } catch(err) {
        console.error(`lite_queryGetRowsData_001 failed message:${err.message} code:${err.code}`);
        liteResultSet?.close();
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_001 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_002
     * @tc.name normal test case of getRowsData
     * @tc.desc multi-table querySqlWithoutRowCount with getRowsData and getRows comparison test
     *          1. query all data
     *          2. execute getRows and getRowsData
     *          3. compare the values returned by the two methods
     */
    it('lite_queryGetRowsData_002', 0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_002 start *************');
      let u8 = new Uint8Array([1, 2, 3]);
      const assets2 = [asset1, asset2];
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        let querySQL = 'SELECT test.id AS test_id, test.name AS test_name, test.age AS test_age, ' +
          'test.data1, test.data2, test1.id AS test1_id, test1.name AS test1_name, test1.age AS test1_age, ' +
          'test1.data3, test1.data4 FROM test INNER JOIN test1 ON test.id = test1.id;'
        liteResultSet = await rdbStore.querySqlWithoutRowCount(querySQL);

        let liteAsRowsData = await liteResultSet.getRowsData(1);
        expect(1).assertEqual(liteAsRowsData.length);
        expect(10).assertEqual(liteAsRowsData[0].length);
        expect(1).assertEqual(liteAsRowsData[0][0]);
        expect('zhangsan').assertEqual(liteAsRowsData[0][1]);
        expect(18).assertEqual(liteAsRowsData[0][2]);
        expect(25000.0).assertEqual(liteAsRowsData[0][3]);
        let rowU8 = liteAsRowsData[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(liteAsRowsData[0][5]);
        expect('liming').assertEqual(liteAsRowsData[0][6]);
        expect(22).assertEqual(liteAsRowsData[0][7]);
        expect(checkAssetEqual(liteAsRowsData[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(liteAsRowsData[0][9], assets2)).assertTrue();

        let liteAsRows = await liteResultSet.getRows(1, 0);
        expect('zhangsan').assertEqual(liteAsRows[0].test_name);
        expect(18).assertEqual(liteAsRows[0].test_age);
        expect(25000.0).assertEqual(liteAsRows[0].data1);
        rowU8 = liteAsRows[0].data2 as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect('liming').assertEqual(liteAsRows[0].test1_name);
        expect(22).assertEqual(liteAsRows[0].test1_age);
        expect(true).assertEqual(checkAssetEqual(liteAsRows[0].data3, asset1));
        expect(true).assertEqual(checkAssetsEqual(liteAsRows[0].data4, assets2));
      } catch(err) {
        console.error(`lite_queryGetRowsData_002 failed message:${err.message} code:${err.code}`);
        liteResultSet?.close();
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_002 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_003
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with liteResultSet already close.
     *          1. close resultSet
     *          2. execute getRowsData and return 14800014
     */
    it('lite_queryGetRowsData_003', 0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_003 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        liteResultSet?.close();
        await liteResultSet.getRowsData(1);
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetRowsData_003 failed message:${err.message} code:${err.code}`);
        expect('14800014').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_003 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_004
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with querySqlWithoutRowCount no such table.
     *          1. not create table
     *          2. execute getRowsData and return 14800021
     */
    it('lite_queryGetRowsData_004', 0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_004 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('SELECT * FROM test2');
        await liteResultSet.getRowsData(1);
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetRowsData_004 failed message:${err.message} code:${err.code}`);
        expect(14800021).assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_004 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_005
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with querySqlWithoutRowCount input create table sql.
     *          1. create table by querySqlWithoutRowCount
     *          2. execute getRowsData and return 14800021
     */
    it('lite_queryGetRowsData_005', 0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_005 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount(CREATE_TABLE_TEST);
        await liteResultSet.getRowsData(1);
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetRowsData_005 failed message:${err.message} code:${err.code}`);
        expect(14800019).assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_005 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_006
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with querySqlWithoutRowCount input sql size less then 3.
     *          1. SQL length is less than 3
     *          2. execute getRowsData and return 14800001
     */
    it('lite_queryGetRowsData_006', 0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_006 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('se');
        await liteResultSet.getRowsData(1);
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetRowsData_006 failed message:${err.message} code:${err.code}`);
        expect(14800001).assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_006 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_007
     * @tc.name abnormal test case of getRowsData
     * @tc.desc liteResultSet.getRowsData test with resultSet is empty.
     *          1. no data in resultSet
     *          2. execute getRowsData and return 14800012
     */
    it('lite_queryGetRowsData_007', 0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_007 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('SELECT * FROM test where id = 3');
        await liteResultSet.getRowsData(1, 1);
      } catch(err) {
        console.error(`lite_queryGetRowsData_007 failed message:${err.message} code:${err.code}`);
        expect(14800012).assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_006 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_008
     * @tc.name normal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount out of liteResultSet rows.
     */
    it('lite_queryGetRowsData_008',  0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_008 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];

        let liteRowsDataAll = await liteResultSet.getRowsData(4);
        expect(2).assertEqual(liteRowsDataAll.length);
        expect(10).assertEqual(liteRowsDataAll[0].length);
        expect(10).assertEqual(liteRowsDataAll[1].length);
        expect(1).assertEqual(liteRowsDataAll[0][0]);
        expect('zhangsan').assertEqual(liteRowsDataAll[0][1]);
        expect(18).assertEqual(liteRowsDataAll[0][2]);
        expect(25000.0).assertEqual(liteRowsDataAll[0][3]);
        let rowU8 = liteRowsDataAll[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(liteRowsDataAll[0][5]);
        expect('liming').assertEqual(liteRowsDataAll[0][6]);
        expect(22).assertEqual(liteRowsDataAll[0][7]);
        expect(checkAssetEqual(liteRowsDataAll[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(liteRowsDataAll[0][9], assets2)).assertTrue();
        expect(2).assertEqual(liteRowsDataAll[1][0]);
        expect('lisi').assertEqual(liteRowsDataAll[1][1]);
        expect(20).assertEqual(liteRowsDataAll[1][2]);
        expect(20000.0).assertEqual(liteRowsDataAll[1][3]);
        rowU8 = liteRowsDataAll[1][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(2).assertEqual(liteRowsDataAll[1][5]);
        expect('lifei').assertEqual(liteRowsDataAll[1][6]);
        expect(24).assertEqual(liteRowsDataAll[1][7]);
        expect(checkAssetEqual(liteRowsDataAll[1][8], asset1)).assertTrue();
        expect(checkAssetsEqual(liteRowsDataAll[1][9], assets2)).assertTrue();
      } catch(err) {
        console.error(`lite_queryGetRowsData_008 failed message:${err.message} code:${err.code}`);
        liteResultSet?.close();
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_008 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_009
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount is -1.
     */
    it('lite_queryGetRowsData_009',  0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_009 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('SELECT * FROM test where id = 1');
        await liteResultSet.getRowsData(-1);
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetRowsData_009 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_009 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_010
     * @tc.name abnormal attach db test case of getRowsData
     * @tc.desc LiteResultSet.getRowsData test with attach db querySqlWithoutRowCount.
     */
    it('lite_queryGetRowsData_010',  0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_010 start *************');
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach('/data/storage/el2/database/rdb/rdbQueryResultSet.db', 'attachDB5');
      expect(1).assertEqual(count);
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStoreAttach.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3])
        const assets2 = [asset1, asset2];
        let rowsData = await liteResultSet.getRowsData(1, 0);
        expect(1).assertEqual(rowsData.length);
        expect(10).assertEqual(rowsData[0].length);
        expect(1).assertEqual(rowsData[0][0]);
        expect('zhangsan').assertEqual(rowsData[0][1]);
        expect(18).assertEqual(rowsData[0][2]);
        expect(25000.0).assertEqual(rowsData[0][3]);
        let rowU8 = rowsData[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(1).assertEqual(rowsData[0][5]);
        expect('liming').assertEqual(rowsData[0][6]);
        expect(22).assertEqual(rowsData[0][7]);
        expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();
      } catch(err) {
        console.error(`lite_queryGetRowsData_010 failed message:${err.message} code:${err.code}`);
        await rdbStoreAttach.detach('attachDB5');
        expect(false).assertTrue();
      }
      liteResultSet?.close();
      await rdbStoreAttach.detach('attachDB5');
      await rdbStoreAttach.close();
      console.log(TAG + '************* lite_queryGetRowsData_010 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_011
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount and position are -1.
     */
    it('lite_queryGetRowsData_011',  0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_011 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('SELECT * FROM test where id = 1');
        await liteResultSet.getRowsData(-1, -1);
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetRowsData_011 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_011 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_012
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount -1 and position is 0.
     */
    it('lite_queryGetRowsData_012',  0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_012 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('SELECT * FROM test where id = 1');
        await liteResultSet.getRowsData(-1, 0);
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetRowsData_012 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_012 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_013
     * @tc.name normal test case of getRowsData
     * @tc.desc getRowsData test for liteResultSet, maxCount is 1, position is 1.
     */
    it('lite_queryGetRowsData_013',  0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_013 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let u8 = new Uint8Array([1, 2, 3]);
        const assets2 = [asset1, asset2];
        let rowsData = await liteResultSet.getRowsData(1,1);
        expect(1).assertEqual(rowsData.length);
        expect(10).assertEqual(rowsData[0].length);
        expect(2).assertEqual(rowsData[0][0]);
        expect('lisi').assertEqual(rowsData[0][1]);
        expect(20).assertEqual(rowsData[0][2]);
        expect(20000.0).assertEqual(rowsData[0][3]);
        let rowU8 = rowsData[0][4] as Uint8Array;
        for(let i = 0; i < u8.length; ++i) {
          expect(u8[i]).assertEqual(rowU8[i]);
        }
        expect(2).assertEqual(rowsData[0][5]);
        expect('lifei').assertEqual(rowsData[0][6]);
        expect(24).assertEqual(rowsData[0][7]);
        expect(checkAssetEqual(rowsData[0][8], asset1)).assertTrue();
        expect(checkAssetsEqual(rowsData[0][9], assets2)).assertTrue();
      } catch(err) {
        console.error(`lite_queryGetRowsData_013 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_013 end *************');
    })

    /**
     * @tc.number lite_queryGetRowsData_014
     * @tc.name abnormal test case of getRowsData
     * @tc.desc getRowsData test with input maxCount -1 and position is 0.
     */
    it('lite_queryGetRowsData_014',  0, async  () => {
      console.log(TAG + '************* lite_queryGetRowsData_014 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('SELECT * FROM test where id = 1');
        await liteResultSet.getRowsData(0);
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetRowsData_014 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetRowsData_014 end *************');
    })

    /**
     * @tc.number lite_queryGetColumnNames_001
     * @tc.name normal test case of getColumnNames
     * @tc.desc multi-table querySqlWithoutRowCount with getColumnNames test, query all column names
     */
    it('lite_queryGetColumnNames_001', 0, async  () => {
      console.log(TAG + '************* lite_queryGetColumnNames_001 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let columnNames = liteResultSet.getColumnNames();
        expect(10).assertEqual(columnNames.length);
        expect('id').assertEqual(columnNames[0]);
        expect('name').assertEqual(columnNames[1]);
        expect('age').assertEqual(columnNames[2]);
        expect('data1').assertEqual(columnNames[3]);
        expect('data2').assertEqual(columnNames[4]);
        expect('id').assertEqual(columnNames[5]);
        expect('name').assertEqual(columnNames[6]);
        expect('age').assertEqual(columnNames[7]);
        expect('data3').assertEqual(columnNames[8]);
        expect('data4').assertEqual(columnNames[9]);
      } catch(err) {
        console.error(`lite_queryGetColumnNames_001 failed message:${err.message} code:${err.code}`);
        expect().assertFail();
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetColumnNames_001 end *************');
    })

    /**
     * @tc.number lite_queryGetColumnNames_002
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc liteResultSet.getColumnNames test with liteResultSet already close.
     *          1. close resultSet
     *          2. execute getColumnNames and return 14800014
     */
    it('lite_queryGetColumnNames_002', 0, async  () => {
      console.log(TAG + '************* lite_queryGetColumnNames_002 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        liteResultSet?.close();
        liteResultSet.getColumnNames();
        console.info(`lite_queryGetColumnNames_002 success`);
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetColumnNames_002 failed message:${err.message} code:${err.code}`);
        expect('14800014').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetColumnNames_002 end *************');
    })

    /**
     * @tc.number lite_queryGetColumnNames_003
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc liteResultSet.getColumnNames test with querySqlWithoutRowCount no such table.
     *          1. not create table
     *          2. execute getColumnNames and return 14800021
     */
    it('lite_queryGetColumnNames_003', 0, async  () => {
      console.log(TAG + '************* lite_queryGetColumnNames_003 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('SELECT * FROM test2');
        liteResultSet.getColumnNames();
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetColumnNames_003 failed message:${err.message} code:${err.code}`);
        expect('14800021').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetColumnNames_003 end *************');
    })

    /**
     * @tc.number lite_queryGetColumnNames_004
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc liteResultSet.getColumnNames test with querySqlWithoutRowCount input create table sql.
     *          1. create table by querySqlWithoutRowCount
     *          2. execute getColumnNames and return 14800021
     */
    it('lite_queryGetColumnNames_004', 0, async  () => {
      console.log(TAG + '************* lite_queryGetColumnNames_004 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount(CREATE_TABLE_TEST);
        liteResultSet.getColumnNames();
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetColumnNames_004 failed message:${err.message} code:${err.code}`);
        expect('14800019').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetColumnNames_004 end *************');
    })

    /**
     * @tc.number lite_queryGetColumnNames_005
     * @tc.name abnormal test case of getColumnNames
     * @tc.desc liteResultSet.getColumnNames test with querySqlWithoutRowCount input sql size less then 3.
     *          1. SQL length is less than 3
     *          2. execute getColumnNames and return 14800001
     */
    it('lite_queryGetColumnNames_005', 0, async  () => {
      console.log(TAG + '************* lite_queryGetColumnNames_005 start *************');
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet = await rdbStore.querySqlWithoutRowCount('se');
        liteResultSet.getColumnNames();
        expect().assertFail();
      } catch(err) {
        console.error(`lite_queryGetColumnNames_005 failed message:${err.message} code:${err.code}`);
        expect('14800001').assertEqual(err.code);
      }
      liteResultSet?.close();
      console.log(TAG + '************* lite_queryGetColumnNames_005 end *************');
    })

    /**
     * @tc.number lite_queryGetColumnNames_006
     * @tc.name normal attach db test case of getColumnNames
     * @tc.desc LiteResultSet.getColumnNames test with attach db querySqlWithoutRowCount.
     */
    it('lite_queryGetColumnNames_006', 0, async  () => {
      console.log(TAG + '************* lite_queryGetColumnNames_006 start *************');
      let rdbStoreAttach = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      let count = await rdbStoreAttach.attach('/data/storage/el2/database/rdb/rdbQueryResultSet.db', 'attachDB6');
      expect(1).assertEqual(count);
      let liteResultSet: relationalStore.LiteResultSet | undefined;
      try {
        liteResultSet =
          await rdbStore.querySqlWithoutRowCount('SELECT * FROM test INNER JOIN test1 ON test.id = test1.id');
        let columnNames = liteResultSet.getColumnNames();
        expect(10).assertEqual(columnNames.length);
        expect('id').assertEqual(columnNames[0]);
        expect('name').assertEqual(columnNames[1]);
        expect('age').assertEqual(columnNames[2]);
        expect('data1').assertEqual(columnNames[3]);
        expect('data2').assertEqual(columnNames[4]);
        expect('id').assertEqual(columnNames[5]);
        expect('name').assertEqual(columnNames[6]);
        expect('age').assertEqual(columnNames[7]);
        expect('data3').assertEqual(columnNames[8]);
        expect('data4').assertEqual(columnNames[9]);
      } catch(e) {
        console.error(`lite_queryGetColumnNames_006 failed message:${e.message} code:${e.code}`);
        expect(false).assertTrue();
      }
      liteResultSet?.close();
      await rdbStoreAttach.detach('attachDB6');
      await rdbStoreAttach.close();
      console.log(TAG + '************* lite_queryGetColumnNames_006 end *************');
    })
  })
}