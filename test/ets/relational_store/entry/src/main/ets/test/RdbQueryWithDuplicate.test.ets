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
  "name text," + "age long, " + "data1 real," + "data2 blob)";

const CREATE_TABLE_TEST1 = "CREATE TABLE IF NOT EXISTS test1 (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name text," + "age long, " + "data3 real," + "data4 blob)";

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "rdbQueryResultSet.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

export default function rdbQueryResultSet() {
  describe('rdbQueryResultSet', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
      try {
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        expect(rdbStore != undefined).assertTrue();
        await rdbStore?.executeSql(CREATE_TABLE_TEST);
        await rdbStore?.executeSql(CREATE_TABLE_TEST1);
        let u8 = new Uint8Array([1, 2, 3])
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
          'data3': 25000.1,
          'data4': u8,
        };
        const valueBucket3: relationalStore.ValuesBucket = {
          'name': 'lifei',
          'age': 24,
          'data3': 20000.1,
          'data4': u8,
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
     * @tc.name Normal test case of getCurrentRowData
     * @tc.desc 1.multi-table join query getCurrentRowData.
     *          2.multi-table join query getRow.
     */
    it('queryCurrentRowData_001',  0, async  () => {
      console.log(TAG + "************* queryCurrentRowData_001 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        if (resultSet?.goToFirstRow()) {
          let u8 = new Uint8Array([1, 2, 3])
          let row = resultSet.getRow();
          expect(row["name"] == "zhangsan").assertTrue();
          expect(row["age"] == 18).assertTrue();
          expect(row["data1"] == 25000.0).assertTrue();
          let rowU8 = row["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(row["data3"] == 25000.1).assertTrue();
          rowU8 = row["data4"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
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
          expect(rowData[8] == 25000.1).assertTrue();
          rowU8 = rowData[9] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
        }
      } catch(e) {
        console.error(`queryCurrentRowData_001 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      console.log(TAG + "************* queryCurrentRowData_001 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_002
     * @tc.name Normal test case of getCurrentRowData
     * @tc.desc 1.multi-table join query getCurrentRowData.
     *          2.multi-table join query getRow.
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
          let u8 = new Uint8Array([1, 2, 3])
          let currentRowData = resultSet.getCurrentRowData();
          expect(currentRowData[0] == 1).assertTrue();
          expect(currentRowData[1] == "zhangsan").assertTrue();
          expect(currentRowData[2] == 18).assertTrue();
          expect(currentRowData[3] == 25000.0).assertTrue();
          let rowU8 = currentRowData[4] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(currentRowData[5] == 1).assertTrue();
          expect(currentRowData[6] == "liming").assertTrue();
          expect(currentRowData[7] == 22).assertTrue();
          expect(currentRowData[8] == 25000.1).assertTrue();
          rowU8 = currentRowData[9] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
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
          expect(asRow["data3"] == 25000.1).assertTrue();
          rowU8 = asRow["data4"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
        }
      } catch(e) {
        console.error(`queryCurrentRowData_002 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      console.log(TAG + "************* queryCurrentRowData_002 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_003
     * @tc.name Normal test case of getRowData
     * @tc.desc 1.result with querySql.
     *          2.getRowData test with already close.
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
      console.log(TAG + "************* queryCurrentRowData_003 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_004
     * @tc.name Normal test case of getRowData
     * @tc.desc 1.result with querySql without no such table.
     *          2.getRowData test.
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
      console.log(TAG + "************* queryCurrentRowData_004 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_005
     * @tc.name Normal test case of getRowData
     * @tc.desc 1.result with querySql user insert sql.
     *          2.getRowData test.
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
      console.log(TAG + "************* queryCurrentRowData_005 end *************");
    })

    /**
     * @tc.number queryCurrentRowData_006
     * @tc.name Normal test case of getRowData
     * @tc.desc 1.result with querySql user sql size less then 3.
     *          2.getRowData test.
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
      console.log(TAG + "************* queryCurrentRowData_006 end *************");
    })

    /**
     * @tc.number queryGetRowsData_001
     * @tc.name Normal test case of getRowsData
     * @tc.desc 1.multi-table join query getRowsData.
     *          2.multi-table join query getRows.
     */
    it('queryGetRowsData_001', 0, async  () => {
      console.log(TAG + "************* queryGetRowsData_001 start *************");
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        resultSet = await rdbStore?.querySql("SELECT * FROM test INNER JOIN test1 ON test.id = test1.id");
        let u8 = new Uint8Array([1, 2, 3])
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
          expect(rowsData[0][8] == 25000.1).assertTrue();
          rowU8 = rowsData[0][9] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          let rows = await resultSet.getRows(1);
          expect(rows[0]["name"] == "lisi").assertTrue();
          expect(rows[0]["age"] == 20).assertTrue();
          expect(rows[0]["data1"] == 20000.0).assertTrue();
          rowU8 = rows[0]["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rows[0]["data3"] == 20000.1).assertTrue();
          rowU8 = rows[0]["data4"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
        }
      } catch(e) {
        console.error(`queryGetRowsData_001 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      console.log(TAG + "************* queryGetRowsData_001 end *************");
    })

    /**
     * @tc.number queryGetRowsData_002
     * @tc.name Normal test case of getRowsData
     * @tc.desc 1.multi-table join query getRowsData.
     *          2.multi-table join query getRows.
     */
    it('queryGetRowsData_002', 0, async  () => {
      console.log(TAG + "************* queryGetRowsData_002 start *************");
      let u8 = new Uint8Array([1, 2, 3])
      let resultSet : relationalStore.ResultSet | undefined;
      try {
        let querySQL = "SELECT test.id AS test_id, test.name AS test_name, test.age AS test_age, " +
          "test.data1, test.data2, test1.id AS test1_id, test1.name AS test1_name, test1.age AS test1_age, " +
          "test1.data3, test1.data4 FROM test INNER JOIN test1 ON test.id = test1.id;"
        resultSet = await rdbStore?.querySql(querySQL);
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
          expect(rowsData[0][8] == 25000.1).assertTrue();
          rowU8 = rowsData[0][9] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          let rows = await resultSet.getRows(1);
          expect(rows[0]["test_name"] == "lisi").assertTrue();
          expect(rows[0]["test_age"] == 20).assertTrue();
          expect(rows[0]["data1"] == 20000.0).assertTrue();
          rowU8 = rows[0]["data2"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
          expect(rows[0]["test1_name"] == "lifei").assertTrue();
          expect(rows[0]["test1_age"] == 24).assertTrue();
          expect(rows[0]["data3"] == 20000.1).assertTrue();
          rowU8 = rows[0]["data4"] as Uint8Array;
          for(let i = 0; i < u8.length; ++i) {
            expect(rowU8[i] == u8[i]).assertTrue();
          }
        }
      } catch(e) {
        console.error(`queryGetRowsData_002 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      console.log(TAG + "************* queryGetRowsData_002 end *************");
    })

    /**
     * @tc.number queryGetRowsData_003
     * @tc.name Normal test case of getRowsData
     * @tc.desc 1.result with querySql.
     *          2.getRowsData test with already close.
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
      console.log(TAG + "************* queryGetRowsData_003 end *************");
    })

    /**
     * @tc.number queryGetRowsData_004
     * @tc.name Normal test case of getRowsData
     * @tc.desc 1.result with querySql without no such table.
     *          2.getRowsData test.
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
      console.log(TAG + "************* queryGetRowsData_004 end *************");
    })

    /**
     * @tc.number queryGetRowsData_005
     * @tc.name Normal test case of getRowsData
     * @tc.desc 1.result with querySql user insert sql.
     *          2.getRowsData test.
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
      console.log(TAG + "************* queryGetRowsData_005 end *************");
    })

    /**
     * @tc.number queryGetRowsData_006
     * @tc.name Normal test case of getRowsData
     * @tc.desc 1.result with querySql user sql size less then 3.
     *          2.getRowsData test.
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
      console.log(TAG + "************* queryGetRowsData_006 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_001
     * @tc.name Normal test case of queryGetColumnNames
     * @tc.desc 1.multi-table join query queryGetColumnNames.
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
          console.log(`columnNames is ${columnNames[0]}`)
        }
      } catch(e) {
        console.error(`queryGetColumnNames_001 failed message:${e.message} code:${e.code}`);
        expect().assertFail();
      }
      console.log(TAG + "************* queryGetColumnNames_001 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_002
     * @tc.name Normal test case of GetColumnNames
     * @tc.desc 1.result with querySql.
     *          2.GetColumnNames test with resultSet already close.
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
      console.log(TAG + "************* queryGetColumnNames_002 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_003
     * @tc.name Normal test case of GetColumnNames
     * @tc.desc 1.result with querySql with no such table.
     *          2.GetColumnNames test.
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
      console.log(TAG + "************* queryGetColumnNames_003 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_004
     * @tc.name Normal test case of GetColumnNames
     * @tc.desc 1.result with querySql user insert sql.
     *          2.GetColumnNames test.
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
      console.log(TAG + "************* queryGetColumnNames_004 end *************");
    })

    /**
     * @tc.number queryGetColumnNames_005
     * @tc.name Normal test case of GetColumnNames
     * @tc.desc 1.result with querySql user sql size less then 3.
     *          2.GetColumnNames test.
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
      console.log(TAG + "************* queryGetColumnNames_005 end *************");
    })
  })
}