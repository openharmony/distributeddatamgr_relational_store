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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import relationalStore from '@ohos.data.relationalStore'
const TAG = "[STAGE_RELATIONAL_STORE_JSKITS_TEST]";
const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "Predicates.db",
  securityLevel: relationalStore.SecurityLevel.S1,
};
const SQL_CREATE_TABLE =
  'CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER, amount INTEGER)';
let rdbStore: relationalStore.RdbStore | undefined = undefined;

async function preData():Promise<void>
{
  const INSERT_SQL =
  'INSERT INTO orders (customer_id, amount) VALUES' +
  '(1, 1500), (1, 2000), (1, 3000), (2, 800), (2, 1200), (3, 1500), (3, 2000), (3, 2500), (3, 1000)';
  await rdbStore?.executeSql(INSERT_SQL);
}

export default function RdbPredicatesEtsTest() {
  describe('rdbPredicatesEtsTest', () => {
    beforeAll(async () => {
      rdbStore = await relationalStore.getRdbStore(globalThis.abilityContext, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      console.info(TAG + 'beforeAll');
    });
    beforeEach(async () => {
      await rdbStore?.executeSql(SQL_CREATE_TABLE);
      await preData();
      console.info(TAG + 'beforeEach');
    });
    afterEach(async () => {
      await rdbStore?.executeSql('DROP TABLE IF EXISTS orders');
      console.info(TAG + 'afterEach');
    });
    afterAll(async () => {
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(globalThis.abilityContext, "Predicates.db");
      console.info(TAG + 'afterAll');
    });

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_001
     * @tc.name Verify no placeholders and pass in empty args in the scenario
     * @tc.desc 1.Execute having("total > 5000 AND count >= 3", [])
     *          2.Query data
     */
    it('testHaving001', 0, async () => {
      console.log(TAG + "************* testHaving001 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.groupBy(["customer_id"]);
        predicates.having("total > 5000 AND count >= 3", []);
        let resultSet:relationalStore.ResultSet =
            rdbStore?.querySync(predicates, ["customer_id", "COUNT(*) AS count", "SUM(amount) AS total"]) as relationalStore.ResultSet;
        console.info(TAG + 'testHaving001 rowCount ' + resultSet.rowCount);
        expect(2).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToNextRow());
        let row:relationalStore.ValuesBucket = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving001 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(1);
        expect(row.total).assertEqual(6500);
        expect(true).assertEqual(resultSet.goToNextRow());
        row = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving001 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(3);
        expect(row.total).assertEqual(7000);
        resultSet.close();
        console.log(TAG + " testHaving001 having success");
      } catch (e) {
        console.error(TAG + " testHaving001 having failed" + e);
        expect(true).assertFail();
      }
      console.log(TAG + "************* testHaving001 end   *************");
    });

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_002
     * @tc.name Verify scenarios without placeholders and without passing args
     * @tc.desc 1.Execute having("total > 5000 AND count >= 3")
     *          2.Query data
     */
    it('testHaving002', 0, async () => {
      console.log(TAG + "************* testHaving002 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.groupBy(["customer_id"]);
        predicates.having("total > 5000 AND count >= 3");
        let resultSet:relationalStore.ResultSet =
          rdbStore?.querySync(predicates, ["customer_id", "COUNT(*) AS count", "SUM(amount) AS total"]) as relationalStore.ResultSet;
        console.info(TAG + 'testHaving002 rowCount ' + resultSet.rowCount);
        expect(2).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToNextRow());
        let row:relationalStore.ValuesBucket = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving002 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(1);
        expect(row.total).assertEqual(6500);
        expect(true).assertEqual(resultSet.goToNextRow());
        row = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving002 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(3);
        expect(row.total).assertEqual(7000);
        resultSet.close();
        console.log(TAG + " testHaving002 having success");
      } catch (e) {
        console.error(TAG + " testHaving002 having failed" + e);
        expect(true).assertFail();
      }
      console.log(TAG + "************* testHaving002 end   *************");
    });

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_003
     * @tc.name Verify the absence of placeholders and null passing scenarios for args
     * @tc.desc 1.Execute having("SALARY = 1.2", null)
     *          2.Query data
     */
    it('testHaving003', 0, async () => {
      console.log(TAG + "************* testHaving003 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.groupBy(["customer_id"]);
        predicates.having("total > 5000 AND count >= 3", null);
        let resultSet:relationalStore.ResultSet =
          rdbStore?.querySync(predicates, ["customer_id", "COUNT(*) AS count", "SUM(amount) AS total"]) as relationalStore.ResultSet;
        console.info(TAG + 'testHaving003 rowCount ' + resultSet.rowCount);
        expect(2).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToNextRow());
        let row:relationalStore.ValuesBucket = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving003 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(1);
        expect(row.total).assertEqual(6500);
        expect(true).assertEqual(resultSet.goToNextRow());
        row = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving003 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(3);
        expect(row.total).assertEqual(7000);
        resultSet.close();
        console.log(TAG + " testHaving003 having success");
      } catch (e) {
        console.error(TAG + " testHaving003 having failed" + e);
        expect(true).assertFail();
      }
      console.log(TAG + "************* testHaving001 end   *************");
    });

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_004
     * @tc.name Verify the absence of placeholders and undefined passing scenarios for args
     * @tc.desc 1.Execute having("SALARY = 1.2", undefined)
     *          2.Query data
     */
    it('testHaving004', 0, async () => {
      console.log(TAG + "************* testHaving001 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.groupBy(["customer_id"]);
        predicates.having("total > 5000 AND count >= 3", undefined);
        let resultSet:relationalStore.ResultSet =
          rdbStore?.querySync(predicates, ["customer_id", "COUNT(*) AS count", "SUM(amount) AS total"]) as relationalStore.ResultSet;
        console.info(TAG + 'testHaving004 rowCount ' + resultSet.rowCount);
        expect(2).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToNextRow());
        let row:relationalStore.ValuesBucket = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving004 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(1);
        expect(row.total).assertEqual(6500);
        expect(true).assertEqual(resultSet.goToNextRow());
        row = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving004 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(3);
        expect(row.total).assertEqual(7000);
        resultSet.close();
        console.log(TAG + " testHaving004 having success");
      } catch (e) {
        console.error(TAG + " testHaving004 having failed" + e);
        expect(true).assertFail();
      }
      console.log(TAG + "************* testHaving004 end   *************");
    });

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_005
     * @tc.name Normal test case for predicate, testing 'having' passing in null condition
     * @tc.desc 1.Execute having("")
     *          2.Query data
     */
    it('testHaving005', 0, async () => {
      console.log(TAG + "************* testHaving005 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.groupBy(["customer_id"]);
        predicates.having("");
        console.log(TAG + " testHaving005 having success");
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + " testHaving005 having failed" + e);
        expect(e.code == 14800001).assertTrue();
      }
      console.log(TAG + "************* testHaving005 end   *************");
    });

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_006
     * @tc.name Test conditions for passing in illegal SQL
     * @tc.desc 1.Execute having("SALARY == 1.2")
     *          2.Query data
     */
    it('testHaving006', 0, async () => {
      console.log(TAG + "************* testHaving006 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.groupBy(["customer_id"]);
        predicates.having("SALARY == 1.2");
        let resultSet:relationalStore.ResultSet = rdbStore?.querySync(predicates) as relationalStore.ResultSet;
        expect(false).assertEqual(resultSet.goToFirstRow());
        resultSet.getRow();
        console.log(TAG + " testHaving006 having success");
        resultSet.close();
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + " testHaving006 having failed. " + e.msg + e.code);
        expect(e.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testHaving006 end   *************");
    });

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_007
     * @tc.name When there are placeholders in the test condition statement, passing in an ARG that does not match the
     * number of placeholders.
     * @tc.desc 1.Execute having(total > ? AND count >= ?", [5000])
     *          2.Query data
     */
    it('testHaving007', 0, async () => {
      console.log(TAG + "************* testHaving007 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.groupBy(["customer_id"]);
        predicates.having("total > ? AND count >= ?");
        let resultSet:relationalStore.ResultSet =
          await rdbStore?.querySync(predicates, ["customer_id", "COUNT(*) AS count", "SUM(amount) AS total"]) as relationalStore.ResultSet;
        expect(0).assertEqual(resultSet.rowCount);
        resultSet.close();
        console.log(TAG + " testHaving007 having success");
      } catch (e) {
        console.error(TAG + " testHaving007 having failed " + e);
        expect(true).assertFail();
      }
      console.log(TAG + "************* testHaving007 end   *************");
    });

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_008
     * @tc.name Call 'having' when 'group by' is missing.
     * @tc.desc Execute having(total > ? AND count >= ?", [5000, 3])
     */
    it('testHaving008', 0, async () => {
      console.log(TAG + "************* testHaving008 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.having("total > ? AND count >= ?", [5000, 3]);
        console.log(TAG + " testHaving008 having success");
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + " testHaving008 having failed" + e);
        expect(e.code == 14800001).assertTrue();
      }
      console.log(TAG + "************* testHaving008 end   *************");
    });

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_009
     * @tc.name Test using placeholder scenarios.
     * @tc.desc 1.Execute having(total > ? AND count >= ?", [5000, 3])
     *          2.Query data
     */
    it('testHaving009', 0, async () => {
      console.log(TAG + "************* testHaving009 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.groupBy(["customer_id"]);
        predicates.having("total > ? AND count >= ?", [5000, 3]);
        let resultSet:relationalStore.ResultSet =
          rdbStore?.querySync(predicates, ["customer_id", "COUNT(*) AS count", "SUM(amount) AS total"]) as relationalStore.ResultSet;
        console.info(TAG + 'testHaving009 rowCount ' + resultSet.rowCount);
        expect(2).assertEqual(resultSet.rowCount);
        expect(true).assertEqual(resultSet.goToNextRow());
        let row:relationalStore.ValuesBucket = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving009 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(1);
        expect(row.total).assertEqual(6500);
        expect(true).assertEqual(resultSet.goToNextRow());
        row = resultSet.getRow() as relationalStore.ValuesBucket;
        console.info(TAG + 'testHaving009 customer_id ' + row.customer_id + ' total ' + row.total);
        expect(row.customer_id).assertEqual(3);
        expect(row.total).assertEqual(7000);
        resultSet.close();
        console.log(TAG + " testHaving009 having success");
      } catch (e) {
        console.error(TAG + " testHaving009 having failed" + e);
        expect(true).assertFail();
      }
      console.log(TAG + "************* testHaving009 end   *************");
    });

    /**
     * @tc.number SUB_DDM_AppDataFWK_ETSRDB_Predicates_010
     * @tc.name Test using placeholder scenarios.
     * @tc.desc Multi threaded testing
     */
    it('testHaving010', 0, async (done:Function) => {
      console.log(TAG + "************* testHaving010 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("orders");
        predicates.groupBy(["customer_id"]);
        predicates.having("total > ? AND count >= ?", [5000, 3]);
        let count:number = 200;
        for (let i = 0; i <= count; ++i) {
          rdbStore?.query(predicates, ["customer_id", "COUNT(*) AS count", "SUM(amount) AS total"])
            .then((resultSet:relationalStore.ResultSet)=>{
              expect(2).assertEqual(resultSet.rowCount);
              expect(true).assertEqual(resultSet.goToNextRow());
              let row:relationalStore.ValuesBucket = resultSet.getRow() as relationalStore.ValuesBucket;
              expect(row.customer_id).assertEqual(1);
              expect(row.total).assertEqual(6500);
              expect(true).assertEqual(resultSet.goToNextRow());
              row = resultSet.getRow() as relationalStore.ValuesBucket;
              expect(row.customer_id).assertEqual(3);
              expect(row.total).assertEqual(7000);
              resultSet.close();
              count--;
              if (count == 0) {
                done();
              }
            }).catch((e:BusinessError)=>{
            console.error(TAG + " testHaving010 having failed query: " + e);
            done();
            expect(true).assertFail();
          });
        }
        console.log(TAG + " testHaving010 having success");
      } catch (e) {
        console.error(TAG + " testHaving010 having failed: " + e);
        done();
        expect(true).assertFail();
      }
      console.log(TAG + "************* testHaving010 end   *************");
    });

    console.log(TAG + "*************Unit Test End*************");
  })
}
