
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


const TAG = "[STAGE_RELATIONAL_STORE_JSKITS_TEST]";
let rdbStore:relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL)";

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "rdbStore.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();


export default function PerfStatEtsTest() {
  describe('perfStatEtsTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore?.executeSql(CREATE_TABLE_TEST);
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      await rdbStore?.insert('test', valueBucket);
      await new Promise<void>(resolve => setTimeout(resolve, 1000));
    })
    afterEach(async () => {
      console.info(TAG + 'afterEach');
      try {
        rdbStore?.off('perfStat');
      } catch (err) {
        expect(err.code).assertEqual("14800014");
      }
      await relationalStore.deleteRdbStore(context, "rdbStore.db");
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    })


    /**
     * @tc.name Normal case for perfStat insert data execution time
     * @tc.number testRdbStorePerfStat_0001
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0001',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0001 start *************");
      rdbStore?.on('perfStat', async (SqlExeInfo) => {
        expect('INSERT INTO test(age,name,salary) VALUES (?,?,?)').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      })
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      let rowId = await rdbStore?.insert('test', valueBucket);
      expect(2).assertEqual(rowId);

      console.log(TAG + "************* testRdbStorePerfStat_0001 end *************");
    })

    /**
     * @tc.name Normal case for perfStat update data execution time
     * @tc.number testRdbStorePerfStat_0002
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0002',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0002 start *************");
      rdbStore?.on('perfStat', async (SqlExeInfo) => {
        expect('UPDATE test SET age=?,name=?,salary=? WHERE id = ? ').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      })

      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'lisi',
        'age': 18,
        'salary': 25000,
      };
      let predicates = new relationalStore.RdbPredicates('test');
      predicates.equalTo('id', 1);
      let rowId = await rdbStore?.update(valueBucket, predicates);
      expect(1).assertEqual(rowId);
      console.log(TAG + "************* testRdbStorePerfStat_0002 end *************");
    })

    /**
     * @tc.name Normal case for perfStat delete data execution time
     * @tc.number testRdbStorePerfStat_0003
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0003',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0003 start *************");
      rdbStore?.on('perfStat', async (SqlExeInfo) => {
        expect('DELETE FROM test WHERE id = ? ').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      })


      let predicates = new relationalStore.RdbPredicates('test');
      predicates.equalTo('id', 1);
      let rowId = await rdbStore?.delete(predicates);
      expect(1).assertEqual(rowId);
      console.log(TAG + "************* testRdbStorePerfStat_0003 end *************");
    })

    /**
     * @tc.name Normal case for perfStat executeSql data execution time
     * @tc.number testRdbStorePerfStat_0004
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0004',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0004 start *************");
      rdbStore?.on('perfStat', async (SqlExeInfo) => {
        expect('CREATE TABLE IF NOT EXISTS EMPLOYEE (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      })

      const SQL_CREATE_TABLE1 = "CREATE TABLE IF NOT EXISTS EMPLOYEE (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "name TEXT NOT NULL)"; // 建表Sql语句
      await rdbStore?.executeSql(SQL_CREATE_TABLE1)
      console.log(TAG + "************* testRdbStorePerfStat_0004 end *************");
    })

    /**
     * @tc.name Normal case for perfStat execute data execution time
     * @tc.number testRdbStorePerfStat_0005
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0005',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0005 start *************");
      rdbStore?.on('perfStat', async (SqlExeInfo) => {
        expect('PRAGMA quick_check').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      })
      await rdbStore?.execute("PRAGMA quick_check")
      console.log(TAG + "************* testRdbStorePerfStat_0005 end *************");
    })

    /**
     * @tc.name Normal case for perfStat update data execution time
     * @tc.number testRdbStorePerfStat_0006
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0006',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0006 start *************");
      rdbStore?.on('perfStat', async (SqlExeInfo) => {
        expect('SELECT * FROM test').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      })
      let predicates = new relationalStore.RdbPredicates('test');
      await rdbStore?.query(predicates);
      console.log(TAG + "************* testRdbStorePerfStat_0006 end *************");
    })

    /**
     * @tc.name Normal case for perfStat querySql data execution time
     * @tc.number testRdbStorePerfStat_0007
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0007',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0007 start *************");
      rdbStore?.on('perfStat', async (SqlExeInfo) => {
        expect('SELECT * FROM test').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      })
      await rdbStore?.querySql("SELECT * FROM test");
      console.log(TAG + "************* testRdbStorePerfStat_0007 end *************");
    })

    /**
     * @tc.name Normal case for perfStat update querySql execution time
     * @tc.number testRdbStorePerfStat_0008
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0008',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0008 start *************");
      rdbStore?.on('perfStat', async (SqlExeInfo) => {
        expect('with test1 as (select * from test) select * from test').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      })
      await rdbStore?.querySql("with test1 as (select * from test) select * from test");
      console.log(TAG + "************* testRdbStorePerfStat_0008 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0009
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0009',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0009 start *************");
      let observer1 = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect('SELECT * FROM test').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      };

      let observer2 = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect().assertFail();
      };

      rdbStore?.on('perfStat', observer1)
      await rdbStore?.querySql("SELECT * FROM test");
      // done()
      console.log(TAG + "************* testRdbStorePerfStat_0009 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0010
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0010',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0010 start *************");
      let observer1 = async (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect('SELECT * FROM test').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        await new Promise<void>(resolve => setTimeout(resolve, 2000));
        done()
      };

      let observer2 = async (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect('SELECT * FROM test').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        await new Promise<void>(resolve => setTimeout(resolve, 2000));
        done()
      };

      rdbStore?.on('perfStat', observer1)
      rdbStore?.on('perfStat', observer2)
      await rdbStore?.querySql("SELECT * FROM test");
      console.log(TAG + "************* testRdbStorePerfStat_0010 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0011
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0011',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0011 start *************");
      let observer = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect('INSERT INTO test(age,name,salary) VALUES (?,?,?)').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      };
      let observer1 = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect('INSERT INTO test(age,name,salary) VALUES (?,?,?)').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      };
      rdbStore?.on('perfStat', observer)
      rdbStore?.on('statistics', observer1)
      const valueBucket1: relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
      }
      await rdbStore?.insert("test", valueBucket1)
      rdbStore?.off('statistics')
      console.log(TAG + "************* testRdbStorePerfStat_0011 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0012
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0012',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0012 start *************");
      let observer = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect('INSERT INTO test(age,name,salary) VALUES (?,?,?)').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      };
      let observer1 = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect().assertFail();
      };
      rdbStore?.on('statistics', observer1)
      rdbStore?.off('statistics')
      await new Promise<void>(resolve => setTimeout(resolve, 1000));
      rdbStore?.on('perfStat', observer)
      const valueBucket1: relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
      }
      await rdbStore?.insert("test", valueBucket1)
      console.log(TAG + "************* testRdbStorePerfStat_0012 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0013
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0013',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0013 start *************");
      let observer = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect(SqlExeInfo.sql.length > 0).assertTrue();
        done()
      };
      let observer1 = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect().assertFail();
      };
      rdbStore?.on('perfStat', observer1)
      rdbStore?.off('perfStat')
      rdbStore?.on('statistics', observer)
      const valueBucket1: relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
      }
      await rdbStore?.insert("test", valueBucket1)
      await new Promise<void>(resolve => setTimeout(resolve, 1000));
      rdbStore?.off('statistics')
      console.log(TAG + "************* testRdbStorePerfStat_0013 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0014
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0014',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0014 start *************");
      let observer1 = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect().assertFail();
      };
      let observer2 = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect().assertFail();
      };

      rdbStore?.on('perfStat', observer1)
      rdbStore?.off('perfStat')
      rdbStore?.on('perfStat', observer2)
      rdbStore?.off('perfStat')
      await new Promise<void>(resolve => setTimeout(resolve, 1000));
      await rdbStore?.querySql("SELECT * FROM test");
      done()
      console.log(TAG + "************* testRdbStorePerfStat_0014 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0015
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0015',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0015 start *************");
      let observer1 = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect().assertFail();
      };
      let observer2 = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect('SELECT * FROM test').assertEqual(SqlExeInfo.sql[0]);
        expect(1).assertEqual(SqlExeInfo.sql.length);
        done()
      };

      rdbStore?.on('perfStat', observer1)
      rdbStore?.off('perfStat', observer1)
      rdbStore?.on('perfStat', observer2)
      await new Promise<void>(resolve => setTimeout(resolve, 1000));
      await rdbStore?.querySql("SELECT * FROM test");
      console.log(TAG + "************* testRdbStorePerfStat_0015 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0016
     * @tc.desc 1. Register callback for perfStat

     */
    it('testRdbStorePerfStat_0016',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0016 start *************");
      let store2: relationalStore.RdbStore | undefined = undefined;
      let STORE_CONFIG2: relationalStore.StoreConfig = {
        name: 'test2.db',
        securityLevel: relationalStore.SecurityLevel.S1
      };
      store2 = await relationalStore.getRdbStore(context, STORE_CONFIG2)
      await store2?.executeSql(CREATE_TABLE_TEST);
      let timerId = -1;
      let observer1 = async (sqlExecutionInfo : relationalStore.SqlExecutionInfo) => {
        expect('INSERT INTO test(age,name,salary) VALUES (?,?,?)').assertEqual(sqlExecutionInfo.sql[0]);
        expect(1).assertEqual(sqlExecutionInfo.sql.length);
        if (timerId > 0) {
          clearTimeout(timerId);
          expect().assertFail();
        }
        timerId = setTimeout(done, 2000);
      };
        rdbStore?.on('perfStat',observer1)

        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'zhangsan',
          'age': 18,
          'salary': 25000,
        };
        let rowId = await rdbStore?.insert('test', valueBucket);
        expect(2).assertEqual(rowId);
        let rowId2 = await store2?.insert('test', valueBucket);
        expect(1).assertEqual(rowId2);
      console.log(TAG + "************* testRdbStorePerfStat_0016 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0001
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0017',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0017 start *************");
      let store2: relationalStore.RdbStore | undefined = undefined;
      let STORE_CONFIG2: relationalStore.StoreConfig = {
        name: 'test2.db',
        securityLevel: relationalStore.SecurityLevel.S1
      };
      let timerId = -1;
      let observer1 = async (sqlExecutionInfo : relationalStore.SqlExecutionInfo) => {
        if (timerId = -1) {
          clearTimeout(timerId);
          expect().assertFail();
        }
      };
      rdbStore?.on('perfStat',observer1)
      store2 = await relationalStore.getRdbStore(context, STORE_CONFIG2)
      timerId = setTimeout(done, 2000);
      console.log(TAG + "************* testRdbStorePerfStat_0017 end *************");
    })

    /**
     * @tc.name Normal case for perfStat
     * @tc.number testRdbStorePerfStat_0001
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0018',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0018 start *************");
      let observer1 = async (sqlExecutionInfo : relationalStore.SqlExecutionInfo) => {
        expect(4).assertEqual(sqlExecutionInfo.sql.length);
        done()
      };
      rdbStore?.on('perfStat',observer1)

      const rdbTrans = await rdbStore?.createTransaction();
      console.info(`mmy 4`);
      const valueBucket1: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      await rdbTrans?.insert('test', valueBucket1)
      await rdbTrans?.insert("test", valueBucket1)
      await rdbTrans?.commit();
      console.log(TAG + "************* testRdbStorePerfStat_0018 end *************");
    })

    /**
     * @tc.name Normal case for perfStat update data execution time
     * @tc.number testRdbStorePerfStat_0019
     * @tc.desc 1. Register callback for perfStat
     */
    it('testRdbStorePerfStat_0019',  0, async  () => {
      console.log(TAG + "************* testRdbStorePerfStat_0019 start *************");
      let observer = (SqlExeInfo : relationalStore.SqlExecutionInfo) => {
        expect().assertFail();
      };

      rdbStore?.close();
      try {
        rdbStore?.on('perfStat', observer);
      } catch (err) {
        expect(err.code).assertEqual("14800014");
      }
      console.log(TAG + "************* testRdbStorePerfStat_0019 end *************");
    })

    /**
     * @tc.name Normal case for perfStat batchInsert data execution time
     * @tc.number testRdbStorePerfStat_0020
     * @tc.desc 1. Register callback for perfStat
     *          2. Update data
     */
    it('testRdbStorePerfStat_0020',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStorePerfStat_0020 start *************");
      let observer = (sqlExecutionInfo : relationalStore.SqlExecutionInfo) => {
        expect(1).assertEqual(sqlExecutionInfo.sql.length);
        done()
      };
      rdbStore?.on('perfStat', observer);
      const valueBucket1: relationalStore.ValuesBucket = {
        'id': 1,
        'name': 'zhangsan',
        'age': 13,
      };
      const valueBucket2: relationalStore.ValuesBucket = {
        'id': 2,
        'name': 'zhangsan',
        'age': 13,
      };
      const valueBucket3: relationalStore.ValuesBucket = {
        'id': 5,
        'name': 'zhangsan',
        'age': 13,
      };
      let valueBuckets = new Array(valueBucket1, valueBucket2, valueBucket3);
      await rdbStore?.batchInsert("test", valueBuckets);
      console.log(TAG + "************* testRdbStorePerfStat_0020 end *************");
    })
  })
}