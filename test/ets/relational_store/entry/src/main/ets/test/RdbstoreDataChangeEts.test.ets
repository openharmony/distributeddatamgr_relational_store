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
const TAG = "[RDB_STORE_DATACHANGE_TEST]";
let rdbStore:relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL)";

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "rdbStore.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();
function sleep(ms:number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  })
}

export default function RdbStoreDataChangeTestEts() {
  describe('rdbStoreDataChangeTestEts', () => {
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
      await relationalStore.deleteRdbStore(context, "rdbStore.db");
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testDataChange001
     * @tc.desc 1. Register callback for dataChange
     */
    it('testDataChange001',  0, async  (done:Function) => {
      console.log(TAG + "************* testDataChange001 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = (devices: Array<string>) => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = (devices: Array<string>) => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver1);
      rdbStore2?.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver2);
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      await rdbStore?.insert("test", valueBucket);
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(1);
      rdbStore?.off('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver1);
      rdbStore2?.off('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver2);
      console.log(TAG + "************* testDataChange001 end *************");
      done();
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testDataChange001
     * @tc.desc 1. Register callback for dataChange
     */
    it('testDataChange002',  0, async  (done:Function) => {
      console.log(TAG + "************* testDataChange002 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = (devices: Array<string>) => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = (devices: Array<string>) => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver1);
      rdbStore2?.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver2);
      await rdbStore2.close();
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      await rdbStore?.insert("test", valueBucket);
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(0);
      rdbStore?.off('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver1);
      console.log(TAG + "************* testDataChange002 end *************");
      done();
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testEvent001
     * @tc.desc 1. Register callback for event
     */
    it('testEvent001',  0, async  (done:Function) => {
      console.log(TAG + "************* testEvent001 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = () => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = () => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('event', true, storeObserver1);
      rdbStore2?.on('event', true, storeObserver2);
      rdbStore?.emit('event');
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(1);
      rdbStore?.off('event', true, storeObserver1);
      rdbStore2?.off('event', true, storeObserver2);
      console.log(TAG + "************* testEvent001 end *************");
      done();
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testEvent002
     * @tc.desc 1. Register callback for event
     */
    it('testEvent002',  0, async  (done:Function) => {
      console.log(TAG + "************* testEvent002 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = () => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = () => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('event', true, storeObserver1);
      rdbStore2?.on('event', true, storeObserver2);
      await rdbStore2.close();
      rdbStore?.emit('event');
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(0);
      rdbStore?.off('event', true, storeObserver1);
      console.log(TAG + "************* testEvent002 end *************");
      done();
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testEvent001
     * @tc.desc 1. Register callback for statistics
     */
    it('testStatistics001',  0, async  (done:Function) => {
      console.log(TAG + "************* testStatistics001 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = (sqlExecutionInfo: relationalStore.SqlExecutionInfo) => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = (sqlExecutionInfo: relationalStore.SqlExecutionInfo) => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('statistics', storeObserver1);
      rdbStore2?.on('statistics', storeObserver2);
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      await rdbStore?.insert("test", valueBucket);
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(1);
      rdbStore?.off('statistics', storeObserver1);
      rdbStore2?.off('statistics', storeObserver2);
      console.log(TAG + "************* testStatistics001 end *************");
      done();
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testEvent001
     * @tc.desc 1. Register callback for statistics
     */
    it('testStatistics002',  0, async  (done:Function) => {
      console.log(TAG + "************* testStatistics002 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = (sqlExecutionInfo: relationalStore.SqlExecutionInfo) => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = (sqlExecutionInfo: relationalStore.SqlExecutionInfo) => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('statistics', storeObserver1);
      rdbStore2?.on('statistics', storeObserver2);
      await rdbStore2.close();
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      await rdbStore?.insert("test", valueBucket);
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(0);
      rdbStore?.off('statistics', storeObserver1);
      console.log(TAG + "************* testStatistics002 end *************");
      done();
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testEvent001
     * @tc.desc 1. Register callback for sqliteErrorOccurred
     */
    it('testSqliteErrorOccurred001',  0, async  (done:Function) => {
      console.log(TAG + "************* testSqliteErrorOccurred001 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = (exceptionMessage: relationalStore.ExceptionMessage) => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = (exceptionMessage: relationalStore.ExceptionMessage) => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('sqliteErrorOccurred', storeObserver1);
      rdbStore2?.on('sqliteErrorOccurred', storeObserver2);
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      try {
        await rdbStore?.insert("test1", valueBucket);
      } catch(e) {}
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(1);
      rdbStore?.off('sqliteErrorOccurred', storeObserver1);
      rdbStore2?.off('sqliteErrorOccurred', storeObserver2);
      console.log(TAG + "************* testSqliteErrorOccurred001 end *************");
      done();
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testEvent001
     * @tc.desc 1. Register callback for sqliteErrorOccurred
     */
    it('testSqliteErrorOccurred002',  0, async  (done:Function) => {
      console.log(TAG + "************* testSqliteErrorOccurred001 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = (exceptionMessage: relationalStore.ExceptionMessage) => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = (exceptionMessage: relationalStore.ExceptionMessage) => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('sqliteErrorOccurred', storeObserver1);
      rdbStore2?.on('sqliteErrorOccurred', storeObserver2);
      await rdbStore2.close();
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      try {
        await rdbStore?.insert("test1", valueBucket);
      } catch(e) {}
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(0);
      rdbStore?.off('sqliteErrorOccurred', storeObserver1);
      console.log(TAG + "************* testSqliteErrorOccurred001 end *************");
      done();
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testEvent001
     * @tc.desc 1. Register callback for perfStat
     */
    it('testPerfStat001',  0, async  (done:Function) => {
      console.log(TAG + "************* testSqliteErrorOccurred001 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = (sqlExecutionInfo: relationalStore.SqlExecutionInfo) => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = (sqlExecutionInfo: relationalStore.SqlExecutionInfo) => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('perfStat', storeObserver1);
      rdbStore2?.on('perfStat', storeObserver2);
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      await rdbStore?.insert("test", valueBucket);
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(1);
      rdbStore?.off('perfStat', storeObserver1);
      rdbStore2?.off('perfStat', storeObserver2);
      console.log(TAG + "************* testSqliteErrorOccurred001 end *************");
      done();
    })

    /**
     * @tc.name Normal Test creating multiple rdbstore objects and registering callbacks.
     * @tc.number testEvent001
     * @tc.desc 1. Register callback for perfStat
     */
    it('testPerfStat002',  0, async  (done:Function) => {
      console.log(TAG + "************* testSqliteErrorOccurred001 start *************");
      let status1 = 0;
      let status2 = 0;
      let storeObserver1 = (sqlExecutionInfo: relationalStore.SqlExecutionInfo) => {
        console.info(TAG + " storeObserver1 into");
        status1 = 1;
      };
      let storeObserver2 = (sqlExecutionInfo: relationalStore.SqlExecutionInfo) => {
        console.info(TAG + " storeObserver2 into");
        status2 = 1;
      };
      let rdbStore2:relationalStore.RdbStore | undefined = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore2 != undefined).assertTrue();
      rdbStore?.on('perfStat', storeObserver1);
      rdbStore2?.on('perfStat', storeObserver2);
      await rdbStore2.close();
      const valueBucket: relationalStore.ValuesBucket = {
        'name': 'zhangsan',
        'age': 18,
        'salary': 25000,
      };
      await rdbStore?.insert("test", valueBucket);
      await sleep(500);
      expect(status1).assertEqual(1);
      expect(status2).assertEqual(1);
      rdbStore?.off('perfStat', storeObserver1);
      console.log(TAG + "************* testSqliteErrorOccurred001 end *************");
      done();
    })
  })
}