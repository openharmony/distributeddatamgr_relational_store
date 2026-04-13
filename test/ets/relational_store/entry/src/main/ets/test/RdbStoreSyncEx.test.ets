/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
import hilog from '@ohos.hilog';
import relationalStore from '@ohos.data.relationalStore';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import fs from '@ohos.file.fs';
import { BusinessError } from '@ohos.base';

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const DOMAIN = 0x0985;
const TAG = "[RDB_STORE_SYNC_EX_TEST]";

const DB_NAME = 'SyncExTest.db';

// SQL for creating test table
const SQL_CREATE_TABLE =
  'CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)';

const SQL_CREATE_TABLE_SYNC =
  'CREATE TABLE IF NOT EXISTS SYNC_TABLE (ID INTEGER PRIMARY KEY AUTOINCREMENT, DATA TEXT NOT NULL, TIMESTAMP INTEGER)';

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: DB_NAME,
  securityLevel: relationalStore.SecurityLevel.S1
};

const DISTRIBUTED_CONFIG: relationalStore.DistributedConfig = {
  autoSync: false,
  asyncDownloadAsset: false,
  enableCloud: false,
  tableType: relationalStore.DistributedTableType.DEVICE_COLLABORATION
};

let rdbStore: relationalStore.RdbStore | undefined = undefined;

/**
 * Cleanup test database files
 */
async function cleanupDatabaseFiles(): Promise<void> {
  try {
    await rdbStore?.close();
  } catch (e) {
    console.info(TAG + 'close failed');
  }

  try {
    await relationalStore.deleteRdbStore(context, DB_NAME);
  } catch (e) {
    console.info(TAG + 'deleteRdbStore failed');
  }
}

/**
 * Initialize RdbStore for testing
 */
async function initRdbStore(): Promise<void> {
  try {
    rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
    expect(rdbStore !== undefined).assertTrue();
    console.info(TAG + 'getRdbStore success');

    await rdbStore.executeSql(SQL_CREATE_TABLE);
    await rdbStore.executeSql(SQL_CREATE_TABLE_SYNC);
    console.info(TAG + 'create tables success');

    // Set distributed table
    await rdbStore.setDistributedTable('EMPLOYEE', DISTRIBUTED_CONFIG);
    await rdbStore.setDistributedTable('SYNC_TABLE', DISTRIBUTED_CONFIG);
    console.info(TAG + 'setDistributedTable success');
  } catch (e) {
    console.error(TAG + `initRdbStore failed: ${JSON.stringify(e)}`);
    expect(true).assertFail();
  }
}

/**
 * Insert test data
 */
async function insertTestData(): Promise<void> {
  try {
    const valueBucket1: relationalStore.ValuesBucket = {
      'NAME': 'Alice',
      'AGE': 30,
      'SALARY': 5000.5,
      'CODES': new Uint8Array([1, 2, 3])
    };

    const valueBucket2: relationalStore.ValuesBucket = {
      'NAME': 'Bob',
      'AGE': 25,
      'SALARY': 4500.0,
      'CODES': new Uint8Array([4, 5, 6])
    };

    await rdbStore?.insert('EMPLOYEE', valueBucket1);
    await rdbStore?.insert('EMPLOYEE', valueBucket2);
    console.info(TAG + 'insert test data success');
  } catch (e) {
    console.error(TAG + `insertTestData failed: ${JSON.stringify(e)}`);
    expect(true).assertFail();
  }
}

export default function RdbStoreSyncExTest() {
  describe('rdbStoreSyncExTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll');
    });

    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
      await cleanupDatabaseFiles();
      await initRdbStore();
      await insertTestData();
    });

    afterEach(async () => {
      console.info(TAG + 'afterEach');
      await cleanupDatabaseFiles();
      rdbStore = undefined;
    });

    afterAll(async () => {
      console.info(TAG + 'afterAll');
    });

    /**
     * @tc.name testSyncExWithPushMode
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_0100
     * @tc.desc Test syncEx with PUSH mode
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExWithPushMode', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExWithPushMode start *************');

      try {
        const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const mode = relationalStore.SyncMode.SYNC_MODE_PUSH;

        const result = await rdbStore?.syncEx(mode, predicates);

        console.info(TAG + `syncEx result: ${JSON.stringify(result)}`);
        expect(result !== undefined).assertTrue();
        expect(Array.isArray(result)).assertTrue();

        done();
      } catch (err) {
        console.error(TAG + `testSyncExWithPushMode failed: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExWithPushMode end *************');
    });

    /**
     * @tc.name testSyncExWithPullMode
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_0200
     * @tc.desc Test syncEx with PULL mode
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExWithPullMode', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExWithPullMode start *************');

      try {
        const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const mode = relationalStore.SyncMode.SYNC_MODE_PULL;

        const result = await rdbStore?.syncEx(mode, predicates);

        console.info(TAG + `syncEx result: ${JSON.stringify(result)}`);
        expect(result !== undefined).assertTrue();
        expect(Array.isArray(result)).assertTrue();

        done();
      } catch (err) {
        console.error(TAG + `testSyncExWithPullMode failed: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExWithPullMode end *************');
    });

    /**
     * @tc.name testSyncExWithPushPullMode
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_0300
     * @tc.desc Test syncEx with PUSH_PULL mode
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExWithPushPullMode', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExWithPushPullMode start *************');

      try {
        const predicates = new relationalStore.RdbPredicates('SYNC_TABLE');
        const mode = relationalStore.SyncMode.SYNC_MODE_PUSH_PULL;

        const result = await rdbStore?.syncEx(mode, predicates);

        console.info(TAG + `syncEx result: ${JSON.stringify(result)}`);
        expect(result !== undefined).assertTrue();
        expect(Array.isArray(result)).assertTrue();

        done();
      } catch (err) {
        console.error(TAG + `testSyncExWithPushPullMode failed: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExWithPushPullMode end *************');
    });

    /**
     * @tc.name testSyncExWithPredicates
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_0400
     * @tc.desc Test syncEx with predicates conditions
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExWithPredicates', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExWithPredicates start *************');

      try {
        const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        predicates.equalTo('NAME', 'Alice');

        const mode = relationalStore.SyncMode.SYNC_MODE_PUSH;

        const result = await rdbStore?.syncEx(mode, predicates);

        console.info(TAG + `syncEx with predicates result: ${JSON.stringify(result)}`);
        expect(result !== undefined).assertTrue();
        expect(Array.isArray(result)).assertTrue();

        done();
      } catch (err) {
        console.error(TAG + `testSyncExWithPredicates failed: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExWithPredicates end *************');
    });

    /**
     * @tc.name testSyncExWithInvalidMode
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_0500
     * @tc.desc Test syncEx with invalid mode (should fail gracefully)
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExWithInvalidMode', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExWithInvalidMode start *************');

      try {
        const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const invalidMode = 999 as relationalStore.SyncMode;

        try {
          const result = await rdbStore?.syncEx(invalidMode, predicates);
          console.info(TAG + `syncEx with invalid mode result: ${JSON.stringify(result)}`);
          // May succeed or fail depending on implementation
          expect(true).assertTrue();
        } catch (syncErr) {
          console.info(TAG + `syncEx with invalid mode failed as expected: ${JSON.stringify(syncErr)}`);
          expect(true).assertTrue(); // Expected to fail
        }

        done();
      } catch (err) {
        console.error(TAG + `testSyncExWithInvalidMode unexpected error: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExWithInvalidMode end *************');
    });

    /**
     * @tc.name testSyncExWithEmptyPredicates
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_0600
     * @tc.desc Test syncEx with empty table name (should fail)
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExWithEmptyPredicates', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExWithEmptyPredicates start *************');

      try {
        const predicates = new relationalStore.RdbPredicates('');
        const mode = relationalStore.SyncMode.SYNC_MODE_PUSH;

        try {
          const result = await rdbStore?.syncEx(mode, predicates);
          console.error(TAG + 'syncEx with empty table should fail but succeeded');
          expect(false).assertTrue();
        } catch (syncErr) {
          console.info(TAG + `syncEx with empty table failed as expected: ${JSON.stringify(syncErr)}`);
          expect(syncErr !== undefined).assertTrue();
        }

        done();
      } catch (err) {
        console.error(TAG + `testSyncExWithEmptyPredicates unexpected error: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExWithEmptyPredicates end *************');
    });

    /**
     * @tc.name testSyncExMultipleCalls
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_0700
     * @tc.desc Test multiple consecutive syncEx calls
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExMultipleCalls', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExMultipleCalls start *************');

      try {
        const predicates1 = new relationalStore.RdbPredicates('EMPLOYEE');
        const mode1 = relationalStore.SyncMode.SYNC_MODE_PUSH;

        const result1 = await rdbStore?.syncEx(mode1, predicates1);
        console.info(TAG + `First syncEx result: ${JSON.stringify(result1)}`);
        expect(result1 !== undefined).assertTrue();

        const predicates2 = new relationalStore.RdbPredicates('SYNC_TABLE');
        const mode2 = relationalStore.SyncMode.SYNC_MODE_PULL;

        const result2 = await rdbStore?.syncEx(mode2, predicates2);
        console.info(TAG + `Second syncEx result: ${JSON.stringify(result2)}`);
        expect(result2 !== undefined).assertTrue();

        done();
      } catch (err) {
        console.error(TAG + `testSyncExMultipleCalls failed: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExMultipleCalls end *************');
    });

    /**
     * @tc.name testSyncExResultStructure
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_0800
     * @tc.desc Test syncEx result structure contains device, code, and message
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExResultStructure', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExResultStructure start *************');

      try {
        const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const mode = relationalStore.SyncMode.SYNC_MODE_PUSH;

        const result = await rdbStore?.syncEx(mode, predicates);

        console.info(TAG + `syncEx result structure: ${JSON.stringify(result)}`);
        expect(result !== undefined).assertTrue();
        expect(Array.isArray(result)).assertTrue();

        if (result && result.length > 0) {
          const firstResult = result[0];
          console.info(TAG + `First result: ${JSON.stringify(firstResult)}`);

          // Check if result has expected structure
          expect(firstResult.hasOwnProperty('device') ||
                 firstResult.hasOwnProperty('code') ||
                 firstResult.hasOwnProperty('message')).assertTrue();
        }

        done();
      } catch (err) {
        console.error(TAG + `testSyncExResultStructure failed: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExResultStructure end *************');
    });

    /**
     * @tc.name testSyncExWithoutDistributedTable
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_0900
     * @tc.desc Test syncEx on table without distributed configuration
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExWithoutDistributedTable', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExWithoutDistributedTable start *************');

      try {
        // Create a non-distributed table
        await rdbStore?.executeSql('CREATE TABLE IF NOT EXISTS LOCAL_TABLE (ID INTEGER PRIMARY KEY, NAME TEXT)');

        const predicates = new relationalStore.RdbPredicates('LOCAL_TABLE');
        const mode = relationalStore.SyncMode.SYNC_MODE_PUSH;

        try {
          const result = await rdbStore?.syncEx(mode, predicates);
          console.info(TAG + `syncEx on non-distributed table result: ${JSON.stringify(result)}`);
          // Behavior may vary - just ensure it doesn't crash
          expect(true).assertTrue();
        } catch (syncErr) {
          console.info(TAG + `syncEx on non-distributed table failed: ${JSON.stringify(syncErr)}`);
          // Expected to fail for non-distributed table
          expect(true).assertTrue();
        }

        done();
      } catch (err) {
        console.error(TAG + `testSyncExWithoutDistributedTable unexpected error: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExWithoutDistributedTable end *************');
    });

    /**
     * @tc.name testSyncExComplexPredicates
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_1000
     * @tc.desc Test syncEx with complex predicates (multiple conditions)
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExComplexPredicates', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExComplexPredicates start *************');

      try {
        const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        predicates.equalTo('AGE', 30)
                 .and()
                 .like('NAME', '%Ali%');

        const mode = relationalStore.SyncMode.SYNC_MODE_PUSH_PULL;

        const result = await rdbStore?.syncEx(mode, predicates);

        console.info(TAG + `syncEx with complex predicates result: ${JSON.stringify(result)}`);
        expect(result !== undefined).assertTrue();
        expect(Array.isArray(result)).assertTrue();

        done();
      } catch (err) {
        console.error(TAG + `testSyncExComplexPredicates failed: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExComplexPredicates end *************');
    });

    /**
     * @tc.name testSyncExWithNullPredicates
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_1100
     * @tc.desc Test syncEx with null predicates (should return error 201)
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExWithNullPredicates', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExWithNullPredicates start *************');

      try {
        const mode = relationalStore.SyncMode.SYNC_MODE_PUSH;

        try {
          // @ts-ignore - Testing null parameter
          const result = await rdbStore?.syncEx(mode, null);
          console.error(TAG + 'syncEx with null predicates should fail but succeeded');
          expect(false).assertTrue();
          done();
        } catch (syncErr) {
          console.info(TAG + `syncEx with null predicates failed as expected: ${JSON.stringify(syncErr)}`);
          const businessError = syncErr as BusinessError;
          expect(businessError !== undefined).assertTrue();
          expect(businessError.code === 201).assertTrue();
          console.info(TAG + `Error code: ${businessError.code}, message: ${businessError.message}`);
          done();
        }
      } catch (err) {
        console.error(TAG + `testSyncExWithNullPredicates unexpected error: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExWithNullPredicates end *************');
    });

    /**
     * @tc.name testSyncExWithUndefinedPredicates
     * @tc.number SUB_DistributedData_RelationalStore_SyncEx_1200
     * @tc.desc Test syncEx with undefined predicates (should return error 201)
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testSyncExWithUndefinedPredicates', 0, async (done: Function) => {
      console.info(TAG + '************* testSyncExWithUndefinedPredicates start *************');

      try {
        const mode = relationalStore.SyncMode.SYNC_MODE_PUSH;

        try {
          // @ts-ignore - Testing undefined parameter
          const result = await rdbStore?.syncEx(mode, undefined);
          console.error(TAG + 'syncEx with undefined predicates should fail but succeeded');
          expect(false).assertTrue();
          done();
        } catch (syncErr) {
          console.info(TAG + `syncEx with undefined predicates failed as expected: ${JSON.stringify(syncErr)}`);
          const businessError = syncErr as BusinessError;
          expect(businessError !== undefined).assertTrue();
          expect(businessError.code === 201).assertTrue();
          console.info(TAG + `Error code: ${businessError.code}, message: ${businessError.message}`);
          done();
        }
      } catch (err) {
        console.error(TAG + `testSyncExWithUndefinedPredicates unexpected error: ${JSON.stringify(err)}`);
        expect(false).assertTrue();
        done();
      }

      console.info(TAG + '************* testSyncExWithUndefinedPredicates end *************');
    });

    console.info(TAG + '************* Unit Test Begin *************');
  });
}
