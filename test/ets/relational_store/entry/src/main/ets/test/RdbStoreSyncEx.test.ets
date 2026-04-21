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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import relationalStore from '@ohos.data.relationalStore'
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();
const TAG = "[RELATIONAL_STORE_SYNCEX_JSKITS_TEST]"

const STORE_CONFIG:relationalStore.StoreConfig = {
  name: "RdbTest.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

const CREATE_TABLE_TEST = 'CREATE TABLE IF NOT EXISTS EMPLOYEE ' +
  '(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER NOT NULL UNIQUE)';

let rdbStore: relationalStore.RdbStore | undefined;

export default function RdbStoreSyncEx() {
  describe('rdbStoreSyncExTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach')
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore.executeSql(CREATE_TABLE_TEST);
    })

    afterEach(async () => {
      console.info(TAG + 'afterEach')
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(context, STORE_CONFIG);
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number syncExTest0001
     * @tc.name No sync permission
     * @tc.desc No sync permission and syncEx returns 201
     */
    it('syncExTest0001', 0, async () => {
      console.log(TAG + "************* syncExTest0001 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0001 is successfully.');

        const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_PUSH, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(201);
      }
      console.log(TAG + "************* syncExTest0001 end *************");
    })

    /**
     * @tc.number syncExTest0002
     * @tc.name The mode does not meet expectations
     * @tc.desc Sync mode is SYNC_MODE_CLOUD_FIRST and syncEx returns 14800001
     */
    it('syncExTest0002', 0, async () => {
      console.log(TAG + "************* syncExTest0002 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0002 is successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_CLOUD_FIRST, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* syncExTest0002 end *************");
    })

    /**
     * @tc.number syncExTest0003
     * @tc.name store is closed
     * @tc.desc store is closed and syncEx returns 14800014
     */
    it('syncExTest0003', 0, async () => {
      console.log(TAG + "************* syncExTest0003 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0003 is successfully.');

        await rdbStore?.close();

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_PUSH, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800014);
      }
      console.log(TAG + "************* syncExTest0003 end *************");
    })

    /**
     * @tc.number syncExTest0004
     * @tc.name mode is null
     * @tc.desc mode is null and syncEx returns 14800001
     */
    it('syncExTest0004', 0, async () => {
      console.log(TAG + "************* syncExTest0004 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0004 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(null as any, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* syncExTest0004 end *************");
    })

    /**
     * @tc.number syncExTest0005
     * @tc.name mode is undefined
     * @tc.desc mode is undefined and syncEx returns 14800001
     */
    it('syncExTest0005', 0, async () => {
      console.log(TAG + "************* syncExTest0005 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0005 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(undefined as any, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* syncExTest0005 end *************");
    })

    /**
     * @tc.number syncExTest0008
     * @tc.name mode is invalid number
     * @tc.desc mode is invalid number (999) and syncEx returns 14800001
     */
    it('syncExTest0008', 0, async () => {
      console.log(TAG + "************* syncExTest0008 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0008 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(999 as any, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* syncExTest0008 end *************");
    })

    /**
     * @tc.number syncExTest0010
     * @tc.name SYNC_MODE_PUSH
     * @tc.desc sync with SYNC_MODE_PUSH, expect 201 due to no permission
     */
    it('syncExTest0010', 0, async () => {
      console.log(TAG + "************* syncExTest0010 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0010 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_PUSH, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(201);
      }
      console.log(TAG + "************* syncExTest0010 end *************");
    })

    /**
     * @tc.number syncExTest0011
     * @tc.name SYNC_MODE_PULL
     * @tc.desc sync with SYNC_MODE_PULL, expect 201 due to no permission
     */
    it('syncExTest0011', 0, async () => {
      console.log(TAG + "************* syncExTest0011 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0011 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_PULL, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(201);
      }
      console.log(TAG + "************* syncExTest0011 end *************");
    })

    /**
     * @tc.number syncExTest0012
     * @tc.name SYNC_MODE_TIME_FIRST
     * @tc.desc sync with SYNC_MODE_TIME_FIRST, expect 14800001
     */
    it('syncExTest0012', 0, async () => {
      console.log(TAG + "************* syncExTest0012 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0012 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* syncExTest0012 end *************");
    })

    /**
     * @tc.number syncExTest0013
     * @tc.name SYNC_MODE_NATIVE_FIRST
     * @tc.desc sync with SYNC_MODE_NATIVE_FIRST, expect 14800001
     */
    it('syncExTest0013', 0, async () => {
      console.log(TAG + "************* syncExTest0013 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0013 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_NATIVE_FIRST, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* syncExTest0013 end *************");
    })

    /**
     * @tc.number syncExTest0014
     * @tc.name SYNC_MODE_CLOUD_FIRST not supported
     * @tc.desc SYNC_MODE_CLOUD_FIRST and syncEx returns 14800001
     */
    it('syncExTest0014', 0, async () => {
      console.log(TAG + "************* syncExTest0014 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0014 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_CLOUD_FIRST, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* syncExTest0014 end *************");
    })

    /**
     * @tc.number syncExTest0015
     * @tc.name predicates with non-existent table
     * @tc.desc predicates with non-existent table, expect 201 due to no permission
     */
    it('syncExTest0015', 0, async () => {
      console.log(TAG + "************* syncExTest0015 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0015 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('NON_EXISTENT_TABLE');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_PUSH, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(201);
      }
      console.log(TAG + "************* syncExTest0015 end *************");
    })

    /**
     * @tc.number syncExTest0016
     * @tc.name predicates with where condition
     * @tc.desc sync with predicates containing where condition, expect 201 due to no permission
     */
    it('syncExTest0016', 0, async () => {
      console.log(TAG + "************* syncExTest0016 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0016 setDistributedTables successfully.');

        // Insert test data first
        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'TestEmployee',
          'age': 30
        };
        await rdbStore?.insert('EMPLOYEE', valueBucket);

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        predicates.equalTo('age', 30);
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_PUSH, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(201);
      }
      console.log(TAG + "************* syncExTest0016 end *************");
    })

    /**
     * @tc.number syncExTest0017
     * @tc.name predicates with limit
     * @tc.desc sync with predicates containing limit, expect 201 due to no permission
     */
    it('syncExTest0017', 0, async () => {
      console.log(TAG + "************* syncExTest0017 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0017 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        predicates.limitAs(10);
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_PUSH, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(201);
      }
      console.log(TAG + "************* syncExTest0017 end *************");
    })

    /**
     * @tc.number syncExTest0018
     * @tc.name predicates with orderBy
     * @tc.desc sync with predicates containing orderBy, expect 201 due to no permission
     */
    it('syncExTest0018', 0, async () => {
      console.log(TAG + "************* syncExTest0018 start *************");
      try {
        console.info(TAG + `SetDistributedTable EMPLOYEE begin`);
        await rdbStore?.setDistributedTables(["EMPLOYEE"]);
        console.info(TAG + 'syncExTest0018 setDistributedTables successfully.');

        const predicates: relationalStore.RdbPredicates = new relationalStore.RdbPredicates('EMPLOYEE');
        predicates.orderByDesc('age');
        const result: Array<relationalStore.SyncResult> = await rdbStore.syncEx(relationalStore.SyncMode.SYNC_MODE_PUSH, predicates);
        expect(null).assertFail();
      } catch (err) {
        console.error(TAG + `syncEx is failed, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(201);
      }
      console.log(TAG + "************* syncExTest0018 end *************");
    })
  })
}
