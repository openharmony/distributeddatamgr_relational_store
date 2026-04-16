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
    console.log(TAG + "*************Unit Test End*************");
  })
}
