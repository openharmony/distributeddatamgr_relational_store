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
const TAG = "[RELATIONAL_STORE_UpdateDistributedInfo_JSKITS_TEST]"
const STORE_CONFIG:relationalStore.StoreConfig = {
  name: "RdbTest.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

let rdbStore: relationalStore.RdbStore | undefined;

export default function UpdateDistributedInfo() {
  describe('UpdateDistributedInfo', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach')
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
    })

    afterEach(async () => {
      console.info(TAG + 'afterEach')
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest.db");
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    /**
     * @tc.number UpdateDistributedInfoTest0001
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo fail due to non system app
     */
    it('UpdateDistributedInfoTest0001', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0001 start *************");
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.log(`UpdateDistributedInfoTest0001 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          await rdbStore.updateDistributedInfo(distributedInfo, predicates);
          console.error(`UpdateDistributedInfoTest0001 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0001 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(202);
        }
      }
      console.log(TAG + "************* UpdateDistributedInfoTest0001 end *************");
    })
    console.log(TAG + "*************Unit Test Begin*************");
  })
}