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
const TAG = "[RELATIONAL_STORE_RequestFullDataDonation_NonSystem_TEST]"

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "RdbTestDonationNonSys.db",
  securityLevel: relationalStore.SecurityLevel.S1,
  isSearchable: true
}

let rdbStore: relationalStore.RdbStore | undefined;

export default function RequestFullDataDonationNonSystem() {
  describe('RequestFullDataDonationNonSystem', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })

    beforeEach(async () => {
      console.info(TAG + 'beforeEach')
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql(
            'CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.info(`executeSql error, code is ${e.code}, message is ${e.message}`);
          expect(null).assertFail();
        }
      }
    })

    afterEach(async () => {
      console.info(TAG + 'afterEach')
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTestDonationNonSys.db");
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number RequestFullDataDonationNonSystemTest0001
     * @tc.name request full data donation by non-system application
     * @tc.desc call requestFullDataDonation as non-system app, expect 202 error
     */
    it('RequestFullDataDonationNonSystemTest0001', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationNonSystemTest0001 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStore.requestFullDataDonation(["EMPLOYEE"]);
        console.info('RequestFullDataDonationNonSystemTest0001 should throw error but did not');
        expect().assertFail();
      } catch (err) {
        console.info(`RequestFullDataDonationNonSystemTest0001 err, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual("202");
      }
      console.log(TAG + "************* RequestFullDataDonationNonSystemTest0001 end *************");
    })
  })
}