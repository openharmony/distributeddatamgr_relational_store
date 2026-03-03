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
import common from '@ohos.app.ability.common';
import fs from '@ohos.file.fs';
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();
const TAG = "[RELATIONAL_STORE_SetDistributedInfo_JSKITS_TEST]"
const DISTRIBUTED_CONFIG_SINGLE:relationalStore.DistributedConfig = {
  autoSync: false,
  asyncDownloadAsset: false,
  enableCloud: false,
  tableType: relationalStore.DistributedTableType.SINGLE_VERSION
}
const STORE_CONFIG:relationalStore.StoreConfig = {
  name: "RdbTest.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
let rdbStore: relationalStore.RdbStore | undefined;

export default function SetDistributedInfo() {
  describe('SetDistributedInfo', () => {
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
     * @tc.number SetDistributedInfoTest0001
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo fail due to non system app
     */
    it('SetDistributedInfoTest0001', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0001 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      }
      console.log(`SetDistributedInfoTest0001 begin`);
      try {
        const distributedInfo:relationalStore.DistributedInfo = {
          flag: relationalStore.DistributedOrigin.ORI_REMOTE,
        }
        const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        await rdbStore.setDistributedInfo(distributedInfo, predicates);
        console.error(`SetDistributedInfoTest0001 success`);
        expect(null).assertFail();
      } catch (e) {
        console.error(`SetDistributedInfoTest0001 failed, code is ${e.code},message is ${e.message}`);
        expect(e.code).assertEqual(202);
      }
      console.log(TAG + "************* SetDistributedInfoTest0001 end *************");
    })
    console.log(TAG + "*************Unit Test Begin*************");
  })
}