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
import deviceInfo from '@ohos.deviceInfo';

const TAG = "[RDB_PREDICATES_PERF]";
const BASE_COUNT = 2000; // loop times
const HAVING_BASE_LINE_TABLE = 50; // callback tablet base line
const HAVING_BASE_LINE_PHONE = 100; // callback phone base line
const HAVING_BASE_LINE = (deviceInfo.deviceType == "tablet") ? HAVING_BASE_LINE_TABLE : HAVING_BASE_LINE_PHONE;

export default function RdbPredicatesPrefEtsTest() {
  describe('rdbPredicatesPrefEtsTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll');
    });
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
    });
    afterEach(async () => {
      console.info(TAG + 'afterEach');
    });
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    });

    console.log(TAG + "*************Unit Test Begin*************");

    it('SUB_DDM_PERF_RDB_Predicates_having', 0, async (done:Function) => {
      let conditions: string = "data";
      let predicates:relationalStore.RdbPredicates = new relationalStore.RdbPredicates("tableName");
      predicates.groupBy(["data1"]);
      let startTime = new Date().getTime();
      for (let i = 0; i < BASE_COUNT; i++) {
          predicates.having(conditions);
      }
      let endTime = new Date().getTime();
      let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
      console.info(TAG + " the Predicates_having average time is: " + averageTime + " μs");
      expect(averageTime < HAVING_BASE_LINE).assertTrue();
      done();
    })

    console.log(TAG + "*************Unit Test End*************");
  })
}
