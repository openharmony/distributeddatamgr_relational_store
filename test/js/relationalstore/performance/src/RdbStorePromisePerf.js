/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, Assert} from 'deccjsunit/index';
import dataRdb from '@ohos.data.relationalStore';
import featureAbility from '@ohos.ability.featureAbility';
import deviceInfo from '@ohos.deviceInfo';

const TAG = "[RDBSTORE_PROMISE]";
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY AUTOINCREMENT, "
  + "name TEXT, age INTEGER, salary REAL, blobType BLOB)";

const DB_NAME = "rdbStorePromise.db";
const STORE_CONFIG = {
  name: DB_NAME,
  securityLevel: dataRdb.SecurityLevel.S1
}
let context = featureAbility.getContext();
var rdbStore = undefined;
const BASE_COUNT = 1000; // loop times
const BASE_LINE_TABLE = 1800; // callback tablet base line
const BASE_LINE_PHONE = 3000; // callback phone base line
const BASE_LINE = (deviceInfo.deviceType == "tablet") ? BASE_LINE_TABLE : BASE_LINE_PHONE;

describe('rdbStorePromisePerf', function () {
  beforeAll(async function () {
    console.info(TAG + 'beforeAll');
    rdbStore = await dataRdb.getRdbStore(context, STORE_CONFIG);
  })
  beforeEach(async function () {
    console.info(TAG + 'beforeEach');
    await rdbStore.executeSql(CREATE_TABLE_TEST, null);
    await prepareTestData();
  })
  afterEach(async function () {
    console.info(TAG + 'afterEach');
    await rdbStore.executeSql("drop table test");
  })
  afterAll(async function () {
    console.info(TAG + 'afterAll');
    rdbStore = null;
    await dataRdb.deleteRdbStore(context, DB_NAME);
  })

  async function prepareTestData() {
    console.info(TAG + "prepare for query performance test")
    var u8 = new Uint8Array([1, 2, 3])
    var valueBucket = {
      "name": "zhangsan",
      "age": 18,
      "salary": 100.5,
      "blobType": u8,
    }
    await dataRdb.insert("test", valueBucket);
  }

  console.log(TAG + "*************Unit Test Begin*************");

  it('SUB_DDM_PERF_RDB_query_Promise_001', 0, async function (done) {
    let averageTime = 0;
    let predicates = new dataRdb.RdbPredicates("test");
    predicates.equalTo("age", 10);
    let startTime = new Date().getTime();
    for (var i = 0; i < BASE_COUNT; i++) {
      let resultSet = await rdbStore.query(predicates, []);
      resultSet.close();
    }
    let endTime = new Date().getTime();
    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the query_Promise average time is: " + averageTime + " μs");
    expect(averageTime < BASE_LINE).assertTrue();
    console.info(TAG + "*************Unit Test End*************");
    done();
  })
})
