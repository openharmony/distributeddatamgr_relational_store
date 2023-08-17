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
import dataRdb from '@ohos.data.rdb';
import featureAbility from '@ohos.ability.featureAbility';
import deviceInfo from '@ohos.deviceInfo';

const TAG = "[RDB_SYNC_PROMISE]";
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY AUTOINCREMENT, "
  + "name TEXT, age INTEGER, salary REAL, blobType BLOB)";

const DB_NAME = "rdbSync.db";
const STORE_CONFIG = {
  name: DB_NAME,
}
let context = featureAbility.getContext();
var rdbStore = undefined;
const BASE_COUNT = 1000; // loop times
const BASE_LINE_TABLE = 2500; // callback tablet base line
const BASE_LINE_PHONE = 3000; // callback phone base line
const BASE_LINE = (deviceInfo.deviceType == "tablet" || deviceInfo.deviceType == "2in1") ? BASE_LINE_TABLE : BASE_LINE_PHONE;


describe('rdbStoreSyncPerf', function () {
  beforeAll(async function () {
    console.info(TAG + 'beforeAll');
    rdbStore = await dataRdb.getRdbStore(context, STORE_CONFIG, 1);
  })
  beforeEach(async function () {
    console.info(TAG + 'beforeEach');
  })
  afterEach(async function () {
    console.info(TAG + 'afterEach');
  })
  afterAll(async function () {
    console.info(TAG + 'afterAll');
    rdbStore = null
    await dataRdb.deleteRdbStore(context, DB_NAME);
  })

  console.log(TAG + "*************Unit Test Begin*************");

  it('SUB_DDM_PERF_RDB_version_001', 0, async function (done) {
    let averageTime = 0;
    let dbVersion = 1;
    let startTime = new Date().getTime();
    for (var i = 0; i < BASE_COUNT; i++) {
      dbVersion = rdbStore.version;
    }
    let endTime = new Date().getTime();
    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the version average time is: " + averageTime + " μs");
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_transaction_commit_001', 0, async function (done) {
    let averageTime = 0;
    let startTime = new Date().getTime();
    for (var i = 0; i < BASE_COUNT; i++) {
      rdbStore.beginTransaction();
      rdbStore.commit();
    }
    let endTime = new Date().getTime();
    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the transaction_commit average time is: " + averageTime + " μs");
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_transaction_rollback_001', 0, async function (done) {
    let averageTime = 0;
    let startTime = new Date().getTime();
    for (var i = 0; i < BASE_COUNT; i++) {
      rdbStore.beginTransaction();
      rdbStore.rollBack();
    }
    let endTime = new Date().getTime();
    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the transaction_rollback average time is: " + averageTime + " μs");
    expect(averageTime < BASE_LINE).assertTrue();
    done();
    console.info(TAG + "*************Unit Test End*************");
  })
})
