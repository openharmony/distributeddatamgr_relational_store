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

const TAG = "[RDB_RESULTSET_PERF]";
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY AUTOINCREMENT, "
  + "name TEXT, age INTEGER, salary REAL, blobType BLOB)";

const DB_NAME = "resultSetPerf.db";
const STORE_CONFIG = {
  name: DB_NAME,
  securityLevel: dataRdb.SecurityLevel.S1
}
let context = featureAbility.getContext();
var rdbStore = undefined;
const BASE_COUNT = 2000; // loop times
const SPECIAL_BASE_COUNT = 12000;
const BASE_LINE_TABLE = 500; // callback tablet base line
const BASE_LINE_PHONE = 1000; // callback phone base line
const BASE_LINE = (deviceInfo.deviceType == "tablet") ? BASE_LINE_TABLE : BASE_LINE_PHONE;

describe('resultSetPerf', function () {
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
    console.info(TAG + "prepare for query performance test");
    var valueBuckets = [];
    var u8 = new Uint8Array([1, 2, 3])
    var valueBucket = {
      "name": "zhangsan",
      "age": 18,
      "salary": 100.5,
      "blobType": u8,
    }
    for (let i = 0; i < BASE_COUNT; i++) {
      valueBucket.age += i;
      valueBuckets.push(valueBucket);
    }
    await rdbStore.batchInsert("test", valueBuckets);
  }

  console.log(TAG + "*************Unit Test Begin*************");

  it('SUB_DDM_PERF_RDB_ResultSet_GetColumnIndex_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    resultSet.goToFirstRow();
    let startTime = new Date().getTime();
    for (let i = 0; i < BASE_LINE; i++) {
      resultSet.getColumnIndex("id");
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GetColumnIndex average time is: " + averageTime + " μs");
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GetColumnName_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    resultSet.goToFirstRow();
    let startTime = new Date().getTime()
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.getColumnName(0);
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GetColumnName average time is: " + averageTime + " μs")
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GoTo_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    resultSet.goToFirstRow();
    let startTime = new Date().getTime()
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.goTo(i % 2);
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GoTo average time is: " + averageTime + " μs")
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GoToRow_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    resultSet.goToFirstRow();
    let startTime = new Date().getTime();
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.goToRow(1);
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GoToRow average time is: " + averageTime + " μs");
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GoToFirstRow_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    let startTime = new Date().getTime();
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.goToFirstRow();
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GoToFirstRow average time is: " + averageTime + " μs");
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GoToLastRow_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    let startTime = new Date().getTime();
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.goToLastRow();
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GoToLastRow average time is: " + averageTime + " μs");
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GoToNextRow_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    resultSet.goToFirstRow();
    let startTime = new Date().getTime();
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.goToNextRow();
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GoToNextRow average time is: " + averageTime + " μs")
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GoToPreviousRow_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    resultSet.goToLastRow();
    let startTime = new Date().getTime();
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.goToPreviousRow();
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GoToPreviousRow average time is: " + averageTime + " μs");
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GetBlob_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    let columnIndex = resultSet.getColumnIndex("blobType");
    resultSet.goToFirstRow();
    let startTime = new Date().getTime()
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.getBlob(columnIndex);
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GetBlob average time is: " + averageTime + " μs");
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GetString_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    let columnIndex = resultSet.getColumnIndex("name");
    let flag = resultSet.goToFirstRow();
    let startTime = new Date().getTime();
    for (var i = 0; i < SPECIAL_BASE_COUNT; i++) {
      resultSet.getString(columnIndex);
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / SPECIAL_BASE_COUNT;
    console.info(TAG + " the ResultSet_GetString average time is: " + averageTime + " μs");
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done()
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GetLong_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    let columnIndex = resultSet.getColumnIndex("age");
    resultSet.goToFirstRow();
    let startTime = new Date().getTime();
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.getLong(columnIndex);
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GetLong average time is: " + averageTime + " μs")
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_GetDouble_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    let columnIndex = resultSet.getColumnIndex("salary");
    resultSet.goToFirstRow();
    let startTime = new Date().getTime()
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.getDouble(columnIndex);
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_GetDouble average time is: " + averageTime + " μs")
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  it('SUB_DDM_PERF_RDB_ResultSet_IsColumnNull_001', 0, async function (done) {
    let predicates = new dataRdb.RdbPredicates("test");
    let resultSet = await rdbStore.query(predicates);
    let columnIndex = resultSet.getColumnIndex("salary");
    resultSet.goToFirstRow();
    let startTime = new Date().getTime()
    for (let i = 0; i < BASE_COUNT; i++) {
      resultSet.isColumnNull(columnIndex);
    }
    let endTime = new Date().getTime();
    let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
    console.info(TAG + " the ResultSet_IsColumnNull average time is: " + averageTime + " μs");
    resultSet.close();
    expect(averageTime < BASE_LINE).assertTrue();
    done();
  })

  console.info(TAG + "*************Unit Test End*************");
})