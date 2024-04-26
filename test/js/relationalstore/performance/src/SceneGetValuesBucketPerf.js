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

const TAG = "[RDB_RESULTSET_PERF]";
const CREATE_TABLE_TEST = "CREATE TABLE test (" +
  "data01 TEXT, data02 INTEGER, data03 FLOAT, data04 BLOB, data05 BOOLEAN, " +
  "data06 TEXT, data07 INTEGER, data08 FLOAT, data09 BLOB, data10 BOOLEAN, " +
  "data11 TEXT, data12 INTEGER, data13 FLOAT, data14 BLOB, data15 BOOLEAN, " +
  "data16 TEXT, data17 INTEGER, data18 FLOAT, data19 BLOB, data20 BOOLEAN" +
  ");";

const FIELDS = ["data01", "data02", "data03", "data04", "data05", "data06", "data07", "data08", "data09", "data10",
  "data11", "data12", "data13", "data14", "data15", "data16", "data17", "data18", "data19", "data20"]

function CREATE_STRING(len) {
  let result = '';
  for (let i = 0; i < len; i++) {
    result += 'a';
  }
  return result;
}

const CONST_STRING_VALUE = CREATE_STRING(127);

function CREATE_UINT8_ARRAY(len) {
  let result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = 1;
  }
  return result;
}

const CONST_UINT8_ARRAY = CREATE_UINT8_ARRAY(127);

const DB_NAME = "resultSetPerf.db";
const STORE_CONFIG = {
  name: DB_NAME,
  securityLevel: dataRdb.SecurityLevel.S3
}

let context = featureAbility.getContext();
let rdbStore = undefined;
const BASE_COUNT = 2000; // loop times

describe('SceneGetValuesBucketPerf', function () {
  beforeAll(async function () {
    console.info(TAG + 'beforeAll');
    rdbStore = await dataRdb.getRdbStore(context, STORE_CONFIG);
    await rdbStore.executeSql(CREATE_TABLE_TEST);
    await prepareTestData();
  })

  beforeEach(async function () {
    console.info(TAG + 'beforeEach');
  })

  afterEach(async function () {
    console.info(TAG + 'afterEach');
  })

  afterAll(async function () {
    console.info(TAG + 'afterAll');
    await rdbStore.executeSql("drop table test");
    rdbStore = null;
    await dataRdb.deleteRdbStore(context, DB_NAME);
  })

  async function prepareTestData() {
    console.info(TAG + "prepare for query performance test");
    let valueBuckets = [];
    let valueBucket = {
      data01: CONST_STRING_VALUE,
      data02: 10001,
      data03: 101.5,
      data04: CONST_UINT8_ARRAY,
      data05: false,
      data06: CONST_STRING_VALUE,
      data07: 10002,
      data08: 102.5,
      data09: CONST_UINT8_ARRAY,
      data10: true,
      data11: CONST_STRING_VALUE,
      data12: 10003,
      data13: 103.5,
      data14: CONST_UINT8_ARRAY,
      data15: false,
      data16: CONST_STRING_VALUE,
      data17: 10004,
      data18: 104.5,
      data19: CONST_UINT8_ARRAY,
      data20: true
    }
    for (let i = 0; i < BASE_COUNT; i++) {
      valueBuckets.push(valueBucket);
    }
    await rdbStore.batchInsert("test", valueBuckets)
  }

  it('Scene_GetValuesBucket_0001', 0, async function (done) {
    console.log(TAG + "************* Scene_GetValuesBucket_0001 start *************");
    let predicates = await new dataRdb.RdbPredicates("test")
    let resultSet = await rdbStore.query(predicates)
    expect(2000).assertEqual(resultSet.rowCount);

    let startTime = new Date().getTime();
    let allValues = new Array();
    let i = 0;
    while (resultSet.goToNextRow()) {
      let values = resultSet.getRow();
      allValues[i++] = values;
    }
    resultSet.close();
    let endTime = new Date().getTime();
    let averageTime = (endTime - startTime);
    console.info(TAG + " the Scene_GetValuesBucket_0001 average time is: " + averageTime + " ms");
    expect(2000).assertEqual(allValues.length);
    expect(averageTime).assertLess(1000);

    expect(CONST_STRING_VALUE).assertEqual(allValues[0]["data01"]);
    done();
    console.log(TAG + "************* Scene_GetValuesBucket_0001 end   *************");
  })

  /**
   * @tc.name RDB Backup Restore test
   * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0010
   * @tc.desc RDB backup and restore function test
   */
  it('Scene_GetValuesBucket_0002', 0, async function (done) {
    console.log(TAG + "************* Scene_GetValuesBucket_0002 start *************");
    let predicates = await new dataRdb.RdbPredicates("test")
    let resultSet = await rdbStore.query(predicates)
    expect(2000).assertEqual(resultSet.rowCount);

    let startTime = new Date().getTime();
    let allValues = new Array(2000);

    let i = 0;
    let indexes = new Array(20);
    while (resultSet.goToNextRow()) {
      let values = new Array();

      if (i == 0) {
        for (let i = 0; i < 20; i++) {
          indexes[i] = resultSet.getColumnIndex(FIELDS[i]);
        }
      }

      for (let i = 0; i < 20; i++) {
        switch (resultSet.getColumnType(indexes[i])) {
          case 0: // TYPE_NULL
            values[FIELDS[i]] = null;
            break;
          case 1: // TYPE_INTEGER
            values[FIELDS[i]] = resultSet.getInt(indexes[i]);
            break;
          case 2: // TYPE_FLOAT
            values[FIELDS[i]] = resultSet.getDouble(indexes[i]);
            break;
          case 3: // TYPE_STRING
            values[FIELDS[i]] = resultSet.getString(indexes[i]);
            break;
          case 4: // TYPE_BLOB
            values[FIELDS[i]] = resultSet.getBlob(indexes[i]);
            break;
        }
      }
      allValues[i++] = values;
    }
    resultSet.close();
    let endTime = new Date().getTime();
    let averageTime = (endTime - startTime);
    console.info(TAG + " the Scene_GetValuesBucket_0002 average time is: " + averageTime + " ms");
    expect(2000).assertEqual(allValues.length);
    expect(averageTime).assertLess(2000);

    expect(CONST_STRING_VALUE).assertEqual(allValues[0]["data01"]);
    done();
    console.log(TAG + "************* Scene_GetValuesBucket_0002 end   *************");
  })
})