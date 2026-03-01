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
  isSearchable: true
}
const STORE_CONFIG1:relationalStore.StoreConfig = {
  name: "RdbTest.db",
  securityLevel: relationalStore.SecurityLevel.S1,
  isSearchable: true,
  isReadOnly:true
}
let rdbStore: relationalStore.RdbStore | undefined;
let rdbStore1: relationalStore.RdbStore | undefined;

async function corruptFile(fileName: string)
{
  let stat = await fs.stat(fileName);
  let file = await fs.open(fileName, fs.OpenMode.READ_WRITE);
  fs.lseek(file.fd, 0, fs.WhenceType.SEEK_SET);
  let bufferSize = stat.size;
  let buffer = new ArrayBuffer(bufferSize);
  let uint8Array = new Uint8Array(buffer);
  let fChar = 'F'.charCodeAt(0);
  uint8Array.fill(fChar);
  await fs.write(file.fd, buffer, { offset: 0, length: bufferSize });
}

export async function corruptDb(context:common.ApplicationContext, config:relationalStore.StoreConfig)
{
  let dbPath = context.databaseDir + "/rdb/" + config.name;
  let dbPathWal = dbPath + "-wal";
  let dbPathShm = dbPath + "-shm";
  await corruptFile(dbPath);
  await corruptFile(dbPathWal);
  await corruptFile(dbPathShm);
}

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
     * @tc.desc SetDistributedInfo success insert update info flag
     */
    it('SetDistributedInfoTest0001', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0001 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0001 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0001 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0001 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`SetDistributedInfoTest0001 success`);
          expect(true).assertTrue();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`SetDistributedInfoTest0001 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0001 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0002
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo success update remote data and update info flag
     */
    it('SetDistributedInfoTest0002', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0002 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0002 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0002 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["data_key"] = 0;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["device"] = value4;
        valueBucket["ori_device"] = value4;
        valueBucket["timestamp"] = 0;
        valueBucket["wtimestamp"] = 0;
        valueBucket["flag"] = 2;
        valueBucket["hash_key"] = value4;
        valueBucket["cloud_gid"] = "test";
        valueBucket["extend_field"] = value4;
        valueBucket["cursor"] = 0;
        valueBucket["version"] = "test";
        valueBucket["sharing_resource"] = "test";
        valueBucket["status"] = 0;
        if (rdbStore != undefined) {
          try {
            await (rdbStore as relationalStore.RdbStore).insert("naturalbase_rdb_aux_EMPLOYEE_log", valueBucket);
            console.info(`Insert is successful`);
          } catch (err) {
            console.error(`Insert is failed`);
          }
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0002 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
            oriDevice: ""
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          predicates.equalTo(relationalStore.DistributedField.ORIGIN, relationalStore.DistributedOrigin.ORI_LOCAL);
          predicates.notEqualTo(relationalStore.DistributedField.ORIGIN_ORIDEVICE, "");
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`setDistributedInfoInsert success`);
          expect(true).assertTrue();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`SetDistributedInfoTest0002 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0002 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0003
     * @tc.name Remove SetDistributedInfo data
     * @tc.desc Remove SetDistributedInfo file due to table is not single distributed table
     */
    it('SetDistributedInfoTest0003', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0003 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('SetDistributedInfoTest0003 EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0003 EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0003 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`SetDistributedInfoTest0003 success`);
          expect(null).assertFail();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
          console.error(`SetDistributedInfoTest0003 success`);
        } catch (e) {
          console.error(`SetDistributedInfoTest0003 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0003 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0004
     * @tc.name Remove SetDistributedInfo data
     * @tc.desc Remove SetDistributedInfo file due to db is not distributed db
     */
    it('SetDistributedInfoTest0004', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0004 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(-1);
        expect(resultSet.goToFirstRow()).assertEqual(false);
        console.log(`SetDistributedInfoTest0004 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          expect(null).assertFail();
          console.error(`SetDistributedInfoTest0004 success`);
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
          console.error(`SetDistributedInfoTest0004 success`);
        } catch (e) {
          console.error(`SetDistributedInfoTest0004 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0004 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0005
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo fail due to readonly db
     */
    it('SetDistributedInfoTest0005', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0005 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE,
            DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0005 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0005 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet: relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row: relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
      }
      rdbStore?.close();
      rdbStore1 = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      if (rdbStore1 == undefined) {
        expect().assertFail();
      } else {
        const distributedInfo:relationalStore.DistributedInfo = {
          flag: relationalStore.DistributedOrigin.ORI_REMOTE,
        }
        console.log(`SetDistributedInfoTest0005 begin`);
        try {
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await rdbStore1.setDistributedInfo(distributedInfo, predicates);
          expect(null).assertFail();
          console.error(`SetDistributedInfoTest0005 success`);
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore1?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`RetainDeviceDataTest0004 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0005 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0006
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo fail due db is close
     */
    it('SetDistributedInfoTest0006', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0006 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0006 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0006 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0006 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          rdbStore.close();
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`SetDistributedInfoTest0006 success`);
          expect(null).assertFail();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`SetDistributedInfoTest0006 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800014);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0006 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0007
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo fail due db is corrupt
     */
    it('SetDistributedInfoTest0007', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0007 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0007 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0007 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0007 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await corruptDb(context, STORE_CONFIG);
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`SetDistributedInfoTest0007 success`);
          expect(null).assertFail();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`SetDistributedInfoTest0007 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800011);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0007 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0008
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo fail due db is busy
     */
    it('SetDistributedInfoTest0008', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0008 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0008 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0008 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0008 begin`);
        try {
          let transactions = await rdbStore?.createTransaction({
            transactionType: relationalStore.TransactionType.DEFERRED
          });
          let valueBucket1: relationalStore.ValuesBucket = {};
          valueBucket1["NAME"] = "lisa";
          valueBucket1["AGE"] = 25;
          valueBucket1["SALARY"] = 23456.6;
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          valueBucket1["CODES"] = value4;
          await transactions.insert("EMPLOYEE", valueBucket1);
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`SetDistributedInfoTest0008 success`);
          expect(null).assertFail();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`SetDistributedInfoTest0008 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800024);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0008 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0009
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo fail due to table is not in db
     */
    it('SetDistributedInfoTest0009', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0009 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0009 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0009 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0009 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE1');
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`SetDistributedInfoTest0009 success`);
          expect(null).assertFail();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`SetDistributedInfoTest0009 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800021);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0009 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0010
     * @tc.name Remove SetDistributedInfo data
     * @tc.desc Remove SetDistributedInfo file due to table is not distributed table
     */
    it('SetDistributedInfoTest0010', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0010 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE1 (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE1"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0010 EMPLOYEE1 SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0010 EMPLOYEE1 SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE1", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(-1);
        expect(resultSet.goToFirstRow()).assertEqual(false);
        const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE1_log');
        let result:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
        expect(result.rowCount).assertEqual(1);
        expect(result.goToFirstRow()).assertEqual(true);
        console.log(`SetDistributedInfoTest0010 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          expect(null).assertFail();
          console.error(`SetDistributedInfoTest0010 success`);
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
          console.error(`SetDistributedInfoTest0010 success`);
        } catch (e) {
          console.error(`SetDistributedInfoTest0010 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0010 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0011
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo fail due to device id is invalid
     */
    it('SetDistributedInfoTest0011', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0011 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0011 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0011 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0011 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
            oriDevice: "test"
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`SetDistributedInfoTest0011 success`);
          expect(null).assertFail();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`SetDistributedInfoTest0011 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0011 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0012
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo fail due to device id is invalid
     */
    it('SetDistributedInfoTest0012', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0012 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0012 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0012 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["data_key"] = 0;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["device"] = value4;
        valueBucket["ori_device"] = value4;
        valueBucket["timestamp"] = 0;
        valueBucket["wtimestamp"] = 0;
        valueBucket["flag"] = 2;
        valueBucket["hash_key"] = value4;
        valueBucket["cloud_gid"] = "test";
        valueBucket["extend_field"] = value4;
        valueBucket["cursor"] = 0;
        valueBucket["version"] = "test";
        valueBucket["sharing_resource"] = "test";
        valueBucket["status"] = 0;
        if (rdbStore != undefined) {
          try {
            await (rdbStore as relationalStore.RdbStore).insert("naturalbase_rdb_aux_EMPLOYEE_log", valueBucket);
            console.info(`Insert is successful`);
          } catch (err) {
            console.error(`Insert is failed`);
          }
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0012 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
            oriDevice: ""
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          predicates.equalTo(relationalStore.DistributedField.ORIGIN, relationalStore.DistributedOrigin.ORI_LOCAL);
          predicates.notEqualTo(relationalStore.DistributedField.ORIGIN_ORIDEVICE, "test");
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`setDistributedInfoInsert success`);
          expect(null).assertFail();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`SetDistributedInfoTest0012 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0012 end *************");
    })

    /**
     * @tc.number SetDistributedInfoTest0013
     * @tc.name SetDistributedInfo
     * @tc.desc SetDistributedInfo fail due to valuetype is invalid
     */
    it('SetDistributedInfoTest0013', 0, async () => {
      console.log(TAG + "************* SetDistributedInfoTest0013 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedInfoTest0013 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedInfoTest0013 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value4;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`SetDistributedInfoTest0013 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE
          }
          const asset : relationalStore.Asset = {
            name: 'name1',
            uri: 'uri1',
            createTime: 'createTime1',
            modifyTime: 'modifyTime1',
            size: 'size1',
            path: 'path1',
            status: relationalStore.AssetStatus.ASSET_NORMAL,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          predicates.equalTo("CODES", value4);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          predicates.equalTo("SALARY", asset);
          await rdbStore.setDistributedInfo(distributedInfo, predicates);
          console.error(`SetDistributedInfoTest0013 success`);
          expect(null).assertFail();
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`SetDistributedInfoTest0013 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* SetDistributedInfoTest0013 end *************");
    })
    console.log(TAG + "*************Unit Test Begin*************");
  })
}