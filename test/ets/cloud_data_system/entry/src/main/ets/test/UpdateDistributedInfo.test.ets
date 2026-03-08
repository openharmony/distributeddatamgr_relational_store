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
const TAG = "[RELATIONAL_STORE_UpdateDistributedInfo_JSKITS_TEST]"
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

export default function UpdateDistributedInfo() {
  describe('UpdateDistributedInfo', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach')
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
      }
    })

    afterEach(async () => {
      console.info(TAG + 'afterEach')
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest.db");
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest.db");
    })

    /**
     * @tc.number UpdateDistributedInfoTest0001
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo fail due to readonly db
     */
    it('UpdateDistributedInfoTest0001', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0001 start *************");
      if (rdbStore != undefined) {
        await rdbStore.close();
      }
      rdbStore1 = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      if (rdbStore1 != undefined) {
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          await rdbStore1.updateDistributedInfo(distributedInfo, predicates);
          expect(null).assertFail();
          console.error(`UpdateDistributedInfoTest0001 success`);
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0001 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      await rdbStore1?.close();
      rdbStore1 = undefined;
      console.log(TAG + "************* UpdateDistributedInfoTest0001 end *************");
    })

    /**
     * @tc.number UpdateDistributedInfoTest0002
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo fail due db is corrupt
     */
    it('UpdateDistributedInfoTest0002', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0002 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('UpdateDistributedInfoTest0002 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`UpdateDistributedInfoTest0002 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.log(`UpdateDistributedInfoTest0002 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          await corruptDb(context, STORE_CONFIG);
          await rdbStore.updateDistributedInfo(distributedInfo, predicates);
          console.error(`UpdateDistributedInfoTest0002 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0002 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800011);
        }
      }
      console.log(TAG + "************* UpdateDistributedInfoTest0002 end *************");
    })

    /**
     * @tc.number UpdateDistributedInfoTest0003
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo fail due device is invalid
     */
    it('UpdateDistributedInfoTest0003', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0003 start *************");
      if (rdbStore != undefined) {
        console.log(`UpdateDistributedInfoTest0003 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
            oriDevice: "test"
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          await rdbStore.updateDistributedInfo(distributedInfo, predicates);
          console.error(`UpdateDistributedInfoTest0003 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0003 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* UpdateDistributedInfoTest0003 end *************");
    })

    /**
     * @tc.number UpdateDistributedInfoTest0004
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo fail due SQLite: The database file is locked.
     */
    it('UpdateDistributedInfoTest0004', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0004 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('UpdateDistributedInfoTest0004 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`UpdateDistributedInfoTest0004 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`UpdateDistributedInfoTest0004 begin`);
        try {
          let transactions = await rdbStore?.createTransaction({
            transactionType: relationalStore.TransactionType.DEFERRED
          });
          let valueBucket: relationalStore.ValuesBucket = {};
          valueBucket["NAME"] = "lisa";
          valueBucket["AGE"] = 25;
          valueBucket["SALARY"] = 23456.6;
          let value = new Uint8Array([1, 2, 3, 4, 5]);
          valueBucket["CODES"] = value;
          await transactions.insert("EMPLOYEE", valueBucket);
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          await rdbStore.updateDistributedInfo(distributedInfo, predicates);
          console.error(`UpdateDistributedInfoTest0004 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0004 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800024);
        }
      }
      console.log(TAG + "************* UpdateDistributedInfoTest0004 end *************");
    })

    /**
     * @tc.number UpdateDistributedInfoTest0005
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo fail due db is close
     */
    it('UpdateDistributedInfoTest0005', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0005 start *************");
      if (rdbStore != undefined) {
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          await rdbStore.close();
          await rdbStore.updateDistributedInfo(distributedInfo, predicates);
          console.error(`UpdateDistributedInfoTest0005 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0005 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800014);
        }
      }
      console.log(TAG + "************* UpdateDistributedInfoTest0005 end *************");
    })

    /**
     * @tc.number UpdateDistributedInfoTest0006
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo fail due table is not distributedTable
     */
    it('UpdateDistributedInfoTest0006', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0006 start *************");
      if (rdbStore != undefined) {
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket[relationalStore.Field.CURSOR_FIELD]
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.log(`UpdateDistributedInfoTest0006 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          predicates.equalTo("CODES", value);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          await rdbStore.updateDistributedInfo(distributedInfo, predicates);
          console.error(`UpdateDistributedInfoTest0006 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0006 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800021);
        }
      }
      console.log(TAG + "************* UpdateDistributedInfoTest0006 end *************");
    })

    /**
     * @tc.number UpdateDistributedInfoTest0007
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo success insert update info return 1 flag form 2 to 0
     */
    it('UpdateDistributedInfoTest0007', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0007 start *************");
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('UpdateDistributedInfoTest0007 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`UpdateDistributedInfoTest0007 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`UpdateDistributedInfoTest0007 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          predicates.equalTo("CODES", value);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          predicates.equalTo(relationalStore.DistributedField.ORIGIN, relationalStore.DistributedOrigin.ORI_LOCAL);
          predicates.equalTo(relationalStore.DistributedField.ORIGIN_ORIDEVICE, "");
          let ret = await rdbStore.updateDistributedInfo(distributedInfo, predicates);
          console.error(`UpdateDistributedInfoTest0007 success`);
          expect(ret).assertEqual(1);
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0007 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* UpdateDistributedInfoTest0007 end *************");
    })

    /**
     * @tc.number UpdateDistributedInfoTest0008
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo success insert update info return 0 flag not changed
     */
    it('UpdateDistributedInfoTest0008', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0008 start *************");
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('UpdateDistributedInfoTest0008 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`UpdateDistributedInfoTest0008 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`UpdateDistributedInfoTest0008 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          predicates.equalTo("CODES", value);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          predicates.equalTo(relationalStore.DistributedField.ORIGIN, relationalStore.DistributedOrigin.ORI_REMOTE);
          predicates.equalTo(relationalStore.DistributedField.ORIGIN_ORIDEVICE, "");
          let ret = await rdbStore.updateDistributedInfo(distributedInfo, predicates);
          console.error(`UpdateDistributedInfoTest0008 success`);
          expect(ret).assertEqual(0);
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(2);
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0008 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* UpdateDistributedInfoTest0008 end *************");
    })

    /**
     * @tc.number UpdateDistributedInfoTest0009
     * @tc.name UpdateDistributedInfo
     * @tc.desc UpdateDistributedInfo success insert info return 1 flag form 2 to 0
     */
    it('UpdateDistributedInfoTest0009', 0, async () => {
      console.log(TAG + "************* UpdateDistributedInfoTest0009 start *************");
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('UpdateDistributedInfoTest0009 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`UpdateDistributedInfoTest0009 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["NAME"] = "Lisa";
        valueBucket["AGE"] = 25;
        valueBucket["SALARY"] = 23456.6;
        let value = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["CODES"] = value;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
          console.info(`Insert is successful`);
        } catch (e) {
          console.error(`Insert data failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        const predicates = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
        let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
        expect(resultSet.rowCount).assertEqual(1);
        expect(resultSet.goToFirstRow()).assertEqual(true);
        let row:relationalStore.ValuesBucket = resultSet.getRow();
        expect(row.flag).assertEqual(2);
        console.log(`UpdateDistributedInfoTest0009 begin`);
        try {
          const distributedInfo:relationalStore.DistributedInfo = {
            flag: relationalStore.DistributedOrigin.ORI_REMOTE,
          }
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          predicates.equalTo("CODES", value);
          predicates.equalTo("AGE", 25);
          predicates.equalTo("NAME", "Lisa");
          predicates.equalTo(relationalStore.DistributedField.ORIGIN, relationalStore.DistributedOrigin.ORI_LOCAL);
          predicates.notEqualTo(relationalStore.DistributedField.ORIGIN_ORIDEVICE, "test");
          let ret = await rdbStore.updateDistributedInfo(distributedInfo, predicates);
          console.error(`UpdateDistributedInfoTest0009 success`);
          expect(ret).assertEqual(1);
          const pre = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.flag).assertEqual(0);
        } catch (e) {
          console.error(`UpdateDistributedInfoTest0009 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* UpdateDistributedInfoTest0009 end *************");
    })
    console.log(TAG + "*************Unit Test Begin*************");
  })
}