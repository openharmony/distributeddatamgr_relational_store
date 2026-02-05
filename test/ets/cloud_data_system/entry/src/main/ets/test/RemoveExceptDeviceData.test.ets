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
const TAG = "[RELATIONAL_STORE_RemoveExceptDeviceData_JSKITS_TEST]"
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
const STORE_CONFIG1:relationalStore.StoreConfig = {
  name: "RdbTest.db",
  securityLevel: relationalStore.SecurityLevel.S1,
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

export default function removeExceptDeviceData() {
  describe('removeExceptDeviceData', () => {
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
     * @tc.number RemoveExceptDeviceDataTest0001
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data success
     */
    it('RemoveExceptDeviceDataTest0001', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0001 start *************");
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
          console.info('RemoveExceptDeviceDataTest0001 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0001 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0001 begin`);
          try {
            const tableAndDevice: Record<string, string[]> = {};
            tableAndDevice['EMPLOYEE'] = devices;
            await rdbStore.removeExceptDeviceData(tableAndDevice);
            console.error(`RemoveExceptDeviceDataTest0001 success`);
            expect(true).assertTrue();
          } catch (e) {
            console.error(`RemoveExceptDeviceDataTest0001 failed, code is ${e.code},message is ${e.message}`);
            expect(null).assertFail();
          }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0001 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0002
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to table is not single distributed table
     */
    it('RemoveExceptDeviceDataTest0002', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0002 start *************");
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
          console.info('RemoveExceptDeviceDataTest0002 EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0002 EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0002 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0002 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0002 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0002 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0003
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to table is not distributed table
     */
    it('RemoveExceptDeviceDataTest0003', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0003 start *************");
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
          console.info('RemoveExceptDeviceDataTest0003 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0003 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0003 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0003 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0003 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0003 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0004
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to db is readonly
     */
    it('RemoveExceptDeviceDataTest0004', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0004 start *************");
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
          console.info('RemoveExceptDeviceDataTest0004 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0004 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      rdbStore?.close();
      rdbStore1 = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      if (rdbStore1 == undefined) {
        expect().assertFail();
      } else {
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0004 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore1.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0004 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0004 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      rdbStore1 = undefined;
      console.log(TAG + "************* RemoveExceptDeviceDataTest0004 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0005
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to devices is empty
     */
    it('RemoveExceptDeviceDataTest0005', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0005 start *************");
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
          console.info('RemoveExceptDeviceDataTest0005 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0005 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        console.log(`RemoveExceptDeviceDataTest0005 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0005 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0005 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0004 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0006
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to map is empty
     */
    it('RemoveExceptDeviceDataTest0006', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0006 start *************");
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
          console.info('RemoveExceptDeviceDataTest0006 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0006 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`RemoveExceptDeviceDataTest0006 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0006 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0006 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0006 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0007
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to db is closed
     */
    it('RemoveExceptDeviceDataTest0007', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0007 start *************");
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
          console.info('RemoveExceptDeviceDataTest0007 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0007 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0007 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          rdbStore.close();
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0007 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0007 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800014);
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0007 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0008
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to table EMPLOYEE1 is not in db
     */
    it('RemoveExceptDeviceDataTest0008', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0008 start *************");
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
          console.info('RemoveExceptDeviceDataTest0008 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0008 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0008 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          tableAndDevice['EMPLOYEE1'] = devices;
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0008 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0008 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800021);
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0008 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0009
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to db is busy
     */
    it('RemoveExceptDeviceDataTest0009', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0009 start *************");
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
          console.info('RemoveExceptDeviceDataTest0009 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0009 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["data_key"] = 0;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["device"] = value4;
        valueBucket["ori_device"] = value4;
        valueBucket["timestamp"] = 0;
        valueBucket["wtimestamp"] = 0;
        valueBucket["flag"] = 0;
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
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0009 begin`);
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
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0009 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0009 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800024);
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0009 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0010
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data fail due to db is corrupted.
     */
    it('RemoveExceptDeviceDataTest0010', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0010 start *************");
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
          console.info('RemoveExceptDeviceDataTest0010 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0010 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0010 begin`);
        try {
          await corruptDb(context, STORE_CONFIG);
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0010 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0010 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800011);
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0010 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0011
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data success
     */
    it('RemoveExceptDeviceDataTest0011', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0011 start *************");
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
          console.info('RemoveExceptDeviceDataTest0011 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0011 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["data_key"] = 1;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["device"] = value4;
        valueBucket["ori_device"] = value4;
        valueBucket["timestamp"] = 0;
        valueBucket["wtimestamp"] = 0;
        valueBucket["flag"] = 0;
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
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0011 begin`);
        try {
          let valueBucket1: relationalStore.ValuesBucket = {};
          valueBucket1["NAME"] = "lisa";
          valueBucket1["AGE"] = 25;
          valueBucket1["SALARY"] = 23456.6;
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          valueBucket1["CODES"] = value4;
          await rdbStore.insert('EMPLOYEE', valueBucket1);
          let pre:relationalStore.RdbPredicates = new relationalStore.RdbPredicates("EMPLOYEE");
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.NAME).assertEqual("lisa");
          resultSet.close;
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0011 success`);
          resultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(0);
          expect(resultSet.goToFirstRow()).assertEqual(false);
          resultSet.close;
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0011 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0011 end *************");
    })

    /**
     * @tc.number RemoveExceptDeviceDataTest0012
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data fail due to delete db
     */
    it('RemoveExceptDeviceDataTest0012', 0, async () => {
      console.log(TAG + "************* RemoveExceptDeviceDataTest0012 start *************");
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
          console.info('RemoveExceptDeviceDataTest0012 EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`RemoveExceptDeviceDataTest0012 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["data_key"] = 1;
        let value4 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["device"] = value4;
        valueBucket["ori_device"] = value4;
        valueBucket["timestamp"] = 0;
        valueBucket["wtimestamp"] = 0;
        valueBucket["flag"] = 0;
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
        const devices: string[] = [];
        devices.push("test");
        console.log(`RemoveExceptDeviceDataTest0012 begin`);
        try {
          let valueBucket1: relationalStore.ValuesBucket = {};
          valueBucket1["NAME"] = "lisa";
          valueBucket1["AGE"] = 25;
          valueBucket1["SALARY"] = 23456.6;
          let value4 = new Uint8Array([1, 2, 3, 4, 5]);
          valueBucket1["CODES"] = value4;
          await rdbStore.insert('EMPLOYEE', valueBucket1);
          let pre:relationalStore.RdbPredicates = new relationalStore.RdbPredicates("EMPLOYEE");
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.NAME).assertEqual("lisa");
          resultSet.close;
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await relationalStore.deleteRdbStore(context, "RdbTest.db");
          await rdbStore.removeExceptDeviceData(tableAndDevice);
          console.error(`RemoveExceptDeviceDataTest0012 success`);
          resultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          resultSet.close;
        } catch (e) {
          console.error(`RemoveExceptDeviceDataTest0012 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800042);
        }
      }
      console.log(TAG + "************* RemoveExceptDeviceDataTest0012 end *************");
    })
    console.log(TAG + "*************Unit Test Begin*************");
  })
}