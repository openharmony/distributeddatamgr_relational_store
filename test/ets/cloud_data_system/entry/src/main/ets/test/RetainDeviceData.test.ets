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
const TAG = "[RELATIONAL_STORE_RetainDeviceData_JSKITS_TEST]"
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

export default function RetainDeviceData() {
  describe('RetainDeviceData', () => {
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
    })

    /**
     * @tc.number RetainDeviceDataTest0001
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data success devices is empty & map is not empty
     */
    it('RetainDeviceDataTest0001', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0001 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('RetainDeviceDataTest0001 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`RetainDeviceDataTest0001 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        console.log(`RetainDeviceDataTest0001 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.retainDeviceData(tableAndDevice);
          console.error(`RetainDeviceDataTest0001 success`);
        } catch (e) {
          console.error(`RetainDeviceDataTest0001 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0001 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0002
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to table is not single distributed table
     */
    it('RetainDeviceDataTest0002', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0002 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('RetainDeviceDataTest0002 EMPLOYEE successfully.');
        } catch (err) {
          console.error(`RetainDeviceDataTest0002 EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`RetainDeviceDataTest0002 begin`);
        const devices: string[] = [];
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.retainDeviceData(tableAndDevice);
          console.error(`RetainDeviceDataTest0002 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RetainDeviceDataTest0002 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0002 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0003
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to table is not distributed table
     */
    it('RetainDeviceDataTest0003', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0003 start *************");
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE1 (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE1"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('RetainDeviceDataTest0001 EMPLOYEE1 SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`RetainDeviceDataTest0001 EMPLOYEE1 SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`RetainDeviceDataTest0003 begin`);
        try {
          const devices: string[] = [];
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.retainDeviceData(tableAndDevice);
          console.error(`RetainDeviceDataTest0003 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RetainDeviceDataTest0003 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0003 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0004
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to db is readonly
     */
    it('RetainDeviceDataTest0004', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0004 start *************");
      rdbStore1 = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      if (rdbStore1 != undefined) {
        try {
          await rdbStore1.retainDeviceData();
          console.error(`RetainDeviceDataTest0004 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RetainDeviceDataTest0004 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      await rdbStore1?.close();
      rdbStore1 = undefined;
      console.log(TAG + "************* RetainDeviceDataTest0004 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0006
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data success, map is empty
     */
    it('RetainDeviceDataTest0006', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0006 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('RetainDeviceDataTest0006 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`RetainDeviceDataTest0006 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`RetainDeviceDataTest0006 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          await rdbStore.retainDeviceData(tableAndDevice);
          console.error(`RetainDeviceDataTest0006 success`);
        } catch (e) {
          console.error(`RetainDeviceDataTest0006 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0006 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0007
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to db is closed
     */
    it('RetainDeviceDataTest0007', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0007 start *************");
      if (rdbStore != undefined) {
        console.log(`RetainDeviceDataTest0007 begin`);
        try {
          await rdbStore.close();
          await rdbStore.retainDeviceData();
          console.error(`RetainDeviceDataTest0007 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RetainDeviceDataTest0007 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800014);
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0007 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0008
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to table EMPLOYEE1 is not in db
     */
    it('RetainDeviceDataTest0008', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0008 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('RetainDeviceDataTest0008 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`RetainDeviceDataTest0008 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        console.log(`RetainDeviceDataTest0008 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          tableAndDevice['EMPLOYEE1'] = devices;
          await rdbStore.retainDeviceData(tableAndDevice);
          console.error(`RetainDeviceDataTest0008 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RetainDeviceDataTest0008 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800021);
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0008 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0009
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to db is busy
     */
    it('RetainDeviceDataTest0009', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0009 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('RetainDeviceDataTest0009 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`RetainDeviceDataTest0009 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`RetainDeviceDataTest0009 begin`);
        try {
          let transactions = await rdbStore?.createTransaction({
            transactionType: relationalStore.TransactionType.DEFERRED
          });
          let valueBucket1: relationalStore.ValuesBucket = {};
          valueBucket1["NAME"] = "lisa";
          valueBucket1["AGE"] = 25;
          valueBucket1["SALARY"] = 23456.6;
          let value1 = new Uint8Array([1, 2, 3, 4, 5]);
          valueBucket1["CODES"] = value1;
          await transactions.insert("EMPLOYEE", valueBucket1);
          await rdbStore.retainDeviceData();
          console.error(`RetainDeviceDataTest0009 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RetainDeviceDataTest0009 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800024);
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0009 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0010
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data fail due to db is corrupted.
     */
    it('RetainDeviceDataTest0010', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0010 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('RetainDeviceDataTest0010 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`RetainDeviceDataTest0010 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`RetainDeviceDataTest0010 begin`);
        try {
          await corruptDb(context, STORE_CONFIG);
          await rdbStore.retainDeviceData();
          console.error(`RetainDeviceDataTest0010 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RetainDeviceDataTest0010 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800011);
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0010 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0011
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data success
     */
    it('RetainDeviceDataTest0011', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0011 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('RetainDeviceDataTest0011 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`RetainDeviceDataTest0011 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        let valueBucket: relationalStore.ValuesBucket = {};
        valueBucket["data_key"] = 1;
        let value1 = new Uint8Array([1, 2, 3, 4, 5]);
        valueBucket["device"] = value1;
        valueBucket["ori_device"] = value1;
        valueBucket["timestamp"] = 0;
        valueBucket["wtimestamp"] = 0;
        valueBucket["flag"] = 0;
        valueBucket["hash_key"] = value1;
        valueBucket["cloud_gid"] = "test";
        valueBucket["extend_field"] = value1;
        valueBucket["cursor"] = 0;
        valueBucket["version"] = "test";
        valueBucket["sharing_resource"] = "test";
        valueBucket["status"] = 0;
        try {
          await (rdbStore as relationalStore.RdbStore).insert("naturalbase_rdb_aux_EMPLOYEE_log", valueBucket);
          console.info(`Insert is successful`);
        } catch (err) {
          console.error(`Insert is failed`);
          expect(null).assertFail();
        }
        const devices: string[] = [];
        console.log(`RetainDeviceDataTest0011 begin`);
        try {
          let valueBucket1: relationalStore.ValuesBucket = {};
          valueBucket1["NAME"] = "lisa";
          valueBucket1["AGE"] = 25;
          valueBucket1["SALARY"] = 23456.6;
          let value1 = new Uint8Array([1, 2, 3, 4, 5]);
          valueBucket1["CODES"] = value1;
          await rdbStore.insert('EMPLOYEE', valueBucket1);
          let pre:relationalStore.RdbPredicates = new relationalStore.RdbPredicates("EMPLOYEE");
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.NAME).assertEqual("lisa");
          resultSet.close();
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.retainDeviceData(tableAndDevice);
          console.error(`RetainDeviceDataTest0011 success`);
          resultSet = await rdbStore?.query(pre) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(0);
          expect(resultSet.goToFirstRow()).assertEqual(false);
          resultSet.close();
        } catch (e) {
          console.error(`RetainDeviceDataTest0011 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }

      console.log(TAG + "************* RetainDeviceDataTest0011 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0012
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data fail due to delete db
     */
    it('RetainDeviceDataTest0012', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0012 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('RetainDeviceDataTest0012 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`RetainDeviceDataTest0012 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`RetainDeviceDataTest0012 begin`);
        try {
          await relationalStore.deleteRdbStore(context, "RdbTest.db");
          await rdbStore.retainDeviceData();
          console.error(`RetainDeviceDataTest0012 success`);
        } catch (e) {
          console.error(`RetainDeviceDataTest0012 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800042);
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0012 end *************");
    })

    /**
     * @tc.number retainDeviceDataTest0013
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data fail due to tableName is empty string
     */
    it('retainDeviceDataTest0013', 0, async () => {
      console.log(TAG + "************* retainDeviceDataTest0013 start *************");
      if (rdbStore != undefined) {
        const devices: string[] = [];
        console.log(`retainDeviceDataTest0013 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          let tableName: string = '';
          tableAndDevice[tableName] = devices;
          await rdbStore.retainDeviceData(tableAndDevice);
          console.error(`retainDeviceDataTest0013 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`retainDeviceDataTest0013 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* retainDeviceDataTest0013 end *************");
    })

    /**
     * @tc.number retainDeviceDataTest0014
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data fail due to device is empty string
     */
    it('retainDeviceDataTest0014', 0, async () => {
      console.log(TAG + "************* retainDeviceDataTest0014 start *************");
      if (rdbStore != undefined) {
        const devices: string[] = [];
        let device: string = '';
        devices.push(device);
        console.log(`retainDeviceDataTest0013 begin`);
        try {
          const tableAndDevice: Record<string, string[]> = {};
          tableAndDevice['EMPLOYEE'] = devices;
          await rdbStore.retainDeviceData(tableAndDevice);
          console.error(`retainDeviceDataTest0014 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`retainDeviceDataTest0014 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* retainDeviceDataTest0014 end *************");
    })

    /**
     * @tc.number retainDeviceDataTest0015
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data success no parameter
     */
    it('retainDeviceDataTest0015', 0, async () => {
      console.log(TAG + "************* retainDeviceDataTest0015 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('retainDeviceDataTest0015 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`retainDeviceDataTest0015 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`retainDeviceDataTest0015 begin`);
        try {
          await rdbStore.retainDeviceData();
          console.error(`retainDeviceDataTest0015 success`);
        } catch (e) {
          console.error(`retainDeviceDataTest0015 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* retainDeviceDataTest0015 end *************");
    })

    /**
     * @tc.number RetainDeviceDataTest0016
     * @tc.name Remove ExceptDevice data
     * @tc.desc Remove ExceptDevice data file due to db is not distributed db
     */
    it('RetainDeviceDataTest0016', 0, async () => {
      console.log(TAG + "************* RetainDeviceDataTest0016 start *************");
      if (rdbStore != undefined) {
        console.log(`RetainDeviceDataTest0003 begin`);
        try {
          await rdbStore.retainDeviceData();
          console.error(`RetainDeviceDataTest0016 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`RetainDeviceDataTest0016 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      console.log(TAG + "************* RetainDeviceDataTest0016 end *************");
    })
    console.log(TAG + "*************Unit Test Begin*************");
  })
}