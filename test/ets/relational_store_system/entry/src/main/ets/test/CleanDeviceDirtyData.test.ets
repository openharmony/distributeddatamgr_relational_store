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

export default function CleanDeviceDirtyData() {
  describe('CleanDeviceDirtyData', () => {
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
     * @tc.number CleanDeviceDirtyDataTest0001
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due to readonly db
     */
    it('CleanDeviceDirtyDataTest0001', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0001 start *************");
      if (rdbStore != undefined) {
        await rdbStore.close();
      }
      rdbStore1 = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      if (rdbStore1 != undefined) {
        try {
          await rdbStore1.cleanDeviceDirtyData("EMPLOYEE");
          expect(null).assertFail();
          console.info(`CleanDeviceDirtyDataTest0001 success`);
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0001 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800043);
        }
      }
      await rdbStore1?.close();
      rdbStore1 = undefined;
      console.log(TAG + "************* CleanDeviceDirtyDataTest0001 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0002
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due db is corrupt
     */
    it('CleanDeviceDirtyDataTest0002', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0002 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('CleanDeviceDirtyDataTest0002 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0002 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0002 begin`);
        try {
          await corruptDb(context, STORE_CONFIG);
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE");
          console.info(`CleanDeviceDirtyDataTest0002 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0002 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800011);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0002 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0003
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due SQLite: The database file is locked.
     */
    it('CleanDeviceDirtyDataTest0003', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0003 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('CleanDeviceDirtyDataTest0003 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0003 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0003 begin`);
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
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE");
          console.info(`CleanDeviceDirtyDataTest0003 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0003 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800024);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0003 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0004
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due db is close
     */
    it('CleanDeviceDirtyDataTest0004', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0004 start *************");
      if (rdbStore != undefined) {
        try {
          await rdbStore.close();
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE");
          console.info(`CleanDeviceDirtyDataTest0004 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0004 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800014);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0004 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0005
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due table is not distributedTable
     */
    it('CleanDeviceDirtyDataTest0005', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0005 start *************");
      if (rdbStore != undefined) {
        console.log(`CleanDeviceDirtyDataTest0005 begin`);
        try {
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE");
          console.info(`CleanDeviceDirtyDataTest0005 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0005 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800021);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0005 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0006
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData success
     */
    it('CleanDeviceDirtyDataTest0006', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0006 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('CleanDeviceDirtyDataTest0006 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0006 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
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
        predicates.equalTo('flag', 2);
        const valueBucket1: relationalStore.ValuesBucket = {
          ori_device: value,
          flag: 9,
        };
        try {
          await rdbStore.update(valueBucket1, predicates);
          console.info(`CleanDeviceDirtyDataTest0006 update is successful`);
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0006 update is failed`);
        }
        console.log(`CleanDeviceDirtyDataTest0006 begin`);
        try {
          const pre = new relationalStore.RdbPredicates('EMPLOYEE');
          pre.greaterThan(relationalStore.DistributedField.CURSOR_FIELD, 0);
          pre.and();
          pre.equalTo(relationalStore.DistributedField.ORIGIN, relationalStore.DistributedOrigin.ORI_REMOTE);
          pre.equalTo("AGE", 25);
          pre.notEqualTo(relationalStore.DistributedField.ORIGIN_ORIDEVICE, "");
          pre.orderByAsc(relationalStore.DistributedField.CURSOR_FIELD);
          let resultSetLog:relationalStore.ResultSet = await rdbStore?.query(pre, ["ID", "NAME"]) as relationalStore.ResultSet;
          expect(resultSetLog.rowCount).assertEqual(1);
          expect(resultSetLog.goToFirstRow()).assertEqual(true);
          let cursor : number = resultSetLog.getLong(resultSetLog.getColumnIndex(relationalStore.Field.CURSOR_FIELD));
          let deleteFlag : number = resultSetLog.getLong(resultSetLog.getColumnIndex(relationalStore.Field.DELETED_FLAG_FIELD));
          let id : number = resultSetLog.getLong(resultSetLog.getColumnIndex("ID"));
          let name : string = resultSetLog.getString(resultSetLog.getColumnIndex("NAME"));
          expect(cursor).assertEqual(1);
          expect(deleteFlag).assertEqual(1);
          expect(id).assertEqual(1);
          expect(name).assertEqual("Lisa");
          const predicates = new relationalStore.RdbPredicates('EMPLOYEE');
          let resultSet:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
          expect(resultSet.rowCount).assertEqual(1);
          expect(resultSet.goToFirstRow()).assertEqual(true);
          let row:relationalStore.ValuesBucket = resultSet.getRow();
          expect(row.NAME).assertEqual("Lisa");
          console.log(`CleanDeviceDirtyDataTest0006 begin1`);
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE", cursor);
          console.info(`CleanDeviceDirtyDataTest0006 success`);
          const pre1 = new relationalStore.RdbPredicates('naturalbase_rdb_aux_EMPLOYEE_log');
          let resultSet1:relationalStore.ResultSet = await rdbStore?.query(pre1) as relationalStore.ResultSet;
          expect(resultSet1.rowCount).assertEqual(0);
          expect(resultSet1.goToFirstRow()).assertEqual(false);
          let resultSet2:relationalStore.ResultSet = await rdbStore?.query(predicates) as relationalStore.ResultSet;
          expect(resultSet2.rowCount).assertEqual(0);
          expect(resultSet2.goToFirstRow()).assertEqual(false);
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0006 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0006 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0007
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due to invalid table name and cursor parameter
     */
    it('CleanDeviceDirtyDataTest0007', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0007 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('CleanDeviceDirtyDataTest0007 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0007 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0007 begin`);
        try {
          await rdbStore.cleanDeviceDirtyData("***", 0);
          console.info(`CleanDeviceDirtyDataTest0007 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0007 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0007 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0008
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData success single distributedTable
     */
    it('CleanDeviceDirtyDataTest0008', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0008 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('CleanDeviceDirtyDataTest0008 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0008 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0008 begin`);
        try {
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE");
          console.info(`CleanDeviceDirtyDataTest0008 success`);
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0008 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0008 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0009
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData success split by device distributedTable
     */
    it('CleanDeviceDirtyDataTest0009', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0009 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('CleanDeviceDirtyDataTest0009 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0009 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0009 begin`);
        try {
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE");
          console.info(`CleanDeviceDirtyDataTest0009 success`);
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0009 failed, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0009 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0010
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due to table is not in db
     */
    it('CleanDeviceDirtyDataTest0010', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0010 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('CleanDeviceDirtyDataTest0010 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0010 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0010 begin`);
        try {
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE1");
          console.info(`CleanDeviceDirtyDataTest0010 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0010 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800021);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0010 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0011
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due to invalid cursor parameter
     */
    it('CleanDeviceDirtyDataTest0011', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0011 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('CleanDeviceDirtyDataTest0011 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0011 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0011 begin`);
        try {
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE", -1);
          console.info(`CleanDeviceDirtyDataTest0011 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0011 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0011 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0012
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due to invalid table name
     */
    it('CleanDeviceDirtyDataTest0012', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0012 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('CleanDeviceDirtyDataTest0012 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0012 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0012 begin`);
        try {
          await rdbStore.cleanDeviceDirtyData("***");
          console.info(`CleanDeviceDirtyDataTest0012 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0012 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0012 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0013
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due to invalid cursor = 0
     */
    it('CleanDeviceDirtyDataTest0013', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0013 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('CleanDeviceDirtyDataTest0013 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0013 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0013 begin`);
        try {
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE", 0);
          console.info(`CleanDeviceDirtyDataTest0013 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0013 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0013 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0014
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due to invalid table name
     */
    it('CleanDeviceDirtyDataTest0014', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0014 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('CleanDeviceDirtyDataTest0014 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0014 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0014 begin`);
        try {
          await rdbStore.cleanDeviceDirtyData("EMPLOYEE.ls", 1);
          console.info(`CleanDeviceDirtyDataTest0014 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0014 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0014 end *************");
    })

    /**
     * @tc.number CleanDeviceDirtyDataTest0015
     * @tc.name CleanDeviceDirtyData
     * @tc.desc CleanDeviceDirtyData fail due to invalid table name length is 257
     */
    it('CleanDeviceDirtyDataTest0015', 0, async () => {
      console.log(TAG + "************* CleanDeviceDirtyDataTest0015 start *************");
      if (rdbStore != undefined) {
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('CleanDeviceDirtyDataTest0015 EMPLOYEE SINGLE_VERSION successfully.');
        } catch (err) {
          console.error(`CleanDeviceDirtyDataTest0015 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.log(`CleanDeviceDirtyDataTest0015 begin`);
        try {
          let tableName = "s";
          for(let i = 0; i < 257; i++) {
            tableName += "s";
          }
          await rdbStore.cleanDeviceDirtyData(tableName, 1);
          console.info(`CleanDeviceDirtyDataTest0015 success`);
          expect(null).assertFail();
        } catch (e) {
          console.error(`CleanDeviceDirtyDataTest0015 failed, code is ${e.code},message is ${e.message}`);
          expect(e.code).assertEqual(14800001);
        }
      }
      console.log(TAG + "************* CleanDeviceDirtyDataTest0015 end *************");
    })
    console.log(TAG + "*************Unit Test Begin*************");
  })
}