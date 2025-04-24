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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, Level, Size, TestType } from "@ohos/hypium";
import data_relationalStore from '@ohos.data.relationalStore';
import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';

let context = abilityDelegatorRegistry.getAbilityDelegator().getAppContext().getApplicationContext();
const TAG = "[RELATIONAL_STORE_ON_ERROR]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
const CREATE_TABLE_TEST4 = "CREATE TABLE users (" + "id INTEGER PRIMARY KEY," + "username TEXT UNIQUE," +
  "email TEXT NOT NULL)";
const STORE_CONFIG :data_relationalStore.StoreConfig= {
  name: "errorlog.db",
  securityLevel: data_relationalStore.SecurityLevel.S1,
}

let rdbStore:data_relationalStore.RdbStore;
export default function rdbStoreErrorlogTest() {
  describe('rdbStoreErrorlogTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach')
      rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
      rdbStore.executeSql(CREATE_TABLE_TEST, null);
      rdbStore.executeSql(CREATE_TABLE_TEST4, null);
      let u8 = new Uint8Array([1, 2, 3])
      const valueBucketUser:data_relationalStore.ValuesBucket = {
        "id": 1,
        "username":'user1',
        "email":'user1@example.com',
      };
      await rdbStore.insert("users", valueBucketUser);
      const valueBucket:data_relationalStore.ValuesBucket= {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await rdbStore.insert("test", valueBucket);
    })

    afterEach(async() => {
      console.info(TAG + 'afterEach')
      rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
      rdbStore.close();
      await data_relationalStore.deleteRdbStore(context, "errorlog.db");
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

  console.log(TAG + "*************Unit Test Begin*************");

  /**
   * @tc.number SUB_DDM_AppDataFWK_JSRDB_Onerrorlog_0001
   * @tc.name Normal test case of Onerrorlog Already closed
   * @tc.desc 1.create db 2.close db 3.Onerrorlog
   */
  it('testRdbStoreOnerrorlog0001', 0, async () =>{
    console.log(TAG + "************* testRdbStoreOnerrorlog0001 start *************");
    try {
      rdbStore.close();
      let exceptionMessage:data_relationalStore.ExceptionMessage;
      rdbStore.on('errorlog', exceptionMessage => {
        console.log(`error log is ${exceptionMessage.code}, ${exceptionMessage.message}, ${exceptionMessage.sql}`)
      });
    } catch (err) {
      expect(err.code == 14800014).assertTrue();
      console.error(`errorlog on is failed code:${err.code},message:${err.message}`);
    }
    console.log(TAG + "************* testRdbStoreOnerrorlog0001 end *************");
  })

  /**
   * @tc.number SUB_DDM_AppDataFWK_JSRDB_Onerrorlog_0002
   * @tc.name Normal test case of Onerrorlog SQLITE_ERROR
   * @tc.desc 1.Onerrorlog 2.execute sql with SQLITE_ERROR
   */
  it('testRdbStoreOnerrorlog0002',  0, async ()=> {
    console.log(TAG + "************* testRdbStoreOnerrorlog0002 start *************");
    try {
      let exceptionMessage:data_relationalStore.ExceptionMessage;
      rdbStore.on('errorlog', exceptionMessage => {
        let sqliteCode = exceptionMessage.code;
        let sqliteMessage = exceptionMessage.message;
        let errSQL = exceptionMessage.sql;
        console.info(`error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
        expect(sqliteCode == 1).assertTrue();
        expect(sqliteMessage == "table test has no column named exsc").assertTrue();
        expect(errSQL == "INSERT INTO test(age,blobType,exsc,name,salary) VALUES (?,?,?,?,?)").assertTrue();
      });
      console.log(`errorlog on is success`);
    } catch (err) {
      console.error(`errorlog on is failed ${err.code}`);
    }
    try {
      let u8:Uint8Array = new Uint8Array([1, 2, 3]);
      const valueBucket:data_relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
        "exsc": 100,
      }
      await rdbStore.insert("test", valueBucket);
      expect().assertFail();
    } catch (err) {
      console.error(`errorlog on is failed code:${err.code},message:${err.message}`);
      expect(e.code == 14800021).assertTrue();
    }
    rdbStore.off('errorlog');
    console.log(TAG + "************* testRdbStoreOnerrorlog0002 end *************");
  })

  /**
    * @tc.number SUB_DDM_AppDataFWK_JSRDB_Onerrorlog_0003
    * @tc.name Normal test case of Onerrorlog SQLITE_MISMATCH
    * @tc.desc 1.Insert data
    */
  it('testRdbStoreOnerrorlog0003', 0, async ()=> {
    console.log(TAG + "************* testRdbStoreOnerrorlog0003 start *************");
    let exceptionMessage = (exceptionMessage: data_relationalStore.ExceptionMessage) => {
      let sqliteCode = exceptionMessage.code;
      let sqliteMessage = exceptionMessage.message;
      let errSQL = exceptionMessage.sql;
      expect(sqliteCode == 20).assertTrue();
      expect(sqliteMessage == "datatype mismatch").assertTrue();
      expect(errSQL == "INSERT INTO test(age,blobType,id,name,salary) VALUES (?,?,?,?,?)").assertTrue();
      console.info(`errCode is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
    };
    try {
      rdbStore.on('errorlog', exceptionMessage);
    } catch (err) {
      console.error(`on err log failed, code is ${err.code},message is ${err.message}`);
      expect().assertFail();
    }
    let u8 = new Uint8Array([1, 2, 3]);
    let transaction = await rdbStore?.createTransaction({
      transactionType: data_relationalStore.TransactionType.IMMEDIATE
    });
    try {
      const valueBucket :data_relationalStore.ValuesBucket = {
        "id": "test",
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      };
      let row = transaction?.insertSync("test", valueBucket);
      console.log(TAG + "testRdbStoreOnerrorlog0003 insert row:" + row);
      expect(null).assertFail();
      await transaction?.commit();
    } catch (e) {
      await transaction?.rollback();
      console.log(TAG + e + " code: " + e.code);
      expect(e.code == 14800033).assertTrue();
      console.log(TAG + "testRdbStoreOnerrorlog0003 failed");
    }
    rdbStore.off('errorlog');
    console.log(TAG + "************* testRdbStoreOnerrorlog0003 end *************");
  })

  /**
    * @tc.number SUB_DDM_AppDataFWK_JSRDB_Onerrorlog_0004
    * @tc.name Normal test case of Onerrorlog performance
    * @tc.desc 1.Insert data
    */
  it('testRdbStoreOnerrorlog0004', 0, async ()=> {
    console.log(TAG + "************* testRdbStoreOnerrorlog0004 start *************");
    try {
      let averageTime = 0;
      let startTime = new Date().getTime();
      for (let i = 0; i < 2000; ++i) {
        let exceptionMessage:data_relationalStore.ExceptionMessage|undefined = undefined;
        rdbStore.on('errorlog', exceptionMessage => {});
      }
      let endTime = new Date().getTime();
      averageTime = ((endTime - startTime) * 1000) / 2000;
      expect(averageTime < 1000).assertTrue();
      console.info(TAG + " testRdbStoreOnerrorlog0004 average time is: " + averageTime + " μs");
    } catch (err) {
      console.error(`on err log failed, code is ${err.code},message is ${err.message}`);
      expect(true).assertFail();
    }
    rdbStore.off('errorlog');
    console.log(TAG + "************* testRdbStoreOnerrorlog0004 end *************");
  })

  /**
    * @tc.number SUB_DDM_AppDataFWK_JSRDB_Onerrorlog_0005
    * @tc.name Normal test case of Onerrorlog and offerrorlog
    * @tc.desc 1.Insert data
    */
  it('testRdbStoreOnerrorlog0005', 0, async ()=> {
    console.log(TAG + "************* testRdbStoreOnerrorlog0005 start *************");
    try {
      let exceptionMessage:data_relationalStore.ExceptionMessage;
      rdbStore.on('errorlog', exceptionMessage => {
        let sqliteCode = exceptionMessage.code;
        let sqliteMessage = exceptionMessage.message;
        let errSQL = exceptionMessage.sql;
        expect(sqliteCode != 1).assertTrue();
        expect(sqliteMessage != "table test has no column named exsc").assertTrue();
        expect(errSQL != "INSERT INTO test(age,blobType,exsc,name,salary) VALUES (?,?,?,?,?)").assertTrue();
        console.info(`error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
      });
      rdbStore.off('errorlog');
    } catch (err) {
      console.error(`errorlog on is failed ${err.code}`);
    }
    try {
      let u8:Uint8Array = new Uint8Array([1, 2, 3]);
      const valueBucket:data_relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
        "exsc": 100,
      }
      await rdbStore.insert("test", valueBucket);
      expect().assertFail();
    } catch (err) {
      console.error(`errorlog on is failed code:${err.code},message:${err.message}`);
      expect(true).assertTrue();
    }
    console.log(TAG + "************* testRdbStoreOnerrorlog0005 end *************");
  })
  console.log(TAG + "*************Unit Test End*************");
  })
}