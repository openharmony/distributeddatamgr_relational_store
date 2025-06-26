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
const CREATE_TABLE_TEST4 = "CREATE TABLE IF NOT EXISTS users (" + "id INTEGER PRIMARY KEY," + "username TEXT UNIQUE," +
  "email TEXT NOT NULL)";
const STORE_CONFIG: data_relationalStore.StoreConfig = {
  name: "sqliteErrorOccurred.db",
  securityLevel: data_relationalStore.SecurityLevel.S1,
}

let rdbStore: data_relationalStore.RdbStore;

export default function rdbStoreSqliteErrorOccurredTest() {
  describe('rdbStoreSqliteErrorOccurredTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async (done: Function) => {
      console.info(TAG + 'beforeEach')
      rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
      await rdbStore.executeSql(CREATE_TABLE_TEST);
      await rdbStore.executeSql(CREATE_TABLE_TEST4);
      let u8 = new Uint8Array([1, 2, 3])
      const valueBucketUser: data_relationalStore.ValuesBucket = {
        "username": 'user1',
        "email": 'user1@example.com',
      };
      await rdbStore.insert("users", valueBucketUser);
      const valueBucket: data_relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await rdbStore.insert("test", valueBucket);
      done();
    })

    afterEach(async (done: Function) => {
      console.info(TAG + 'afterEach')
      try {
        rdbStore.off('sqliteErrorOccurred');
        await rdbStore.close();
      } catch (err) {
        console.log(`afterEach error, failed code:${err.code},message:${err.message}`);
      }
      await data_relationalStore.deleteRdbStore(context, "sqliteErrorOccurred.db");
      done();
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0001
     * @tc.name Normal test case of OnsqliteErrorOccurred Already closed
     * @tc.desc 1.create db 2.close db 3.OnsqliteErrorOccurred
     */
    it('testRdbStoreOnsqliteErrorOccurred0001', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0001 start *************");
      try {
        rdbStore.close();
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          console.log(`error log is ${exceptionMessage.code}`)
        });
      } catch (err) {
        expect(err.code == 14800014).assertTrue();
        console.error(`error is failed code:${err.code},message:${err.message}`);
      }
      done();
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0001 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0002
     * @tc.name Normal test case of OnsqliteErrorOccurred SQLITE_ERROR
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute sql with SQLITE_ERROR
     */
    it('testRdbStoreOnsqliteErrorOccurred0002', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0002 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "table test has no column named exsc").assertTrue();
          expect(errSQL == "INSERT INTO test(age,blobType,exsc,name,salary) VALUES (?,?,?,?,?)").assertTrue();
          done();
        });
        console.log(`sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        let u8: Uint8Array = new Uint8Array([1, 2, 3]);
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
          "exsc": 100,
        }
        await rdbStore.insert("test", valueBucket);
        expect(true).assertFail();
      } catch (err) {
        console.error(`sqliteErrorOccurred on is failed code:${err.code},message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0002 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0003
     * @tc.name Normal test case of OnsqliteErrorOccurred SQLITE_MISMATCH
     * @tc.desc 1.Insert data
     */
    it('testRdbStoreOnsqliteErrorOccurred0003', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0003 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          expect(sqliteCode == 20).assertTrue();
          expect(sqliteMessage == "datatype mismatch").assertTrue();
          expect(errSQL == "INSERT INTO test(age,blobType,id,name,salary) VALUES (?,?,?,?,?)").assertTrue();
          console.info(`errCode is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          done();
        });
      } catch (err) {
        console.error(`err log failed, code is ${err.code},message is ${err.message}`);
        expect(true).assertFail();
      }
      let u8 = new Uint8Array([1, 2, 3]);
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "id": "test",
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        };
        let row = transaction?.insertSync("test", valueBucket);
        console.log(TAG + "testRdbStoreOnsqliteErrorOccurred0003 insert row:" + row);
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(TAG + e + " code: " + e.code);
        expect(e.code == 14800033).assertTrue();
        console.log(TAG + "testRdbStoreOnsqliteErrorOccurred0003 failed");
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0003 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0004
     * @tc.name Normal test case of OnsqliteErrorOccurred performance
     * @tc.desc 1.Insert data
     */
    it('testRdbStoreOnsqliteErrorOccurred0004', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0004 start *************");
      try {
        let averageTime = 0;
        let startTime = new Date().getTime();
        for (let i = 0; i < 2000; ++i) {
          let exceptionMessage: data_relationalStore.ExceptionMessage | undefined = undefined;
          rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          });
        }
        let endTime = new Date().getTime();
        averageTime = ((endTime - startTime) * 1000) / 2000;
        expect(averageTime < 1000).assertTrue();
        console.info(TAG + " testRdbStoreOnsqliteErrorOccurred0004 average time is: " + averageTime + " μs");
      } catch (err) {
        console.error(`on err log failed, code is ${err.code},message is ${err.message}`);
        expect(true).assertFail();
      }
      rdbStore.off('sqliteErrorOccurred');
      done();
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0004 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0005
     * @tc.name Normal test case of OnsqliteErrorOccurred and offsqliteErrorOccurred
     * @tc.desc 1.Insert data
     */
    it('testRdbStoreOnsqliteErrorOccurred0005', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0005 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          expect(exceptionMessage.code === 0).assertTrue();
        });
        rdbStore.off('sqliteErrorOccurred');
      } catch (err) {
        console.error(`sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        let u8: Uint8Array = new Uint8Array([1, 2, 3]);
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
          "exsc": 100,
        }
        await rdbStore.insert("test", valueBucket);
        expect().assertFail();
      } catch (err) {
        console.error(`sqliteErrorOccurred on is failed code:${err.code},message:${err.message}`);
        expect(true).assertTrue();
      }
      done();
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0005 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0006
     * @tc.name Abormal test case of OnErrorlog
     * @tc.desc 1.Insert data
     */
    it('testRdbStoreOnsqliteErrorOccurred0006',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0006 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        done()
        return
      }
      let STORE_CONFIG1: data_relationalStore.StoreConfig = {
        name: 'rdbStore2.db',
        securityLevel: data_relationalStore.SecurityLevel.S1,
        vector: true,
      };
      let rdbStore1 = await data_relationalStore.getRdbStore(context, STORE_CONFIG1)
      try{
        rdbStore1.on('sqliteErrorOccurred', exceptionMessage => {
          expect().assertFail();
        });
        expect().assertFail();
        done();
      } catch (err){
        expect(err.code).assertEqual("801");
        done()
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0006 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0007
     * @tc.name Abnormal test case of offErrorlog
     * @tc.desc 1.Insert data
     */
    it('testRdbStoreOnsqliteErrorOccurred0007',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0007 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        done()
        return
      }
      let STORE_CONFIG1: data_relationalStore.StoreConfig = {
        name: 'rdbStore2.db',
        securityLevel: data_relationalStore.SecurityLevel.S1,
        vector: true,
      };
      let rdbStore1 = await data_relationalStore.getRdbStore(context, STORE_CONFIG1)
      try{
        rdbStore1.off('sqliteErrorOccurred');
        expect().assertFail();
        done();
      } catch (err){
        expect(err.code).assertEqual("801");
        done()
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0007 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
  })
}