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
      try {
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
      } catch (err) {
        console.log(`beforeEach error, failed code:${err.code},message:${err.message}`);
      }
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
        console.info(TAG + " testRdbStoreOnsqliteErrorOccurred0004 average time is: " + averageTime + " μs");
        expect(averageTime < 1000).assertTrue();
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0004 on err log failed, code is ${err.code},message is ${err.message}`);
        rdbStore.off('sqliteErrorOccurred');
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

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0008
     * @tc.name Normal test case of updateWithReturningSync with TRANSACTION and SQLITE_ERROR
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute updateWithReturningSync in TRANSACTION with SQLITE_ERROR
     */
    it('testRdbStoreOnsqliteErrorOccurred0008', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0008 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0008 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "no such column: invalid_column").assertTrue();
          expect(errSQL.includes("UPDATE")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0008 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0008 sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        let u8 = new Uint8Array([1, 2, 3]);
        let transaction = await rdbStore?.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        try {
          const valueBucket: data_relationalStore.ValuesBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
            "invalid_column": 100,
          };
          let predicates = new data_relationalStore.RdbPredicates("test");
          predicates.equalTo('name', 'zhangsan');
          const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
          let resultSet = transaction?.updateWithReturningSync(valueBucket, predicates, config);
          console.log(TAG + "testRdbStoreOnsqliteErrorOccurred0008 updateWithReturningSync resultSet:" + resultSet);
          expect(true).assertFail();
          await transaction?.commit();
        } catch (e) {
          await transaction?.rollback();
          console.log(TAG + e + " code: " + e.code);
          expect(e.code == 14800021).assertTrue();
        }
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0008 transaction failed code:${err.code},message:${err.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0008 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0009
     * @tc.name Normal test case of updateWithReturning with TRANSACTION and SQLITE_ERROR
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute updateWithReturning in TRANSACTION with SQLITE_ERROR
     */
    it('testRdbStoreOnsqliteErrorOccurred0009', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0009 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0009 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "no such column: invalid_column").assertTrue();
          expect(errSQL.includes("UPDATE")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0009 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0009 sqliteErrorOccurred on is failed ${err.code}`);
      }
      let u8 = new Uint8Array([1, 2, 3]);
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
          "invalid_column": 100,
        };
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo('name', 'zhangsan');
        const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
        let resultSet = await transaction?.updateWithReturning(valueBucket, predicates, config);
        console.log(TAG + "testRdbStoreOnsqliteErrorOccurred0009 updateWithReturning resultSet:" + resultSet);
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(TAG + e + " code: " + e.code);
        expect(e.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0009 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0010
     * @tc.name Normal test case of batchInsertWithReturningSync with TRANSACTION and SQLITE_ERROR
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute batchInsertWithReturningSync in TRANSACTION with SQLITE_ERROR
     */
    it('testRdbStoreOnsqliteErrorOccurred0010', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0010 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0010 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "table test has no column named invalid_column").assertTrue();
          expect(errSQL.includes("INSERT")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0010 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0010 sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        let transaction = await rdbStore?.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        try {
          const valueBucket: data_relationalStore.ValuesBucket = {
            "name": "zhangsan",
            "age": 18,
            "invalid_column": 100,
          };
          const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
          let resultSet = transaction?.batchInsertWithReturningSync("test", [valueBucket], config);
          console.log(TAG + "testRdbStoreOnsqliteErrorOccurred0010 batchInsertWithReturningSync resultSet:" + resultSet);
          expect(true).assertFail();
          await transaction?.commit();
        } catch (e) {
          await transaction?.rollback();
          console.log(TAG + e + " code: " + e.code);
          expect(e.code == 14800021).assertTrue();
        }
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0010 transaction failed code:${err.code},message:${err.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0010 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0011
     * @tc.name Normal test case of batchInsertWithReturning with TRANSACTION and SQLITE_ERROR
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute batchInsertWithReturning in TRANSACTION with SQLITE_ERROR
     */
    it('testRdbStoreOnsqliteErrorOccurred0011', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0011 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0011 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "table test has no column named invalid_column").assertTrue();
          expect(errSQL.includes("INSERT")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0011 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0011 sqliteErrorOccurred on is failed ${err.code}`);
      }
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "invalid_column": 100,
        };
        const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
        let resultSet = await transaction?.batchInsertWithReturning("test", [valueBucket], config);
        console.log(TAG + "testRdbStoreOnsqliteErrorOccurred0011 batchInsertWithReturning resultSet:" + resultSet);
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(TAG + e + " code: " + e.code);
        expect(e.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0011 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0012
     * @tc.name Normal test case of deleteWithReturningSync with TRANSACTION and wrong table name
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute deleteWithReturningSync in TRANSACTION with wrong table
     */
    it('testRdbStoreOnsqliteErrorOccurred0012', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0012 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0012 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "no such table: wrong_table").assertTrue();
          expect(errSQL.includes("DELETE")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0012 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0012 sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        let transaction = await rdbStore?.createTransaction({
          transactionType: data_relationalStore.TransactionType.IMMEDIATE
        });
        try {
          let predicates = new data_relationalStore.RdbPredicates("wrong_table");
          predicates.equalTo('id', 1);
          const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
          let resultSet = transaction?.deleteWithReturningSync(predicates, config);
          console.log(TAG + "testRdbStoreOnsqliteErrorOccurred0012 deleteWithReturningSync resultSet:" + resultSet);
          expect(true).assertFail();
          await transaction?.commit();
        } catch (e) {
          await transaction?.rollback();
          console.log(TAG + e + " code: " + e.code);
          expect(e.code == 14800021).assertTrue();
        }
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0012 transaction failed code:${err.code},message:${err.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0012 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0013
     * @tc.name Normal test case of deleteWithReturning with TRANSACTION and wrong table name
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute deleteWithReturning in TRANSACTION with wrong table
     */
    it('testRdbStoreOnsqliteErrorOccurred0013', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0013 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0013 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "no such table: wrong_table").assertTrue();
          expect(errSQL.includes("DELETE")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0013 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0013 sqliteErrorOccurred on is failed ${err.code}`);
      }
      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.IMMEDIATE
      });
      try {
        let predicates = new data_relationalStore.RdbPredicates("wrong_table");
        predicates.equalTo('id', 1);
        const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
        let resultSet = await transaction?.deleteWithReturning(predicates, config);
        console.log(TAG + "testRdbStoreOnsqliteErrorOccurred0013 deleteWithReturning resultSet:" + resultSet);
        expect(true).assertFail();
        await transaction?.commit();
      } catch (e) {
        await transaction?.rollback();
        console.log(TAG + e + " code: " + e.code);
        expect(e.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0013 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0014
     * @tc.name Normal test case of updateWithReturningSync with SQLITE_ERROR
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute updateWithReturningSync with SQLITE_ERROR
     */
    it('testRdbStoreOnsqliteErrorOccurred0014', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0014 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0014 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "no such column: invalid_column").assertTrue();
          expect(errSQL.includes("UPDATE")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0014 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0014 sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "invalid_column": 100,
        };
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo('name', 'zhangsan');
        const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
        rdbStore.updateWithReturningSync(valueBucket, predicates, config);
        expect(true).assertFail();
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0014 updateWithReturningSync failed code:${err.code},message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0014 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0015
     * @tc.name Normal test case of updateWithReturning with SQLITE_ERROR
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute updateWithReturning with SQLITE_ERROR
     */
    it('testRdbStoreOnsqliteErrorOccurred0015', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0015 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0015 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "no such column: invalid_column").assertTrue();
          expect(errSQL.includes("UPDATE")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0015 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0015 sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "invalid_column": 100,
        };
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo('name', 'zhangsan');
        const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
        await rdbStore.updateWithReturning(valueBucket, predicates, config);
        expect(true).assertFail();
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0015 updateWithReturning failed code:${err.code},message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0015 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0016
     * @tc.name Normal test case of batchInsertWithReturningSync with SQLITE_ERROR
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute batchInsertWithReturningSync with SQLITE_ERROR
     */
    it('testRdbStoreOnsqliteErrorOccurred0016', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0016 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0016 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "table test has no column named invalid_column").assertTrue();
          expect(errSQL.includes("INSERT")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0016 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0016 sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "invalid_column": 100,
        };
        const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
        rdbStore.batchInsertWithReturningSync("test", [valueBucket], config);
        expect(true).assertFail();
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0016 batchInsertWithReturningSync failed code:${err.code},message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0016 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0017
     * @tc.name Normal test case of batchInsertWithReturning with SQLITE_ERROR
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute batchInsertWithReturning with SQLITE_ERROR
     */
    it('testRdbStoreOnsqliteErrorOccurred0017', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0017 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0017 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "table test has no column named invalid_column").assertTrue();
          expect(errSQL.includes("INSERT")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0017 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0017 sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "invalid_column": 100,
        };
        const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
        await rdbStore.batchInsertWithReturning("test", [valueBucket], config);
        expect(true).assertFail();
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0017 batchInsertWithReturning failed code:${err.code},message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0017 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0018
     * @tc.name Normal test case of deleteWithReturningSync with wrong table name
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute deleteWithReturningSync with wrong table
     */
    it('testRdbStoreOnsqliteErrorOccurred0018', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0018 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0018 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "no such table: wrong_table").assertTrue();
          expect(errSQL.includes("DELETE")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0018 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0018 sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        let predicates = new data_relationalStore.RdbPredicates("wrong_table");
        predicates.equalTo('id', 1);
        const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
        rdbStore.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0018 deleteWithReturningSync failed code:${err.code},message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0018 end *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_OnsqliteErrorOccurred_0019
     * @tc.name Normal test case of deleteWithReturning with wrong table name
     * @tc.desc 1.OnsqliteErrorOccurred 2.execute deleteWithReturning with wrong table
     */
    it('testRdbStoreOnsqliteErrorOccurred0019', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0019 start *************");
      try {
        let exceptionMessage: data_relationalStore.ExceptionMessage;
        rdbStore.on('sqliteErrorOccurred', exceptionMessage => {
          let sqliteCode = exceptionMessage.code;
          let sqliteMessage = exceptionMessage.message;
          let errSQL = exceptionMessage.sql;
          console.info(`testRdbStoreOnsqliteErrorOccurred0019 error log is ${sqliteCode}, errMessage is ${sqliteMessage}, errSQL is ${errSQL}`);
          expect(sqliteCode == 1).assertTrue();
          expect(sqliteMessage == "no such table: wrong_table").assertTrue();
          expect(errSQL.includes("DELETE")).assertTrue();
          expect(errSQL.includes("returning")).assertTrue();
          done();
        });
        console.log(`testRdbStoreOnsqliteErrorOccurred0019 sqliteErrorOccurred on is success`);
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0019 sqliteErrorOccurred on is failed ${err.code}`);
      }
      try {
        let predicates = new data_relationalStore.RdbPredicates("wrong_table");
        predicates.equalTo('id', 1);
        const config: data_relationalStore.ReturningConfig = { columns: ['name', 'age'] };
        await rdbStore.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (err) {
        console.error(`testRdbStoreOnsqliteErrorOccurred0019 deleteWithReturning failed code:${err.code},message:${err.message}`);
        expect(err.code == 14800021).assertTrue();
      }
      console.log(TAG + "************* testRdbStoreOnsqliteErrorOccurred0019 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
  })
}