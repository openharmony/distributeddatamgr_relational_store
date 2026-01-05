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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from "@ohos/hypium";
import relationalStore from '@ohos.data.relationalStore';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import { call, callAndReturnCode } from './TestUtils';
const TAG = "[RDB_STORE_UNDEFINED_TEST]";
let rdbStore: relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "data ASSET, " + "data1 ASSETS," + "blobType BLOB)";
const DROP_TABLE_TEST = "DROP TABLE IF EXISTS test;";
const dbName = "undefinedTest.db";
const STORE_CONFIG: relationalStore.StoreConfig = {
  name: dbName,
  securityLevel: relationalStore.SecurityLevel.S1,
}

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

let options: relationalStore.TransactionOptions = {
  transactionType: relationalStore.TransactionType.IMMEDIATE
}

export default function RdbStoreUndefinedTest() {
  describe('rdbStoreUndefinedTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll');
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
    })

    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
      await rdbStore?.executeSql(CREATE_TABLE_TEST);
    })

    afterEach(async () => {
      console.info(TAG + 'afterEach');
      await rdbStore?.executeSql(DROP_TABLE_TEST);
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll');
      await relationalStore.deleteRdbStore(context, STORE_CONFIG);
    })

    /**
     * @tc.number testGetInsertSqlInfo001
     * @tc.name Get Insert SQL Info
     * @tc.desc Tests the conflict is undefined.
     */
    it('testGetInsertSqlInfo001', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfo001 start *************");
      try {
        const bucket: relationalStore.ValuesBucket = { name: "Logitech", age: "18", sex: "man", desc: "asserter" };
        const info: relationalStore.SqlInfo = relationalStore.getInsertSqlInfo("USER", bucket, undefined);
        expect(info.sql).assertEqual("INSERT INTO USER(age,desc,name,sex) VALUES (?,?,?,?)");
        expect(info.args[0]).assertEqual("18");
        expect(info.args[1]).assertEqual("asserter");
        expect(info.args[2]).assertEqual("Logitech");
        expect(info.args[3]).assertEqual("man");
      } catch (e) {
        console.error(TAG + `testGetInsertSqlInfo001 failed. code is ${e.code}, message is ${e.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* testGetInsertSqlInfo001 end *************");
    });

    /**
     * @tc.number testGetInsertSqlInfo002
     * @tc.name Get Insert SQL Info
     * @tc.desc Tests the conflict is null.
     */
    it('testGetInsertSqlInfo002', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfo002 start *************");
      try {
        const bucket: relationalStore.ValuesBucket = { name: "Logitech", age: "18", sex: "man", desc: "asserter" };
        const info: relationalStore.SqlInfo = relationalStore.getInsertSqlInfo("USER", bucket, null);
        expect(info.sql).assertEqual("INSERT INTO USER(age,desc,name,sex) VALUES (?,?,?,?)");
        expect(info.args[0]).assertEqual("18");
        expect(info.args[1]).assertEqual("asserter");
        expect(info.args[2]).assertEqual("Logitech");
        expect(info.args[3]).assertEqual("man");
      } catch (e) {
        console.error(TAG + `testGetInsertSqlInfo002 failed. code is ${e.code}, message is ${e.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* testGetInsertSqlInfo002 end *************");
    });

    /**
     * @tc.number testGetInsertSqlInfo003
     * @tc.name Get Insert SQL Info
     * @tc.desc Tests the conflict is string.
     */
    it('testGetInsertSqlInfo003', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfo003 start *************");
      try {
        const bucket: relationalStore.ValuesBucket = { name: "Logitech", age: "18", sex: "man", desc: "asserter" };
        const info: relationalStore.SqlInfo = relationalStore.getInsertSqlInfo("USER", bucket, "string");
        expect(info.sql).assertEqual("INSERT INTO USER(age,desc,name,sex) VALUES (?,?,?,?)");
        expect(info.args[0]).assertEqual("18");
        expect(info.args[1]).assertEqual("asserter");
        expect(info.args[2]).assertEqual("Logitech");
        expect(info.args[3]).assertEqual("man");
      } catch (e) {
        console.error(TAG + `testGetInsertSqlInfo003 failed. code is ${e.code}, message is ${e.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* testGetInsertSqlInfo003 end *************");
    });

    /**
     * @tc.number testGetUpdateSqlInfo001
     * @tc.name Get Update SQL Info
     * @tc.desc Tests the conflict is undefined.
     */
    it('testGetUpdateSqlInfo001', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfo001 start *************");
      try {
        const bucket: relationalStore.ValuesBucket = { name: "Logitech", age: "18", sex: "man", desc: "asserter" };
        const predicates = new relationalStore.RdbPredicates("users");
        const info: relationalStore.SqlInfo = relationalStore.getUpdateSqlInfo(predicates, bucket, undefined);
        expect(info.sql).assertEqual("UPDATE users SET age=?,desc=?,name=?,sex=?");
        expect(info.args[0]).assertEqual("18");
        expect(info.args[1]).assertEqual("asserter");
        expect(info.args[2]).assertEqual("Logitech");
        expect(info.args[3]).assertEqual("man");
      } catch (e) {
        console.error(TAG + `testGetUpdateSqlInfo001 failed. code is ${e.code}, message is ${e.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* testGetUpdateSqlInfo001 end *************");
    });

    /**
     * @tc.number testGetUpdateSqlInfo002
     * @tc.name Get Update SQL Info
     * @tc.desc Tests the conflict is null.
     */
    it('testGetUpdateSqlInfo002', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfo002 start *************");
      try {
        const bucket: relationalStore.ValuesBucket = { name: "Logitech", age: "18", sex: "man", desc: "asserter" };
        const predicates = new relationalStore.RdbPredicates("users");
        const info: relationalStore.SqlInfo = relationalStore.getUpdateSqlInfo(predicates, bucket, null);
        expect(info.sql).assertEqual("UPDATE users SET age=?,desc=?,name=?,sex=?");
        expect(info.args[0]).assertEqual("18");
        expect(info.args[1]).assertEqual("asserter");
        expect(info.args[2]).assertEqual("Logitech");
        expect(info.args[3]).assertEqual("man");
      } catch (e) {
        console.error(TAG + `testGetUpdateSqlInfo001 failed. code is ${e.code}, message is ${e.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* testGetUpdateSqlInfo002 end *************");
    });

    /**
     * @tc.number testGetUpdateSqlInfo003
     * @tc.name Get Update SQL Info
     * @tc.desc Tests the conflict is string.
     */
    it('testGetUpdateSqlInfo003', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfo003 start *************");
      try {
        const bucket: relationalStore.ValuesBucket = { name: "Logitech", age: "18", sex: "man", desc: "asserter" };
        const predicates = new relationalStore.RdbPredicates("users");
        const info: relationalStore.SqlInfo = relationalStore.getUpdateSqlInfo(predicates, bucket, "string");
        expect(info.sql).assertEqual("UPDATE users SET age=?,desc=?,name=?,sex=?");
        expect(info.args[0]).assertEqual("18");
        expect(info.args[1]).assertEqual("asserter");
        expect(info.args[2]).assertEqual("Logitech");
        expect(info.args[3]).assertEqual("man");
      } catch (e) {
        console.error(TAG + `testGetUpdateSqlInfo001 failed. code is ${e.code}, message is ${e.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* testGetUpdateSqlInfo003 end *************");
    });

    /**
     * @tc.name insert test.
     * @tc.number insert001
     * @tc.desc 1. Tests the conflict is undefined.
     */
    it('insert001', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      await call("insert001", async () => {
        await rdbStore?.insert("test", valueBucket, undefined);
      });
      valueBucket['id'] = 2;
      await call("insertSync001", async () => {
        rdbStore?.insertSync("test", valueBucket, undefined);
      });
    })

    /**
     * @tc.name insert test.
     * @tc.number insert002
     * @tc.desc 1. Tests the conflict is null.
     */
    it('insert002', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      await call("insert002", async () => {
        await rdbStore?.insert("test", valueBucket, null);
      });
      valueBucket['id'] = 2;
      await call("insertSync002", async () => {
        rdbStore?.insertSync("test", valueBucket, null);
      });
    })

    /**
     * @tc.name insert test.
     * @tc.number insert003
     * @tc.desc 1. Tests the conflict is string.
     */
    it('insert003', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      await call("insert003", async () => {
        await rdbStore?.insert("test", valueBucket, "string");
      });
      valueBucket['id'] = 2;
      await call("insertSync003", async () => {
        rdbStore?.insertSync("test", valueBucket, "string");
      });
    })

    /**
     * @tc.name trans insert test.
     * @tc.number transInsert001
     * @tc.desc 1. Tests the conflict is undefined.
     */
    it('transInsert001', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      let trans = await rdbStore?.createTransaction(options);
      await call("transInsert001", async () => {
        await trans?.insert("test", valueBucket, undefined);
      });
      valueBucket['id'] = 2;
      await call("transInsertSync001", async () => {
        trans?.insertSync("test", valueBucket, undefined);
      });
      await trans?.commit();
    })

    /**
     * @tc.name trans insert test.
     * @tc.number transInsert002
     * @tc.desc 1. Tests the conflict is null.
     */
    it('transInsert002', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      let trans = await rdbStore?.createTransaction(options);
      await call("transInsert002", async () => {
        await trans?.insert("test", valueBucket, null);
      });
      valueBucket['id'] = 2;
      await call("transInsertSync002", async () => {
        await trans?.insertSync("test", valueBucket, null);
      });
      await trans?.commit();
    })

    /**
     * @tc.name trans insert test.
     * @tc.number transInsert003
     * @tc.desc 1. Tests the conflict is string.
     */
    it('transInsert003', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      let trans = await rdbStore?.createTransaction(options);
      let code = await callAndReturnCode("transInsert003", async () => {
        await trans?.insert("test", valueBucket, "string");
      });
      expect("401").assertEqual(code);
      valueBucket['id'] = 2;
      code = await callAndReturnCode("transInsertSync002", async () => {
        await trans?.insertSync("test", valueBucket, "string");
      });
      expect("401").assertEqual(code);
      await trans?.commit();
    })

    /**
     * @tc.name update test.
     * @tc.number update001
     * @tc.desc 1. Tests the conflict is undefined.
     */
    it('update001', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      let predicates = new relationalStore.RdbPredicates("test");
      await call("update001", async () => {
        await rdbStore?.update(valueBucket, predicates, undefined);
      });
      await call("updateSync001", async () => {
        await rdbStore?.updateSync(valueBucket, predicates, undefined);
      });
    })

    /**
     * @tc.name update test.
     * @tc.number update002
     * @tc.desc 1. Tests the conflict is null.
     */
    it('update002', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      let predicates = new relationalStore.RdbPredicates("test");
      await call("update002", async () => {
        await rdbStore?.update(valueBucket, predicates, null);
      });
      await call("updateSync002", async () => {
        await rdbStore?.updateSync(valueBucket, predicates, null);
      });
    })

    /**
     * @tc.name update test.
     * @tc.number update003
     * @tc.desc 1. Tests the conflict is string.
     */
    it('update003', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      let predicates = new relationalStore.RdbPredicates("test");
      await call("update003", async () => {
        await rdbStore?.update(valueBucket, predicates, "string");
      });
      await call("updateSync003", async () => {
        await rdbStore?.updateSync(valueBucket, predicates, "string");
      });
    })

    /**
     * @tc.name trans update test.
     * @tc.number transUpdate001
     * @tc.desc 1. Tests the conflict is undefined.
     */
    it('transUpdate001', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      let trans = await rdbStore?.createTransaction(options);
      let predicates = new relationalStore.RdbPredicates("test");
      await call("transUpdate001", async () => {
        await trans?.update(valueBucket, predicates, undefined);
      });
      await call("transUpdateSync001", async () => {
        await trans?.updateSync(valueBucket, predicates, undefined);
      });
      await trans?.commit();
    })

    /**
     * @tc.name trans update test.
     * @tc.number transUpdate002
     * @tc.desc 1. Tests the conflict is null.
     */
    it('transUpdate002', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      let trans = await rdbStore?.createTransaction(options);
      let predicates = new relationalStore.RdbPredicates("test");
      await call("transUpdate002", async () => {
        await trans?.update(valueBucket, predicates, null);
      });
      await call("transUpdateSync002", async () => {
        await trans?.updateSync(valueBucket, predicates, null);
      });
      await trans?.commit();
    })

    /**
     * @tc.name trans update test.
     * @tc.number transUpdate003
     * @tc.desc 1. Tests the conflict is string.
     */
    it('transUpdate003', 0, async () => {
      const valueBucket: relationalStore.ValuesBucket = { id: 1, name: 'zhangsan' };
      let trans = await rdbStore?.createTransaction(options);
      let predicates = new relationalStore.RdbPredicates("test");
      let code = await callAndReturnCode("transUpdate003", async () => {
        await trans?.update(valueBucket, predicates, "string");
      });
      expect("401").assertEqual(code);
      code = await callAndReturnCode("transUpdateSync003", async () => {
        await trans?.updateSync(valueBucket, predicates, "string");
      });
      expect("401").assertEqual(code);
      await trans?.commit();
    })
  })
}