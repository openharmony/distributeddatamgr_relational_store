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
import data_relationalStore from '@ohos.data.relationalStore'

const TAG = "[RDB_REKEY_VECTOR_TEST]";
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL)";

export default function RdbstoreRekeyVectorEtsTest() {
  describe('rdbstoreRekeyVectorEtsTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll');
    });
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
    });
    afterEach(async () => {
      console.info(TAG + 'afterEach');
    });
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    });

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number testRekeyVector
     * @tc.name testRekeyVector0001
     * @tc.desc Normal rekey on encrypted vector database with explicit key using Uint8Array
     * @tc.type FUNC
     */
    it('testRekeyVector0001', 0, async () => {
      console.log(TAG + "************* testRekeyVector0001 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        return;
      }
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
      };
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekeyVector0001.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        vector: true,
        cryptoParam: cryptoParam,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      await rdbStore.execute(CREATE_TABLE_TEST, 0, undefined);
      await rdbStore.execute("INSERT INTO test VALUES(1, 'zhangsan', 18, 100.5)", 0, undefined);

      try {
        let newKey = new Uint8Array([6, 5, 4, 3, 2, 1]);
        await rdbStore.rekey(newKey);

        let resultSet = await rdbStore.querySql("SELECT * FROM test WHERE name = ?", ["zhangsan"]);
        expect(true).assertEqual(resultSet.goToFirstRow());
        let nameIndex = resultSet.getColumnIndex("name");
        expect("zhangsan").assertEqual(resultSet.getString(nameIndex));
        resultSet.close();
      } catch (e) {
        console.log(TAG + "catch err: code=" + e.code + " message=" + e.message);
        expect(false).assertTrue();
      }

      rdbStore = undefined;
      await data_relationalStore.deleteRdbStore(globalThis.abilityContext, "testRekeyVector0001.db");
      console.log(TAG + "************* testRekeyVector0001 end *************");
    });

    /**
     * @tc.number testRekeyVector
     * @tc.name testRekeyVector0002
     * @tc.desc Rekey on encrypted vector database with empty CryptoParam (auto-generated key)
     * @tc.type FUNC
     */
    it('testRekeyVector0002', 0, async () => {
      console.log(TAG + "************* testRekeyVector0002 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        return;
      }
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekeyVector0002.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        vector: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      await rdbStore.execute(CREATE_TABLE_TEST, 0, undefined);
      await rdbStore.execute("INSERT INTO test VALUES(1, 'zhangsan', 18, 100.5)", 0, undefined);

      try {
        let emptyKey = new Uint8Array();
        await rdbStore.rekey(emptyKey);

        let resultSet = await rdbStore.querySql("SELECT * FROM test WHERE name = ?", ["zhangsan"]);
        expect(true).assertEqual(resultSet.goToFirstRow());
        let nameIndex = resultSet.getColumnIndex("name");
        expect("zhangsan").assertEqual(resultSet.getString(nameIndex));
        resultSet.close();
      } catch (e) {
        console.log(TAG + "catch err: code=" + e.code + " message=" + e.message);
        expect(false).assertTrue();
      }

      rdbStore = undefined;
      await data_relationalStore.deleteRdbStore(globalThis.abilityContext, "testRekeyVector0002.db");
      console.log(TAG + "************* testRekeyVector0002 end *************");
    });

    /**
     * @tc.number testRekeyVector
     * @tc.name testRekeyVector0003
     * @tc.desc Rekey on non-encrypted vector database should fail with E_NOT_SUPPORT
     * @tc.type FUNC
     */
    it('testRekeyVector0003', 0, async () => {
      console.log(TAG + "************* testRekeyVector0003 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        return;
      }
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekeyVector0003.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        vector: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      try {
        let newKey = new Uint8Array([1, 2, 3, 4, 5, 6]);
        await rdbStore.rekey(newKey);
        expect().assertFail();
      } catch (e) {
        console.log(TAG + "catch err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
      }

      rdbStore = undefined;
      await data_relationalStore.deleteRdbStore(globalThis.abilityContext, "testRekeyVector0003.db");
      console.log(TAG + "************* testRekeyVector0003 end *************");
    });

    /**
     * @tc.number testRekeyVector
     * @tc.name testRekeyVector0004
     * @tc.desc Multiple consecutive rekey operations on encrypted vector database
     * @tc.type FUNC
     */
    it('testRekeyVector0004', 0, async () => {
      console.log(TAG + "************* testRekeyVector0004 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        return;
      }
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
      };
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekeyVector0004.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        vector: true,
        cryptoParam: cryptoParam,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      await rdbStore.execute(CREATE_TABLE_TEST, 0, undefined);
      await rdbStore.execute("INSERT INTO test VALUES(1, 'zhangsan', 18, 100.5)", 0, undefined);

      try {
        let key1 = new Uint8Array([2, 3, 4, 5, 6, 7]);
        await rdbStore.rekey(key1);

        let key2 = new Uint8Array([3, 4, 5, 6, 7, 8]);
        await rdbStore.rekey(key2);

        let resultSet = await rdbStore.querySql("SELECT * FROM test WHERE name = ?", ["zhangsan"]);
        expect(true).assertEqual(resultSet.goToFirstRow());
        let nameIndex = resultSet.getColumnIndex("name");
        expect("zhangsan").assertEqual(resultSet.getString(nameIndex));
        resultSet.close();
      } catch (e) {
        console.log(TAG + "catch err: code=" + e.code + " message=" + e.message);
        expect(false).assertTrue();
      }

      rdbStore = undefined;
      await data_relationalStore.deleteRdbStore(globalThis.abilityContext, "testRekeyVector0004.db");
      console.log(TAG + "************* testRekeyVector0004 end *************");
    });

    /**
     * @tc.number testRekeyVector
     * @tc.name testRekeyVector0005
     * @tc.desc Rekey on vector DB with CryptoParam object (not Uint8Array) should fail with E_NOT_SUPPORT.
     *          Covers branch: isVector=false path when napi_is_typedarray returns false for CryptoParam,
     *          and (!isVector && config_.GetDBType() == DB_VECTOR) in rdb_store_impl.cpp
     * @tc.type FUNC
     */
    it('testRekeyVector0005', 0, async () => {
      console.log(TAG + "************* testRekeyVector0005 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        return;
      }
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
      };
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekeyVector0005.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        vector: true,
        cryptoParam: cryptoParam,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      try {
        let newCryptoParam: data_relationalStore.CryptoParam = {
          encryptionKey: new Uint8Array([6, 5, 4, 3, 2, 1]),
        };
        await rdbStore.rekey(newCryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log(TAG + "catch err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
      }

      rdbStore = undefined;
      await data_relationalStore.deleteRdbStore(globalThis.abilityContext, "testRekeyVector0005.db");
      console.log(TAG + "************* testRekeyVector0005 end *************");
    });

    /**
     * @tc.number testRekeyVector
     * @tc.name testRekeyVector0006
     * @tc.desc Rekey on non-encrypted vector DB with empty Uint8Array should fail.
     *          Covers branch: !config_.IsEncrypt() in rdb_store_impl.cpp
     * @tc.type FUNC
     */
    it('testRekeyVector0006', 0, async () => {
      console.log(TAG + "************* testRekeyVector0006 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        return;
      }
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekeyVector0006.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        vector: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      try {
        let emptyKey = new Uint8Array();
        await rdbStore.rekey(emptyKey);
        expect().assertFail();
      } catch (e) {
        console.log(TAG + "catch err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
      }

      rdbStore = undefined;
      await data_relationalStore.deleteRdbStore(globalThis.abilityContext, "testRekeyVector0006.db");
      console.log(TAG + "************* testRekeyVector0006 end *************");
    });

    /**
     * @tc.number testRekeyVector
     * @tc.name testRekeyVector0007
     * @tc.desc Rekey on non-custom-encrypted vector DB with explicit Uint8Array key should fail.
     *          Covers branch: (config_.IsCustomEncryptParam() == cryptoParam.encryptKey_.empty()) in
     *          rdb_store_impl.cpp when store was NOT created with custom key but rekey provides a key
     * @tc.type FUNC
     */
    it('testRekeyVector0007', 0, async () => {
      console.log(TAG + "************* testRekeyVector0007 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        return;
      }
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekeyVector0007.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        vector: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      try {
        let newKey = new Uint8Array([1, 2, 3, 4, 5, 6]);
        await rdbStore.rekey(newKey);
        expect().assertFail();
      } catch (e) {
        console.log(TAG + "catch err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
      }

      rdbStore = undefined;
      await data_relationalStore.deleteRdbStore(globalThis.abilityContext, "testRekeyVector0007.db");
      console.log(TAG + "************* testRekeyVector0007 end *************");
    });

    /**
     * @tc.number testRekeyVector
     * @tc.name testRekeyVector0008
     * @tc.desc Multiple consecutive rekey operations on encrypted vector database
     * @tc.type FUNC
     */
    it('testRekeyVector0008', 0, async () => {
      console.log(TAG + "************* testRekeyVector0008 start *************");
      if (!data_relationalStore.isVectorSupported()) {
        return;
      }
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
      };
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekeyVector0008.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        vector: false,
        cryptoParam: cryptoParam,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      await rdbStore.execute(CREATE_TABLE_TEST, 0, undefined);
      await rdbStore.execute("INSERT INTO test VALUES(1, 'zhangsan', 18, 100.5)", 0, undefined);

      try {
        let key1 = new Uint8Array([2, 3, 4, 5, 6, 7]);
        await rdbStore.rekey(key1);

        let key2 = new Uint8Array([3, 4, 5, 6, 7, 8]);
        await rdbStore.rekey(key2);

        let resultSet = await rdbStore.querySql("SELECT * FROM test WHERE name = ?", ["zhangsan"]);
        expect(true).assertEqual(resultSet.goToFirstRow());
        let nameIndex = resultSet.getColumnIndex("name");
        expect("zhangsan").assertEqual(resultSet.getString(nameIndex));
        resultSet.close();
      } catch (e) {
        console.log(TAG + "catch err: code=" + e.code + " message=" + e.message);
        expect(false).assertTrue();
      }

      rdbStore = undefined;
      await data_relationalStore.deleteRdbStore(globalThis.abilityContext, "testRekeyVector0008.db");
      console.log(TAG + "************* testRekeyVector0008 end *************");
    });
}
