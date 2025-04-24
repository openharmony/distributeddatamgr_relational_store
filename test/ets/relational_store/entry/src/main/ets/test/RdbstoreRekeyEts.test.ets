import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import data_relationalStore from '@ohos.data.relationalStore'
import common from "@ohos.app.ability.common"

const TAG = "[RDB_REKEY_TEST]";
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

export default function RdbstoreRekeysEtsTest() {
  describe('rdbstoreRekeyEtsTest', () => {
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
     * @tc.number testRekey
     * @tc.name testRekey0001
     * @tc.desc invalid parameters test
     */
    it('testRekey0001', 0, async () => {
      console.log(TAG + "************* testRekey0001 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testCrypt0001.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        iterationCount: -1,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("14800001").assertEqual(e.code);
        console.log(TAG + "************* testRekey0001 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0002
     * @tc.desc invalid parameters test
     */
    it('testRekey0002', 0, async () => {
      console.log(TAG + "************* testRekey0002 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0002.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        encryptionAlgo: -1,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("14800001").assertEqual(e.code);
        console.log(TAG + "************* testRekey0002 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0003
     * @tc.desc invalid parameters test
     */
    it('testRekey0003', 0, async () => {
      console.log(TAG + "************* testRekey0003 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0003.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        hmacAlgo: -1,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("14800001").assertEqual(e.code);
        console.log(TAG + "************* testRekey0003 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0004
     * @tc.desc invalid parameters test
     */
    it('testRekey0004', 0, async () => {
      console.log(TAG + "************* testRekey0004 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0004.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        kdfAlgo: -1,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("14800001").assertEqual(e.code);
        console.log(TAG + "************* testRekey0004 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0005
     * @tc.desc invalid parameters test
     */
    it('testRekey0005', 0, async () => {
      console.log(TAG + "************* testRekey0005 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0005.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        cryptoPageSize: -1,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("14800001").assertEqual(e.code);
        console.log(TAG + "************* testRekey0005 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0006
     * @tc.desc non-encrypted database rekey test
     */
    it('testRekey0006', 0, async () => {
      console.log(TAG + "************* testRekey0006 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0006.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0006 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0007
     * @tc.desc exception iterationCount test
     */
    it('testRekey0007', 0, async () => {
      console.log(TAG + "************* testRekey0007 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0007.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        iterationCount: 500,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0007 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0008
     * @tc.desc exception encryptionAlgo test
     */
    it('testRekey0008', 0, async () => {
      console.log(TAG + "************* testRekey0008 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0008.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        encryptionAlgo: 1,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0008 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0009
     * @tc.desc exception hmacAlgo test
     */
    it('testRekey0009', 0, async () => {
      console.log(TAG + "************* testRekey0009 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0009.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        hmacAlgo: 2,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0009 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0010
     * @tc.desc exception kdfAlgo test
     */
    it('testRekey0010', 0, async () => {
      console.log(TAG + "************* testRekey0010 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0010.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        kdfAlgo: 2,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0010 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0011
     * @tc.desc exception cryptoPageSize test
     */
    it('testRekey0011', 0, async () => {
      console.log(TAG + "************* testRekey0011 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0011.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        cryptoPageSize: 2048,
      };

      try {
        await rdbStore.rekey(cryptoParam);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0011 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0012
     * @tc.desc custom encrypt rekey test
     */
    it('testRekey0012', 0, async () => {
      console.log(TAG + "************* testRekey0012 start *************");
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
      };

      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0012.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        cryptoParam: cryptoParam,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      await rdbStore.executeSql(CREATE_TABLE_TEST);

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([6, 5, 4, 3, 2, 1]),
      };

      try {
        await rdbStore.rekey(cryptoParam1);
        let  u8 = new Uint8Array([1, 2, 3])
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket);
        const valueBucket1: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 19,
          "salary": 200.5,
          "blobType": u8,
        }
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("NAME", "zhangsan");
        await rdbStore.update(valueBucket1, predicates)
        await rdbStore.delete(predicates);
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(false).assertTrue();
        console.log(TAG + "************* testRekey0012 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0013
     * @tc.desc custom encrypt rekey test
     */
    it('testRekey0013', 0, async () => {
      console.log(TAG + "************* testRekey0013 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0013.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([6, 5, 4, 3, 2, 1]),
      };

      try {
        await rdbStore.rekey(cryptoParam1);
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0013 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0014
     * @tc.desc rekey test
     */
    it('testRekey0014', 0, async () => {
      console.log(TAG + "************* testRekey0014 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0014.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      await rdbStore.executeSql(CREATE_TABLE_TEST);

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
      };

      try {
        await rdbStore.rekey(cryptoParam1);
        let  u8 = new Uint8Array([1, 2, 3])
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket);
        const valueBucket1: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 19,
          "salary": 200.5,
          "blobType": u8,
        }
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("NAME", "zhangsan");
        await rdbStore.update(valueBucket1, predicates)
        await rdbStore.delete(predicates);
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(false).assertTrue();
        console.log(TAG + "************* testRekey0014 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0015
     * @tc.desc rekey test
     */
    it('testRekey0015', 0, async () => {
      console.log(TAG + "************* testRekey0015 start *************");
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([6, 5, 4, 3, 2, 1]),
      };

      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0015.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        cryptoParam: cryptoParam,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
      };

      try {
        await rdbStore.rekey(cryptoParam1);
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0015 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0016
     * @tc.desc transaction rekey test
     */
    it('testRekey0016', 0, async () => {
      console.log(TAG + "************* testRekey0016 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0016.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let SQL_CREATE_TABLE =
        'CREATE TABLE IF NOT EXISTS employee (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER)';
      await rdbStore.executeSql(SQL_CREATE_TABLE);

      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.DEFERRED
      });

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
      };

      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "id": 1,
          "name": "lisi",
          "age": 18,
        }
        await transaction.insert("employee", valueBucket)
        await rdbStore.rekey(cryptoParam1);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(14800015));
        console.log(TAG + "************* testRekey0016 end *************");
      }
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0017
     * @tc.desc transaction rekey test
     */
    it('testRekey0017', 0, async () => {
      console.log(TAG + "************* testRekey0017 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0017.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let SQL_CREATE_TABLE =
        'CREATE TABLE IF NOT EXISTS employee (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER)';
      await rdbStore.executeSql(SQL_CREATE_TABLE);

      let transaction = await rdbStore?.createTransaction({
        transactionType: data_relationalStore.TransactionType.EXCLUSIVE
      });

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
      };

      try {
        const valueBucket: data_relationalStore.ValuesBucket = {
          "id": 1,
          "name": "lisi",
          "age": 18,
        }
        await transaction.insert("employee", valueBucket)
        await rdbStore.rekey(cryptoParam1);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(14800015));
        console.log(TAG + "************* testRekey0017 end *************");
      }
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0018
     * @tc.desc other parameters rekey test
     */
    it('testRekey0018', 0, async () => {
      console.log(TAG + "************* testRekey0018 start *************");
      let storeConfig : data_relationalStore.StoreConfig= {
        name: "testRekey0018.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      try {
        await rdbStore.rekey(undefined);
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(false).assertTrue();
        console.log(TAG + "************* testRekey0018 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0019
     * @tc.desc other parameters rekey test
     */
    it('testRekey0019', 0, async () => {
      console.log(TAG + "************* testRekey0019 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0019.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      try {
        await rdbStore.rekey(null);
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(false).assertTrue();
        console.log(TAG + "************* testRekey0019 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0020
     * @tc.desc other parameters rekey test
     */
    it('testRekey0020', 0, async () => {
      console.log(TAG + "************* testRekey0020 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0020.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      try {
        await rdbStore.rekey();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(false).assertTrue();
        console.log(TAG + "************* testRekey0020 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0021
     * @tc.desc other parameters rekey test
     */
    it('testRekey0021', 0, async () => {
      console.log(TAG + "************* testRekey0021 start *************");
      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0021.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);
      await rdbStore.executeSql(CREATE_TABLE_TEST);

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
      };

      try {
        let u8 = new Uint8Array([1, 2, 3])
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket);
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("name", "zhangsan");
        const resultSet = await rdbStore.query(predicates);
        resultSet.goToNextRow();
        await rdbStore.rekey(cryptoParam1);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(14800015));
        console.log(TAG + "************* testRekey0021 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0022
     * @tc.desc exception iterationCount test
     */
    it('testRekey0022', 0, async () => {
      console.log(TAG + "************* testRekey0022 start *************");
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([6, 5, 4, 3, 2, 1]),
      };

      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0022.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        cryptoParam: cryptoParam
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
        iterationCount: 500,
      };

      try {
        await rdbStore.rekey(cryptoParam1);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0022 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0023
     * @tc.desc exception encryptionAlgo test
     */
    it('testRekey0023', 0, async () => {
      console.log(TAG + "************* testRekey0023 start *************");
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([6, 5, 4, 3, 2, 1]),
      };

      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0023.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        cryptoParam: cryptoParam
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
        encryptionAlgo: 1,
      };

      try {
        await rdbStore.rekey(cryptoParam1);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0023 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0024
     * @tc.desc exception hmacAlgo test
     */
    it('testRekey0024', 0, async () => {
      console.log(TAG + "************* testRekey0024 start *************");
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([6, 5, 4, 3, 2, 1]),
      };

      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0024.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        cryptoParam: cryptoParam
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
        hmacAlgo: 2,
      };

      try {
        await rdbStore.rekey(cryptoParam1);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0024 end *************");
      }
      console.info(TAG + " ************* End*************");
    });

    /**
     * @tc.number testRekey
     * @tc.name testRekey0025
     * @tc.desc exception kdfAlgo test
     */
    it('testRekey0025', 0, async () => {
      console.log(TAG + "************* testRekey0025 start *************");
      let cryptoParam: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([6, 5, 4, 3, 2, 1]),
      };

      let storeConfig: data_relationalStore.StoreConfig = {
        name: "testRekey0025.db",
        securityLevel: data_relationalStore.SecurityLevel.S2,
        encrypt: true,
        cryptoParam: cryptoParam
      }
      let rdbStore = await data_relationalStore.getRdbStore(globalThis.abilityContext, storeConfig);

      let cryptoParam1: data_relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
        kdfAlgo: 2,
      };

      try {
        await rdbStore.rekey(cryptoParam1);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.log(TAG + "************* testRekey0025 end *************");
      }
      console.info(TAG + " ************* End*************");
    });
    console.log(TAG + "*************Unit Test End*************");
  })
}