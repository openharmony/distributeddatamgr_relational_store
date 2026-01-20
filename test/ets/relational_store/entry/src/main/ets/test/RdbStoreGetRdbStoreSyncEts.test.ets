import { hilog } from '@kit.PerformanceAnalysisKit';
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import relationalStore from '@ohos.data.relationalStore'
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const TAG = "[RDB_STORE_GET_RDB_STORE_SYNC_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG : relationalStore.StoreConfig = {
  name: "rdbstore.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG1 : relationalStore.StoreConfig = {
  name: "rdbstore1.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

export default function RdbStoregetRdbStoreSyncSyncEtsTest() {
  describe('rdbStoregetRdbStoreSyncSyncEts', () => {
    // Defines a test suite. Two parameters are supported: test suite name and test suite function.
    beforeAll(async () => {
      console.info(TAG + 'beforeAll');
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
    })
    afterEach(async () => {
      console.info(TAG + 'afterEach');
      await relationalStore.deleteRdbStore(context, "RdbTest.db");
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number testRdbStore0001
     * @tc.desc rdb store getRdbStoreSync test
     */
    it('testRdbStore0001', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0001 start *************");
      try {
        let store: relationalStore.RdbStore = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
        console.log(TAG + "getRdbStoreSync done: " + store);
        done();
      } catch (e) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0001 end   *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync and create table
     * @tc.number testRdbStore0002
     * @tc.desc rdb store getRdbStoreSync and create table
     */
    it('testRdbStore0002', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0002 start *************");
      let store: relationalStore.RdbStore = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      try {
        console.log(TAG + "getRdbStoreSync done: " + store);
        await store.executeSql(CREATE_TABLE_TEST);
        done();
      } catch (e) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0002 end   *************");
    })

    /**
     * @tc.name rdb storegetRdbStoreSync with wrong path
     * @tc.number testRdbStore0003
     * @tc.desc rdb store getRdbStoreSync with wrong path
     */
    it('testRdbStore0003', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0003 start *************");
      let storeConfig: relationalStore.StoreConfig = {
        name: "/wrong/rdbstore.db",
        securityLevel: relationalStore.SecurityLevel.S1,
      }
      try {
        relationalStore.getRdbStoreSync(context, storeConfig)
        console.log("testRdbStore0003 getRdbStoreSync succeed")
        expect().assertFail();
      } catch (e) {
        console.log("testRdbStore0003 catch err: failed, err: code=" + e.code + " message=" + e.message)
        expect("401").assertEqual(e.code)
      }
      console.info(TAG + "************* testRdbStore0003 end   *************");
      done();
    })

    /**
     * @tc.name rdb store deleteRdbStore
     * @tc.number testRdbStore0004
     * @tc.desc rdb store deleteRdbStore
     */
    it('testRdbStore0004', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0004 start *************");
      try {
        let store: relationalStore.RdbStore = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
        await store.executeSql(CREATE_TABLE_TEST);
      } catch (e) {
        console.log(TAG + "create table error");
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0004 end   *************");
      done();
    })

    /**
     * @tc.name rdb store setVersion & getVersion
     * @tc.number testRdbStore0005
     * @tc.desc rdb store setVersion & getVersion
     */
    it('testRdbStore0005', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0005 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);

      try {
        store.version = 5
        expect(5).assertEqual(store.version)
        store.version = 2147483647
        expect(2147483647).assertEqual(store.version)
      } catch (e) {
        expect().assertFail();
      }
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      console.log(TAG + "************* testRdbStore0005 end   *************");
      done();
    })

    /**
     * @tc.name rdb store setVersion & getVersion
     * @tc.number testRdbStore0006
     * @tc.desc rdb store setVersion
     */
    it('testRdbStore0006', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0006 start *************");
      let store: relationalStore.RdbStore = relationalStore.getRdbStoreSync(context, STORE_CONFIG);

      try {
        store.version = -2147483648;
      } catch (err) {
        expect("401").assertEqual(err.code);
      }

      try {
        store.version = 2147483647000;
      } catch (err) {
        expect("401").assertEqual(err.code);
      }

      try {
        store.version = 0;
      } catch (err) {
        expect("401").assertEqual(err.code);
      }
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      console.log(TAG + "************* testRdbStore0006 end   *************");
      done();
    })

    /**
     * @tc.name rdb store getRdbStoreSync with securityLevel
     * @tc.number testRdbStore0007
     * @tc.desc rdb store getRdbStoreSync with securityLevel
     * @tc.require: I5PIL6
     */
    it('testRdbStore0007', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0007 start *************");
      let config: relationalStore.StoreConfig = {
        name: "secure.db",
        securityLevel: relationalStore.SecurityLevel.S3
      }
      try {
        let store: relationalStore.RdbStore = relationalStore.getRdbStoreSync(context, config);
        await store.executeSql(CREATE_TABLE_TEST);
        await relationalStore.deleteRdbStore(context, "secure.db");
      } catch (e) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0007 end   *************");
      done();
    })

    /**
     * @tc.name rdb store getRdbStoreSync with invalid securityLevel
     * @tc.number testRdbStore0008
     * @tc.desc rdb store getRdbStoreSync with invalid securityLevel
     * @tc.require: I5PIL6
     */
    it('testRdbStore0008', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0008 start *************");
      let config: relationalStore.StoreConfig = {
        name: "secure.db",
        securityLevel: 8
      }
      try {
        relationalStore.getRdbStoreSync(context, config);
      } catch (err) {
        expect("401").assertEqual(err.code)
      }
      console.log(TAG + "************* testRdbStore0008 end   *************");
      done();
    })

    /**
     * @tc.name rdb store getRdbStoreSync with different securityLevel
     * @tc.number testRdbStore0009
     * @tc.desc rdb store getRdbStoreSync with different securityLevel
     * @tc.require: I5PIL6
     */
    it('testRdbStore0009', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0009 start *************");
      let config1: relationalStore.StoreConfig = {
        name: "rdbstore9.db",
        securityLevel: relationalStore.SecurityLevel.S1,
      }

      let config2: relationalStore.StoreConfig = {
        name: "rdbstore9.db",
        securityLevel: relationalStore.SecurityLevel.S2,
      }

      relationalStore.getRdbStoreSync(context, config1);
      try {
        relationalStore.getRdbStoreSync(context, config2);
        done();
      } catch (err) {
        expect(14800017).assertEqual(Number(err.code))
        console.log(TAG + "************* testRdbStore0009 end   *************");
      }
      done();
    })

    /**
     * @tc.name rdb store getRdbStoreSync with different securityLevel
     * @tc.number testRdbStore0010
     * @tc.desc rdb store getRdbStoreSync with different securityLevel
     * @tc.require: I5PIL6
     */
    it('testRdbStore0010', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0010 start *************");
      let config1: relationalStore.StoreConfig = {
        name: "rdbstore10.db",
        securityLevel: relationalStore.SecurityLevel.S1,
      }

      let config2: relationalStore.StoreConfig = {
        name: "rdbstore10.db",
        securityLevel: relationalStore.SecurityLevel.S2,
      }

      try {
        relationalStore.getRdbStoreSync(context, config1);
        relationalStore.getRdbStoreSync(context, config2);
        expect(true).assertFail();
      } catch (e) {
        expect(14800017).assertEqual(Number(e.code))
        console.log("testRdbStore0003 catch err: failed, err: code=" + e.code + " message=" + e.message)
      }
      console.log(TAG + "************* testRdbStore0010 end   *************");
      done();
    })

    /**
     * @tc.name rdb store getRdbStoreSync with invalid securityLevel
     * @tc.number testRdbStore0011
     * @tc.desc rdb store getRdbStoreSync with invalid securityLevel
     */
    it('testRdbStore0011', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0011 start *************");
      let config: relationalStore.StoreConfig = {
        name: "search.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        // isSearchable: true
      }
      let store = relationalStore.getRdbStoreSync(context, config);
      try {
        // store.isSearchable = true
        // expect(true).assertEqual(store.isSearchable)
      } catch (err) {
        expect("401").assertEqual(err.code)
      }
      console.log(TAG + "************* testRdbStore0011 end   *************");
      done();
    })

    /**
     * @tc.name rdb store wal file overlimit test
     * @tc.number testRdbStore0012
     * @tc.desc Checkpoint failure delayed retry
     */
    it('testRdbStore0012', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0012 start *************");
      try {
        const rowCount = 18;
        const rdbStore = relationalStore.getRdbStoreSync(context, {
          name: "walTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          encrypt: true,
        });
        const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test ("
          + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
          + "blobType BLOB)";
        rdbStore.executeSync(CREATE_TABLE_TEST);
        const valueTest = Array(rowCount).fill(0).map(() => {
          const valueBucket: relationalStore.ValuesBucket = {
            "blobType": new Uint8Array(Array(1024).fill(1)),
          };
          return valueBucket;
        });
        rdbStore.batchInsertSync('test', valueTest);
        const predicates = new relationalStore.RdbPredicates('test');
        const resultSet = rdbStore.querySync(predicates);
        expect(resultSet.rowCount).assertEqual(rowCount);
        resultSet.goToFirstRow();
        const valueBuckets = Array(rowCount).fill(0).map(() => {
          const valueBucket: relationalStore.ValuesBucket = {
            "blobType": new Uint8Array(Array(1024 * 1024).fill(1)),
          };
          return valueBucket;
        });
        rdbStore.batchInsertSync('test', valueBuckets);
        const startTime = new Date().getTime();
        const valueBucket: relationalStore.ValuesBucket = {
          "blobType": new Uint8Array(Array(1024 * 1024).fill(1)),
        };
        rdbStore.insertSync('test', valueBucket);
        const middleTime = new Date().getTime();
        console.log(TAG + "testRdbStore0012, startTime:" + startTime + " middleTime:" + middleTime + " costTime" +
          (middleTime - startTime));
        expect((middleTime - startTime) > 500).assertTrue();
        rdbStore.insertSync('test', valueBucket);
        const endTime = new Date().getTime();
        console.log(TAG + "testRdbStore0012, endTime:" + endTime + " middleTime:" + middleTime + " costTime" +
          (endTime - middleTime));
        expect((endTime - middleTime) < 500).assertTrue();
        resultSet.close();
        console.log(TAG + "************* testRdbStore0012 end *************");
        done();
      } catch (e) {
        console.log(TAG + "testRdbStore0012 failed " + JSON.stringify(e));
        done();
        expect().assertFail();
      }
    })

    /**
     * @tc.name rdb store update after deleteRdbStore
     * @tc.number testRdbStore0013
     * @tc.desc rdb store update after deleteRdbStore
     */
    it('testRdbStore0013', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0013 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);

      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)

      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        const valueBucket1: relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 19,
          "salary": 200.5,
          "blobType": u8,
        }
        let predicates = new relationalStore.RdbPredicates("test");
        predicates.equalTo("NAME", "zhangsan");
        await store.update(valueBucket1, predicates)
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0013 end *************");
      done();
    })

    /**
     * @tc.name rdb store insert after deleteRdbStore
     * @tc.number testRdbStore0014
     * @tc.desc rdb store insert after deleteRdbStore
     */
    it('testRdbStore0014', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0014 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        let u8 = new Uint8Array([1, 2, 3])
        const valueBucket: relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        }
        await store.insert("test", valueBucket)
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0014 end *************");
      done();
    })

    /**
     * @tc.name rdb store batchInsert after deleteRdbStore
     * @tc.number testRdbStore0015
     * @tc.desc rdb store batchInsert after deleteRdbStore
     */
    it('testRdbStore0015', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0015 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);

      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      let valueBucketArray: Array<relationalStore.ValuesBucket> = new Array();
      for (let i = 0; i < 10; i++) {
        valueBucketArray.push(valueBucket);
      }

      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.batchInsert("test", valueBucketArray)
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0015 end *************");
      done();
    })

    /**
     * @tc.name rdb store delete after deleteRdbStore
     * @tc.number testRdbStore0016
     * @tc.desc rdb store delete after deleteRdbStore
     */
    it('testRdbStore0016', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0016 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);
      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)

      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        let predicates = await new relationalStore.RdbPredicates("test")
        await store.delete(predicates)
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0016 end *************");
      done();
    })

    /**
     * @tc.name rdb store query after deleteRdbStore
     * @tc.number testRdbStore0017
     * @tc.desc rdb store query after deleteRdbStore
     */
    it('testRdbStore0017', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0017 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);
      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        let predicates = await new relationalStore.RdbPredicates("test")
        await store.query(predicates)
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0017 end *************");
      done();
    })

    /**
     * @tc.name rdb store querySql after deleteRdbStore
     * @tc.number testRdbStore0018
     * @tc.desc rdb store querySql after deleteRdbStore
     */
    it('testRdbStore0018', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0018 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);
      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.querySql("SELECT * FROM test")
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0018 end *************");
      done();
    })

    /**
     * @tc.name rdb store backup after deleteRdbStore
     * @tc.number testRdbStore0019
     * @tc.desc rdb store backup after deleteRdbStore
     */
    it('testRdbStore0019', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0019 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.backup("backup.db");
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0019 end *************");
      done();
    })

    /**
     * @tc.name rdb store restore after deleteRdbStore
     * @tc.number testRdbStore0020
     * @tc.desc rdb store restore after deleteRdbStore
     */
    it('testRdbStore0020', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0020 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.backup("backup.db");
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.restore("backup.db");
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0020 end *************");
      done();
    })

    /**
     * @tc.name rdb store cleanDirtyData after deleteRdbStore
     * @tc.number testRdbStore0021
     * @tc.desc rdb store cleanDirtyData after deleteRdbStore
     */
    it('testRdbStore0021', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0021 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.cleanDirtyData('test')
        expect().assertFail();
      } catch (err) {
        expect(14800000).assertEqual(err.code)
      }
      console.log(TAG + "************* testRdbStore0021 end *************");
      done();
    })

    /**
     * @tc.name rdb store executeSql after deleteRdbStore
     * @tc.number testRdbStore0022
     * @tc.desc rdb store executeSql after deleteRdbStore
     */
    it('testRdbStore0022', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0022 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.executeSql(CREATE_TABLE_TEST)
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0022 end *************");
      done();
    })

    /**
     * @tc.name rdb store execute after deleteRdbStore
     * @tc.number testRdbStore0023
     * @tc.desc rdb store execute after deleteRdbStore
     */
    it('testRdbStore0023', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0023 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.execute(CREATE_TABLE_TEST)
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0023 end *************");
      done();
    })

    /**
     * @tc.name rdb store beginTransaction after deleteRdbStore
     * @tc.number testRdbStore0024
     * @tc.desc rdb store beginTransaction after deleteRdbStore
     */
    it('testRdbStore0024', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0024 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        store.beginTransaction();
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0024 end *************");
      done();
    })

    /**
     * @tc.name rdb store setDistributedTables after deleteRdbStore
     * @tc.number testRdbStore0025
     * @tc.desc rdb store setDistributedTables after deleteRdbStore
     */
    it('testRdbStore0025', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0025 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.setDistributedTables(['test'])
        expect().assertFail();
      } catch (err) {
        expect(14800000).assertEqual(err.code);
      }
      console.log(TAG + "************* testRdbStore0025 end *************");
      done();
    })

    /**
     * @tc.name rdb store attach after deleteRdbStore
     * @tc.number testRdbStore0026
     * @tc.desc rdb store attach after deleteRdbStore
     */
    it('testRdbStore0026', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0026 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.attach(context, STORE_CONFIG1, "attachDB");
        expect().assertFail();
      } catch (err) {
        expect(14800010).assertEqual(err.code);
      }
      console.log(TAG + "************* testRdbStore0026 end *************");
      done();
    })

    /**
     * @tc.name rdb store detach after deleteRdbStore
     * @tc.number testRdbStore0027
     * @tc.desc rdb store detach after deleteRdbStore
     */
    it('testRdbStore0027', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0027 start *************");

      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      relationalStore.getRdbStoreSync(context, STORE_CONFIG1);
      await store.executeSql(CREATE_TABLE_TEST);

      await store.attach(context, STORE_CONFIG1, "attachDB");
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.detach("attachDB")
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0027 end *************");
      done();
    })

    /**
     * @tc.name rdb store createTransaction after deleteRdbStore
     * @tc.number testRdbStore0028
     * @tc.desc rdb store createTransaction after deleteRdbStore
     */
    it('testRdbStore0028', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0028 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");

      try {
        await store?.createTransaction({
          transactionType: relationalStore.TransactionType.IMMEDIATE
        });
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0028 end *************");
      done();
    })

    /**
     * @tc.name rdb store beginTrans after deleteRdbStore
     * @tc.number testRdbStore0029
     * @tc.desc rdb store beginTrans after deleteRdbStore
     */
    it('testRdbStore0029', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0029 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.beginTrans();
        expect().assertFail();
      } catch (err) {
        expect(801).assertEqual(err.code);
      }
      console.log(TAG + "************* testRdbStore0029 end *************");
      done();
    })

    /**
     * @tc.name rdb store commit after deleteRdbStore
     * @tc.number testRdbStore0030
     * @tc.desc rdb store commit after deleteRdbStore
     */
    it('testRdbStore0030', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0030 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);

      store.beginTransaction();
      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "lisi",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        store.commit();
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0030 end *************");
      done();
    })

    /**
     * @tc.name rdb store getModifyTime after deleteRdbStore
     * @tc.number testRdbStore0031
     * @tc.desc rdb store getModifyTime after deleteRdbStore
     */
    it('testRdbStore0031', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0031 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);
      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        await store.getModifyTime('test', 'name', [1]);
        expect().assertFail();
      } catch (err) {
        expect(14800000).assertEqual(err.code);
      }
      console.log(TAG + "************* testRdbStore0031 end *************");
      done();
    })

    /**
     * @tc.name rdb store rollBack after deleteRdbStore
     * @tc.number testRdbStore0032
     * @tc.desc rdb store rollBack after deleteRdbStore
     */
    it('testRdbStore0032', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0032 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);

      store.beginTransaction();
      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "lisi",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)
      await relationalStore.deleteRdbStore(context, "rdbstore.db");
      try {
        store.rollBack();
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0032 end *************");
      done();
    })

    /**
     * @tc.name rdb store queryLockedRow after deleteRdbStore
     * @tc.number testRdbStore0033
     * @tc.desc rdb store queryLockedRow after deleteRdbStore
     */
    it('testRdbStore0033', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0033 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);

      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "lisi",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)
      await relationalStore.deleteRdbStore(context, "rdbstore.db");

      try {
        let predicates = new relationalStore.RdbPredicates("test");
        predicates.equalTo('age', 18);
        await store.queryLockedRow(predicates);
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0033 end *************");
      done();
    })

    /**
     * @tc.name rdb store lockRow after deleteRdbStore
     * @tc.number testRdbStore0034
     * @tc.desc rdb store lockRow after deleteRdbStore
     */
    it('testRdbStore0034', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0034 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);

      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "lisi",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)
      await relationalStore.deleteRdbStore(context, "rdbstore.db");

      try {
        let predicates = new relationalStore.RdbPredicates("test");
        predicates.equalTo('age', 18);
        await store.lockRow(predicates);
        expect().assertFail();
      } catch (err) {
        expect(14800018).assertEqual(err.code);
      }
      console.log(TAG + "************* testRdbStore0034 end *************");
      done();
    })

    /**
     * @tc.name rdb store unlockRow after deleteRdbStore
     * @tc.number testRdbStore0035
     * @tc.desc rdb store unlockRow after deleteRdbStore
     */
    it('testRdbStore0035', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0035 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);

      let u8 = new Uint8Array([1, 2, 3])
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "lisi",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
      }
      await store.insert("test", valueBucket)
      await relationalStore.deleteRdbStore(context, "rdbstore.db");

      try {
        let predicates = new relationalStore.RdbPredicates("test");
        predicates.equalTo('age', 18);
        await store.unlockRow(predicates);
        expect().assertFail();
      } catch (err) {
        expect(14800018).assertEqual(err.code);
      }
      console.log(TAG + "************* testRdbStore0035 end *************");
      done();
    })

    /**
     * @tc.name rdb store transaction insert after deleteRdbStore
     * @tc.number testRdbStore0036
     * @tc.desc rdb store transaction insert after deleteRdbStore
     */
    it('testRdbStore0036', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0036 start *************");
      let store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
      await store.executeSql(CREATE_TABLE_TEST);
      let transaction = await store?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      await relationalStore.deleteRdbStore(context, "rdbstore.db");

      try {
        let u8 = new Uint8Array([1, 2, 3])
        const valueBucket: relationalStore.ValuesBucket = {
          "name": "lisi",
          "age": 18,
          "salary": 100.5,
          "blobType": u8,
        }
        await transaction.insert("test", valueBucket)
      } catch (err) {
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStore0036 end *************");
      done();
    })

    /**
     * @tc.name rootDir support test
     * @tc.number testRdbStore0037
     * @tc.desc invalid rootDir path async
     */
    it('testRdbStore0037', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0037 start *************");
      try {
        relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "invalidPath",
          customDir: "entry/rdb"
        });
        expect().assertFail();
      } catch (e) {
        expect("14800010").assertEqual(e.code);
      }
      console.log(TAG + "************* testRdbStore0037 end *************");
      done();
    })

    /**
     * @tc.name rootDir support test
     * @tc.number testRdbStore0038
     * @tc.desc invalid rootDir path callback
     */
    it('testRdbStore0038', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0038 start *************");
      try {
        relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "invalidPath",
          customDir: "entry/rdb"
        });
        expect().assertFail();
      } catch (e) {
        expect("14800010").assertEqual(e.code);
        console.log(TAG + "************* testRdbStore0038 end *************");
        done();
      }
      ;
    })

    /**
     * @tc.name rootDir support test
     * @tc.number testRdbStore0039
     * @tc.desc db not exist test async
     */
    it('testRdbStore0039', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0039 start *************");
      try {
        relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database",
          customDir: "entry/rdb"
        });
        expect().assertFail();
      } catch (e) {
        expect("14800010").assertEqual(e.code);
      }
      console.log(TAG + "************* testRdbStore0039 end *************");
      done();
    })

    /**
     * @tc.name rootDir support test
     * @tc.number testRdbStore0040
     * @tc.desc db not exist test callback
     */
    it('testRdbStore0040', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0040 start *************");
      try {
        relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database",
          customDir: "entry/rdb"
        });
        expect().assertFail();
      } catch (e) {
        expect("14800010").assertEqual(e.code);
        console.log(TAG + "************* testRdbStore0040 end *************");
        done();
      }
    })

    /**
     * @tc.name rootDir support test
     * @tc.number testRdbStore0041
     * @tc.desc query test async
     */
    it('testRdbStore0041', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0041 start *************");
      try {
        const rowCount = 18;
        const rdbStore = relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
        })

        rdbStore.executeSync(CREATE_TABLE_TEST);

        const valueBuckets = Array(rowCount).fill(0).map(() => {
          const valueBucket: relationalStore.ValuesBucket = {
            "name": "lisi",
            "age": 15,
            "salary": 153.3,
            "blobType": new Uint8Array([1, 2, 3]),
          }
          return valueBucket;
        })
        rdbStore.batchInsertSync('test', valueBuckets);
        rdbStore.close();

        const rdbStore1 = relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database",
          customDir: "entry/rdb"
        })

        const predicates = new relationalStore.RdbPredicates('test');
        const resultSet = rdbStore1.querySync(predicates);
        expect(resultSet.rowCount).assertEqual(rowCount);
      } catch (e) {
        expect("14800010").assertEqual(e.code);
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
      }
      await relationalStore.deleteRdbStore(context, "rootDirTest");
      console.log(TAG + "************* testRdbStore0041 end *************");
      done();
    })

    /**
     * @tc.name rootDir support test
     * @tc.number testRdbStore0042
     * @tc.desc query test callback
     */
    it('testRdbStore0042', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0042 start *************");
      const rowCount = 18;
      const rdbStore = relationalStore.getRdbStoreSync(context, {
        name: "rootDirTest",
        securityLevel: relationalStore.SecurityLevel.S3,
      })

      rdbStore.executeSync(CREATE_TABLE_TEST);

      const valueBuckets = Array(rowCount).fill(0).map(() => {

        const valueBucket: relationalStore.ValuesBucket = {
          "name": "lisi",
          "age": 15,
          "salary": 153.3,
          "blobType": new Uint8Array([1, 2, 3]),
        }
        return valueBucket;
      })
      rdbStore.batchInsertSync('test', valueBuckets);
      rdbStore.close();

      try {
        relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database",
          customDir: "entry/rdb"
        });
      } catch (e) {
        if (e) {
          console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
          expect("14800010").assertEqual(e.code);
        } else {
          const predicates = new relationalStore.RdbPredicates('test');
          const resultSet = rdbStore.querySync(predicates);
          expect(resultSet.rowCount).assertEqual(rowCount);
          relationalStore.deleteRdbStore(context, "rootDirTest");
          console.log(TAG + "************* testRdbStore0042 end *************");
          done();
        }
        done();
      }
    })

    /**
     * @tc.name rootDir support test
     * @tc.number testRdbStore0043
     * @tc.desc write test async
     */
    it('testRdbStore0043', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0043 start *************");
      try {
        const rdbStore = relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
        })

        rdbStore.executeSync(CREATE_TABLE_TEST);
        rdbStore.close();

        const rdbStore1 = relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database",
          customDir: "entry/rdb"
        })

        rdbStore1.insertSync('test', {
          "name": "lisi",
          "age": 15,
          "salary": 153.3,
          "blobType": new Uint8Array([1, 2, 3]),
        });
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
        expect("14800010").assertEqual(e.code);
      }
      await relationalStore.deleteRdbStore(context, "rootDirTest");
      console.log(TAG + "************* testRdbStore0043 end *************");
      done();
    })

    /**
     * @tc.name rootDir support test
     * @tc.number testRdbStore0044
     * @tc.desc write test callback
     */
    it('testRdbStore0044', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0044 start *************");
      const rdbStore = relationalStore.getRdbStoreSync(context, {
        name: "rootDirTest",
        securityLevel: relationalStore.SecurityLevel.S3,
      })

      rdbStore.executeSync(CREATE_TABLE_TEST);
      rdbStore.close();

      try {
        relationalStore.getRdbStoreSync(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database",
          customDir: "entry/rdb"
        });
        rdbStore.insertSync('test', {
          "name": "lisi",
          "age": 15,
          "salary": 153.3,
          "blobType": new Uint8Array([1, 2, 3]),
        });
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
        expect("14800010").assertEqual(e.code);
      }
      relationalStore.deleteRdbStore(context, "rootDirTest");
      console.log(TAG + "************* testRdbStore0044 end *************");
      done();
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number testRdbStore0045
     * @tc.desc deleteRdb test async
     */
    it('testRdbStore0045', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0045 start *************");
      try {
        const rdbStore = relationalStore.getRdbStoreSync(context, {
          name: "RdbTest.db",
          securityLevel: relationalStore.SecurityLevel.S3,
        })

        rdbStore.executeSync(CREATE_TABLE_TEST);
        rdbStore.close();

        await relationalStore.deleteRdbStore(context, {
          name: "RdbTest.db",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database",
          customDir: "entry/rdb"
        })
      } catch (e) {
        expect(14800010).assertEqual(Number(e.code));
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
      }
      console.log(TAG + "************* testRdbStore0045 end *************");
      done();
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number testRdbStore0046
     * @tc.desc deleteRdb test callback
     */
    it('testRdbStore0046', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0046 start *************");
      const rdbStore = relationalStore.getRdbStoreSync(context, {
        name: "rootDirTest",
        securityLevel: relationalStore.SecurityLevel.S3,
      })

      rdbStore.executeSync(CREATE_TABLE_TEST);
      rdbStore.close();

      try {
        relationalStore.deleteRdbStore(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database",
          customDir: "entry/rdb"
        })
        expect().assertFail();
      } catch (e) {
        if (e) {
          expect(14800010).assertEqual(Number(e.code));
          console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)

        } else {
          console.log(TAG + "************* testRdbStore0046 end *************");
          done();
        }
      }
      done();
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number testRdbStore0047
     * @tc.desc invalid rootDir test async
     */
    it('testRdbStore0047', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0047 start *************");
      try {
        await relationalStore.deleteRdbStore(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "invalidPath",
          customDir: "entry/rdb"
        })
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("14800010").assertEqual(e.code);
      }
      console.log(TAG + "************* testRdbStore0047 end *************");
      done();
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number testRdbStore0048
     * @tc.desc invalid rootDir test callback
     */
    it('testRdbStore0048', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0048 start *************");
      try {
        relationalStore.deleteRdbStore(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "invalidPath",
          customDir: "entry/rdb"
        }, (e) => {
          expect().assertFail();
        })
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("14800010").assertEqual(e.code);
        console.log(TAG + "************* testRdbStore0048 end *************");
        done();
      }
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number testRdbStore0049
     * @tc.desc db not exist test async
     */
    it('testRdbStore0049', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0049 start *************");
      try {
        await relationalStore.deleteRdbStore(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database/entry/rdb",
        })
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("14800010").assertEqual(e.code);
      }
      console.log(TAG + "************* testRdbStore0049 end *************");
      done();
    })

    /**
     * @tc.name rootDir support deleteRdb test
     * @tc.number testRdbStore0050
     * @tc.desc db not exist test async
     */
    it('testRdbStore0050', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0050 start *************");
      try {
        relationalStore.deleteRdbStore(context, {
          name: "rootDirTest",
          securityLevel: relationalStore.SecurityLevel.S3,
          rootDir: "/data/storage/el2/database/entry/rdb",
        }, () => {
          expect().assertFail();
        })
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("14800010").assertEqual(e.code);
        console.log(TAG + "************* testRdbStore0050 end *************");
        done();
      }
    })

    /**
     * @tc.name tokenizer supported test
     * @tc.number testRdbStore0051
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0051', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0051 start *************");
      try {
        relationalStore.isTokenizerSupported(112321);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("401").assertEqual(e.code);
        console.log(TAG + "************* testRdbStore0051 end *************");
        done();
      }
    })

    /**
     * @tc.name tokenizer supported test
     * @tc.number testRdbStore0052
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0052', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0052 start *************");
      try {
        relationalStore.isTokenizerSupported(401);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("401").assertEqual(e.code);
        console.log(TAG + "************* testRdbStore0052 end *************");
        done();
      }
      done()
    })

    /**
     * @tc.name tokenizer supported test
     * @tc.number testRdbStore0053
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0053', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0053 start *************");
      try {
        relationalStore.isTokenizerSupported(undefined);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("401").assertEqual(e.code);
        console.log(TAG + "************* testRdbStore0053 end *************");
        done();
      }
    })

    /**
     * @tc.name tokenizer supported test
     * @tc.number testRdbStore0054
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0054', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0054 start *************");
      try {
        relationalStore.isTokenizerSupported(521);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect("401").assertEqual(e.code);
        console.log(TAG + "************* testRdbStore0054 end *************");
        done();
      }
    })

    /**
     * @tc.name tokenizer supported test
     * @tc.number testRdbStore0055
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStore0055', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStore0055 start *************");
      let storeConfig: relationalStore.StoreConfig = {
        name: "testSupportTokenizer.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        tokenizer: relationalStore.Tokenizer.CUSTOM_TOKENIZER,
      }
      try {
        relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        console.log("catch err: failed, err: code=" + e.code + " message=" + e.message);
        expect(String(e.code)).assertEqual(String(801));
        console.info(TAG + "************* testRdbStore0055 end   *************");
        done();
      }
    })

    /**
     * @tc.number testCrypt
     * @tc.name testCrypt0001
     * @tc.desc
     */
    it('testCrypt0001', 0, async (done: Function) => {
      console.log(TAG + "************* testCrypt0001 start *************");
      let cryptoParam: relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
      }
      let storeConfig: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S2,
        cryptoParam: cryptoParam
      }
      try {
        let store = relationalStore.getRdbStoreSync(context, storeConfig);
        await store.executeSql(CREATE_TABLE_TEST);
        store.close();
        console.log(TAG + "getRdbStoreSync success 1");
        cryptoParam.encryptionKey = new Uint8Array([6, 5, 4, 3, 2, 1]);
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.close();
        console.log(TAG + "getRdbStoreSync success 2");
        expect(false).assertTrue();
      } catch (e) {
        console.log(TAG + e + " code: " + e.code);
        expect(e.code).assertEqual(14800011)
        console.log(TAG + "testCorrupt0001 success");
      }
      await relationalStore.deleteRdbStore(context, storeConfig);
      done()
      console.log(TAG + "************* testCorrupt0001 end *************");
    });


    /**
     * @tc.name tokenizer supported test
     * @tc.number testRdbStoreConfigChange001
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStoreConfigChange001', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreConfigChange001 start *************");
      let config1: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
      }

      let config2: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S2,
      }

      try {
        relationalStore.getRdbStore(context, config1);
        relationalStore.getRdbStore(context, config2);
        done();
      } catch (err) {
        expect().assertFail();
        console.log(TAG + "************* testRdbStoreConfigChange001 end   *************");
      }
      done();
    })


    /**
     * @tc.name tokenizer supported test
     * @tc.number testRdbStoreConfigChange002
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStoreConfigChange002', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreConfigChange002 start *************");
      let config1: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
      }

      let config2: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S2,
      }

      try {
        relationalStore.getRdbStore(context, config1);
        relationalStore.getRdbStoreSync(context, config2);
        done();
      } catch (err) {
        expect(14800017).assertEqual(Number(err.code))
        console.log(TAG + "************* testRdbStoreConfigChange002 end   *************");
      }
      done();
    })


    /**
     * @tc.name tokenizer supported test
     * @tc.number testRdbStoreConfigChange003
     * @tc.desc invalid tokenizer test callback
     */
    it('testRdbStoreConfigChange003', 0, async (done: Function) => {
      console.log(TAG + "************* testRdbStoreConfigChange003 start *************");
      let config1: relationalStore.StoreConfig = {
        name: "rdbstore9.db",
        securityLevel: relationalStore.SecurityLevel.S1,
      }

      let config2: relationalStore.StoreConfig = {
        name: "rdbstore9.db",
        securityLevel: relationalStore.SecurityLevel.S2,
      }

      try {
        relationalStore.getRdbStoreSync(context, config1);
        relationalStore.getRdbStore(context, config2);
        done();
      } catch (err) {
        expect().assertFail();
        console.log(TAG + "************* testRdbStoreConfigChange003 end   *************");
      }
      done();
    })


    console.log(TAG + "*************Unit Test End*************");
  })
}







