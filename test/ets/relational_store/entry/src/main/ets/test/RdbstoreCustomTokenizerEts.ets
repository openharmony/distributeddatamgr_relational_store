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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import relationalStore from '@ohos.data.relationalStore'
import common from "@ohos.app.ability.common"
let context: common.UIAbilityContext

const TAG = "[RDB_CUSTOM_TOKENIZER_TEST]";

export default function RdbStoreCustomTokenizerTest() {
  describe('rdbStoreCustomTokenizerEtsTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll');
      context = globalThis.abilityContext;
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
     * @tc.number rdbStoreCustomTokenizerEtsTest
     * @tc.name CustomTokenizerTest001
     * @tc.desc Test a single long word
     */
    it('CustomTokenizerTest001', 0, async () => {
      console.log(TAG + "************* CustomTokenizerTest001 start *************");
      try {
        let store: relationalStore.RdbStore | undefined = undefined;
        const storeConfig: relationalStore.StoreConfig = {
          name: "MyStore.db",
          securityLevel: relationalStore.SecurityLevel.S3
        };
        let customType = relationalStore.Tokenizer.CUSTOM_TOKENIZER;
        let customTypeSupported = relationalStore.isTokenizerSupported(customType);
        if (customTypeSupported) {
          storeConfig.tokenizer = customType;
        } else {
          console.info('not support custom tokenizer.');
          return true;
        }
        store = await relationalStore.getRdbStore(context, storeConfig);
        if (store == undefined) {
          expect().assertFail();
          return false;
        }

        let createTableSql = "CREATE VIRTUAL TABLE example USING fts5(content, " +
          "tokenize = 'customtokenizer cut_mode short_words')";
        await store.executeSql(createTableSql);

        let insertValueSql = "INSERT INTO example VALUES('电子邮件')";
        await store.executeSql(insertValueSql);

        let words: string[] = ["电子", "邮件", "电子邮件"];
        for (const word of words) {
          let resultSet = await store.querySql("SELECT * FROM example WHERE content MATCH ?;", [word]);
          expect(1).assertEqual(resultSet.rowCount);
        }

        let dropTableSql = "DROP TABLE IF EXISTS example";
        await store.executeSql(dropTableSql);
        await store.close();
      } catch (err) {
        console.log("errcode: " + err.code);
        expect().assertFail();
      }
      console.log(TAG + "************* CustomTokenizerTest001 end *************");
      return true;
    });

    /**
     * @tc.number rdbStoreCustomTokenizerEtsTest
     * @tc.name CustomTokenizerTest002
     * @tc.desc Test if there is a long word in a sentence
     */
    it('CustomTokenizerTest002', 0, async () => {
      console.log(TAG + "************* CustomTokenizerTest002 start *************");
      try {
        let store: relationalStore.RdbStore | undefined = undefined;
        const storeConfig: relationalStore.StoreConfig = {
          name: "MyStore.db",
          securityLevel: relationalStore.SecurityLevel.S3
        };
        let customType = relationalStore.Tokenizer.CUSTOM_TOKENIZER;
        let customTypeSupported = relationalStore.isTokenizerSupported(customType);
        if (customTypeSupported) {
          storeConfig.tokenizer = customType;
        } else {
          console.info('not support custom tokenizer.');
          return true;
        }
        store = await relationalStore.getRdbStore(context, storeConfig);
        if (store == undefined) {
          expect().assertFail();
          return false;
        }

        let createTableSql = "CREATE VIRTUAL TABLE example USING fts5(content, " +
          "tokenize = 'customtokenizer cut_mode short_words')";
        await store.executeSql(createTableSql);

        let insertValueSql = "INSERT INTO example VALUES('这是一封电子邮件')";
        await store.executeSql(insertValueSql);

        let words: string[] = ["电子", "邮件", "电子邮件"];
        for (const word of words) {
          let resultSet = await store.querySql("SELECT * FROM example WHERE content MATCH ?;", [word]);
          expect(1).assertEqual(resultSet.rowCount);
        }

        let dropTableSql = "DROP TABLE IF EXISTS example";
        await store.executeSql(dropTableSql);
        await store.close();
      } catch (err) {
        console.log("errcode: " + err.code);
        expect().assertFail();
      }
      console.log(TAG + "************* CustomTokenizerTest002 end *************");
      return true;
    });

    /**
     * @tc.number rdbStoreCustomTokenizerEtsTest
     * @tc.name CustomTokenizerTest003
     * @tc.desc Test multiple long words
     */
    it('CustomTokenizerTest003', 0, async () => {
      console.log(TAG + "************* CustomTokenizerTest003 start *************");
      try {
        let store: relationalStore.RdbStore | undefined = undefined;
        const storeConfig: relationalStore.StoreConfig = {
          name: "MyStore.db",
          securityLevel: relationalStore.SecurityLevel.S3
        };
        let customType = relationalStore.Tokenizer.CUSTOM_TOKENIZER;
        let customTypeSupported = relationalStore.isTokenizerSupported(customType);
        if (customTypeSupported) {
          storeConfig.tokenizer = customType;
        } else {
          console.info('not support custom tokenizer.');
          return true;
        }
        store = await relationalStore.getRdbStore(context, storeConfig);
        if (store == undefined) {
          expect().assertFail();
          return false;
        }

        let createTableSql = "CREATE VIRTUAL TABLE example USING fts5(content, " +
          "tokenize = 'customtokenizer cut_mode short_words')";
        await store.executeSql(createTableSql);

        let insertValueSql = "INSERT INTO example VALUES('这是一封关于少数民族的电子邮件')";
        await store.executeSql(insertValueSql);

        let words: string[] = ["电子", "邮件", "电子邮件", "少数", "民族", "少数民族"];
        for (const word of words) {
          let resultSet = await store.querySql("SELECT * FROM example WHERE content MATCH ?;", [word]);
          expect(1).assertEqual(resultSet.rowCount);
        }

        let dropTableSql = "DROP TABLE IF EXISTS example";
        await store.executeSql(dropTableSql);
        await store.close();
      } catch (err) {
        console.log("errcode: " + err.code);
        expect().assertFail();
      }
      console.log(TAG + "************* CustomTokenizerTest003 end *************");
      return true;
    });

    /**
     * @tc.number rdbStoreCustomTokenizerEtsTest
     * @tc.name CustomTokenizerTest004
     * @tc.desc Test repeated long words
     */
    it('CustomTokenizerTest004', 0, async () => {
      console.log(TAG + "************* CustomTokenizerTest004 start *************");
      try {
        let store: relationalStore.RdbStore | undefined = undefined;
        const storeConfig: relationalStore.StoreConfig = {
          name: "MyStore.db",
          securityLevel: relationalStore.SecurityLevel.S3
        };
        let customType = relationalStore.Tokenizer.CUSTOM_TOKENIZER;
        let customTypeSupported = relationalStore.isTokenizerSupported(customType);
        if (customTypeSupported) {
          storeConfig.tokenizer = customType;
        } else {
          console.info('not support custom tokenizer.');
          return true;
        }
        store = await relationalStore.getRdbStore(context, storeConfig);
        if (store == undefined) {
          expect().assertFail();
          return false;
        }

        let createTableSql = "CREATE VIRTUAL TABLE example USING fts5(content, " +
          "tokenize = 'customtokenizer cut_mode short_words')";
        await store.executeSql(createTableSql);

        let insertValueSql = "INSERT INTO example VALUES('华中师范大学是一所位于武汉市的全日制综合性师范大学')";
        await store.executeSql(insertValueSql);

        let words: string[] = ["华中", "中师", "师范", "武汉", "武汉市", "师范大学"];
        for (const word of words) {
          let resultSet = await store.querySql("SELECT * FROM example WHERE content MATCH ?;", [word]);
          expect(1).assertEqual(resultSet.rowCount);
        }

        let dropTableSql = "DROP TABLE IF EXISTS example";
        await store.executeSql(dropTableSql);
        await store.close();
      } catch (err) {
        console.log("errcode: " + err.code);
        expect().assertFail();
      }
      console.log(TAG + "************* CustomTokenizerTest004 end *************");
      return true;
    });

    /**
     * @tc.number rdbStoreCustomTokenizerEtsTest
     * @tc.name CustomTokenizerTest005
     * @tc.desc Test intermediate words
     */
    it('CustomTokenizerTest005', 0, async () => {
      console.log(TAG + "************* CustomTokenizerTest005 start *************");
      try {
        let store: relationalStore.RdbStore | undefined = undefined;
        const storeConfig: relationalStore.StoreConfig = {
          name: "MyStore.db",
          securityLevel: relationalStore.SecurityLevel.S3
        };
        let customType = relationalStore.Tokenizer.CUSTOM_TOKENIZER;
        let customTypeSupported = relationalStore.isTokenizerSupported(customType);
        if (customTypeSupported) {
          storeConfig.tokenizer = customType;
        } else {
          console.info('not support custom tokenizer.');
          return true;
        }
        store = await relationalStore.getRdbStore(context, storeConfig);
        if (store == undefined) {
          expect().assertFail();
          return false;
        }

        let createTableSql = "CREATE VIRTUAL TABLE example USING fts5(content, " +
          "tokenize = 'customtokenizer cut_mode short_words')";
        await store.executeSql(createTableSql);

        let insertValueSql = "INSERT INTO example VALUES('中华人民共和国')";
        await store.executeSql(insertValueSql);

        let words: string[] = ["中华", "华人", "人民", "共和", "共和国", "中华人民共和国"];
        for (const word of words) {
          let resultSet = await store.querySql("SELECT * FROM example WHERE content MATCH ?;", [word]);
          expect(1).assertEqual(resultSet.rowCount);
        }
        let noMatchWord = "人民共和国";
        let noMatchResultSet = await store.querySql("SELECT * FROM example WHERE content MATCH ?;", [noMatchWord]);
        expect(0).assertEqual(noMatchResultSet.rowCount);

        let dropTableSql = "DROP TABLE IF EXISTS example";
        await store.executeSql(dropTableSql);
        await store.close();
      } catch (err) {
        console.log("errcode: " + err.code);
        expect().assertFail();
      }
      console.log(TAG + "************* CustomTokenizerTest005 end *************");
      return true;
    });

    /**
     * @tc.number rdbStoreCustomTokenizerEtsTest
     * @tc.name CustomTokenizerTest006
     * @tc.desc Test in both Chinese and English
     */
    it('CustomTokenizerTest006', 0, async () => {
      console.log(TAG + "************* CustomTokenizerTest006 start *************");
      try {
        let store: relationalStore.RdbStore | undefined = undefined;
        const storeConfig: relationalStore.StoreConfig = {
          name: "MyStore.db",
          securityLevel: relationalStore.SecurityLevel.S3
        };
        let customType = relationalStore.Tokenizer.CUSTOM_TOKENIZER;
        let customTypeSupported = relationalStore.isTokenizerSupported(customType);
        if (customTypeSupported) {
          storeConfig.tokenizer = customType;
        } else {
          console.info('not support custom tokenizer.');
          return true;
        }
        store = await relationalStore.getRdbStore(context, storeConfig);
        if (store == undefined) {
          expect().assertFail();
          return false;
        }

        let createTableSql = "CREATE VIRTUAL TABLE example USING fts5(content, " +
          "tokenize = 'customtokenizer cut_mode short_words')";
        await store.executeSql(createTableSql);

        let insertValueSql = "INSERT INTO example VALUES('武汉市长江大桥Wuhan Yangtze River Bridge是武汉市最长的桥')";
        await store.executeSql(insertValueSql);

        let words: string[] = ["长江", "大桥", "Wuhan", "Yangtze", "武汉市"];
        for (const word of words) {
          let resultSet = await store.querySql("SELECT * FROM example WHERE content MATCH ?;", [word]);
          expect(1).assertEqual(resultSet.rowCount);
        }

        let dropTableSql = "DROP TABLE IF EXISTS example";
        await store.executeSql(dropTableSql);
        await store.close();
      } catch (err) {
        console.log("errcode: " + err.code);
        expect().assertFail();
      }
      console.log(TAG + "************* CustomTokenizerTest006 end *************");
      return true;
    });
    console.log(TAG + "*************Unit Test End*************");
  })
}