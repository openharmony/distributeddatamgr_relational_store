package com.example.myapplicationperfstage2;

import com.example.myapplicationperfstage2.slice.MainAbilitySlice;
import ohos.aafwk.ability.Ability;
import ohos.aafwk.content.Intent;
import ohos.data.DatabaseHelper;
import ohos.data.rdb.RdbPredicates;
import ohos.data.rdb.RdbStore;
import ohos.data.rdb.StoreConfig;
import ohos.data.rdb.ValuesBucket;
import ohos.data.resultset.ResultSet;
import ohos.hiviewdfx.HiLog;
import ohos.hiviewdfx.HiLogLabel;

public class MainAbility extends Ability {
    private static final HiLogLabel LABEL = new HiLogLabel(HiLog.LOG_APP, 0x00201, "Test-RDB");
    String createTable = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, name TEXT NOT NULL, "
            + "AGE INTEGER, salary REAL, data blob)";
    String deleteTable = "DELETE FROM test";

    public void createTable(int num, RdbStore store) {
        store.executeSql(createTable);
        ValuesBucket value = new ValuesBucket();
        value.putString("name", "lisi");
        value.putInteger("age", 18);
        value.putFloat("salary", (float) 100.6);
        value.putFloat("data", null);
        store.insert("test", value);

    }
    public void deleteTable(RdbStore store) {
        store.executeSql(deleteTable);
    }

    @Override
    public void onStart(Intent intent) {
        super.onStart(intent);
        RdbStore store;
        int num = 2000;
        String dbName = "perfTest.db";
        DatabaseHelper helper = new DatabaseHelper(this);
        StoreConfig config = StoreConfig.newDefaultConfig(dbName);
        store = helper.getRdbStore(config, 1, null, null);
        super.setMainRoute(MainAbilitySlice.class.getName());
        //
        long stime = System.nanoTime();
        long etime = System.nanoTime();
        long time = 0;

        HiLog.info(LABEL, "***************** RdbStore Test Begin *****************");

        // version
        int version = 1;
        time = 0;
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            version = store.getVersion();
            etime = System.nanoTime();
            time += etime - stime;
        }
        HiLog.info(LABEL, "rdbTest version averageTime : " + (float)(time) / 1000 / num);

        // beginTransaction_commit
        time = 0;
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            store.beginTransaction();
            store.markAsCommit();
            etime = System.nanoTime();
            time += etime - stime;
        }
        HiLog.info(LABEL, "rdbTest beginTransaction_commit averageTime : " + (float)(time) / 1000 / num);

        // beginTransaction_rollback

        // query
        time = 0;
        createTable(num, store);
        RdbPredicates predicates = new RdbPredicates("test");
        predicates.equalTo("age", 10);
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            ResultSet resultSet = store.query(predicates, new String[]{});
            resultSet.goToFirstRow();
            HiLog.info(LABEL, "rowCount is " + resultSet.getRowCount());
            etime = System.nanoTime();
            time += etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest query averageTime : " + (float)(time) / 1000 / num);

        // insert
        time = 0;
        createTable(num, store);
        ValuesBucket value = new ValuesBucket();
        value.putString("name", "lisi");
        value.putInteger("age", 18);
        value.putFloat("salary", (float) 100.6);
        value.putFloat("data", null);
        predicates = new RdbPredicates("test");
        predicates.equalTo("age", 10);
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            store.insert("test", value);
            etime = System.nanoTime();
            time += etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest insert averageTime : " + (float)(time) / 1000 / num);

        // update
        time = 0;
        createTable(num, store);
        predicates = new RdbPredicates("test");
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            predicates.equalTo("age", 18);
            store.update(value, predicates);
            etime = System.nanoTime();
            time += etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest update averageTime : " + (float)(time) / 1000 / num);

        // delete
        time = 0;
        createTable(num, store);
        predicates = new RdbPredicates("test");
        predicates.equalTo("age", 0);
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            store.delete(predicates);
            etime = System.nanoTime();
            time += etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest delete averageTime : " + (float)(time) / 1000 / num);

        // querySql
        time = 0;
        createTable(num, store);
        predicates = new RdbPredicates("test");
        predicates.equalTo("age", 0);
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            store.querySql("select * from test", new String[]{});
            etime = System.nanoTime();
            time += etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest querySql averageTime : " + (float)(time) / 1000 / num);

        // executeSql
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            store.executeSql("insert into test (name, age) values ('tom', 22)");
            etime = System.nanoTime();
            time += etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest executeSql averageTime : " + (float)(time) / 1000 / num);

        // backup
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            store.backup("backup.db");
            etime = System.nanoTime();
            time += etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest backup averageTime : " + (float)(time) / 1000 / num);

        // restore
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            store.restore("backup.db");
            etime = System.nanoTime();
            time += etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest restore averageTime : " + (float)(time) / 1000 / num);

        store = null;

        HiLog.info(LABEL, "***************** RdbStore Test End *****************");

        HiLog.info(LABEL, "***************** RdbHelper Test Begin *****************");

        // getRdbStore
        time = 0;
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            helper.getRdbStore(config, 1, null, null);
            etime = System.nanoTime();
            time += etime - stime;
        }
        HiLog.info(LABEL, "rdbTest getRdbStore averageTime : " + (float)(time) / 1000 / num);

        // deleteRdbStore
        time = 0;
        for (int i = 0; i < num; i++) {
            stime = System.nanoTime();
            helper.deleteRdbStore(dbName);
            etime = System.nanoTime();
            time += etime - stime;
        }
        HiLog.info(LABEL, "rdbTest deleteRdbStore averageTime : " + (float)(time) / 1000 / num);

        helper.deleteRdbStore(dbName);

        HiLog.info(LABEL, "***************** RdbHelper Test End *****************");
    }
}
