package com.example.myapplication;

import com.example.myapplication.slice.MainAbilitySlice;
import ohos.aafwk.ability.Ability;
import ohos.aafwk.content.Intent;
import ohos.app.Context;
import ohos.app.dispatcher.TaskDispatcher;
import ohos.app.dispatcher.task.TaskPriority;
import ohos.data.DatabaseHelper;
import ohos.data.preferences.Preferences;
import ohos.data.rdb.*;
import ohos.data.resultset.ResultSet;
import ohos.hiviewdfx.HiLog;
import ohos.hiviewdfx.HiLogLabel;

import java.util.function.Predicate;

public class MainAbility extends Ability {
    private static final HiLogLabel LABEL = new HiLogLabel(HiLog.LOG_APP, 0x00201, "Test-RDB");
    String createTable = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, name TEXT NOT NULL, "
            + "AGE INTEGER, salary REAL, data blob)";
    String deleteTable = "DELETE FROM test";

    public void createTable(int num, RdbStore store) {
        store.executeSql(createTable);
        for (int i=0; i<num; i++){
            ValuesBucket value = new ValuesBucket();
            value.putInteger("id", i);
            value.putString("name", "lisi"+ i);
            value.putInteger("age", 18+i);
            value.putFloat("salary", (float) 100.6);
            value.putFloat("data", null);
            store.insert("test", value);
        }
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

        // getColumnIndexForName
        createTable(num, store);
        RdbPredicates predicates = new RdbPredicates("test");
        ResultSet resultSet = store.query(predicates, null);
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.getColumnIndexForName("id");
        }
        etime = System.nanoTime();
        time = etime - stime;
        predicates = null;
        resultSet.close();
        resultSet = null;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getColumnIndexForName averageTime : " + (float)(time) / 1000 / num);

        // getColumnNameForIndex
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.getColumnNameForIndex(0);
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getColumnNameForIndex averageTime : " + (float)(time) / 1000 / num);

        // goTo
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.goTo(1);
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goTo averageTime : " + (float)(time) / 1000 / num);

        // goToRow
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.goToRow(1);
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToRow averageTime : " + (float)(time) / 1000 / num);

        // goToFirstRow
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.goToFirstRow();
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToFirstRow averageTime : " + (float)(time) / 1000 / num);

        // goToLastRow
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.goToLastRow();
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToLastRow averageTime : " + (float)(time) / 1000 / num);

        // goToNextRow
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.goToNextRow();
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToNextRow averageTime : " + (float)(time) / 1000 / num);

        // goToPreviousRow
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        resultSet.goToLastRow();
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.goToPreviousRow();
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToPreviousRow averageTime : " + (float)(time) / 1000 / num);

        // getBlob
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        int index = resultSet.getColumnIndexForName("data");
        resultSet.goToFirstRow();
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.getBlob(index);
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getBlob averageTime : " + (float)(time) / 1000 / num);

        // getString
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        index = resultSet.getColumnIndexForName("name");
        resultSet.goToFirstRow();
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.getString(index);
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getString averageTime : " + (float)(time) / 1000 / num);

        // getLong
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        index = resultSet.getColumnIndexForName("age");
        resultSet.goToFirstRow();
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.getLong(index);
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getLong averageTime : " + (float)(time) / 1000 / num);

        // getDouble
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        index = resultSet.getColumnIndexForName("salary");
        resultSet.goToFirstRow();
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.getDouble(index);
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getDouble averageTime : " + (float)(time) / 1000 / num);

        // isColumnNull
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        index = resultSet.getColumnIndexForName("salary");
        resultSet.goToFirstRow();
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            resultSet.isColumnNull(index);
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest isColumnNull averageTime : " + (float)(time) / 1000 / num);

        // close
        createTable(num, store);
        predicates = new RdbPredicates("test");
        resultSet = store.query(predicates, null);
        index = resultSet.getColumnIndexForName("salary");
        resultSet.goToFirstRow();
        stime = System.nanoTime();
        for (int i = 0; i < num; i++) {
            resultSet.close();
        }
        etime = System.nanoTime();
        predicates = null;
        resultSet.close();
        resultSet = null;
        time = etime - stime;
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest close averageTime : " + (float)(time) / 1000 / num);

        // equalTo
        createTable(num, store);
        stime = System.nanoTime();
        for (int i = 0; i < 200; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.equalTo("name", "lisi1");
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest equalTo averageTime : " + (float)(time) / 1000 / num);

        // notEqualTo
        stime = System.nanoTime();
        for (int i = 0; i < 200; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.notEqualTo("name", "lisi1");
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest notEqualTo averageTime : " + (float)(time) / 1000 / num);

        // beginWrap()
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.beginWrap();
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest beginWrap averageTime : " + (float)(time) / 1000 / num);

        // endWrap
        stime = System.nanoTime();
        for (int i = 0; i < num; i++) {
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.endWrap();
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest beginWrap averageTime : " + (float)(time) / 1000 / num);

        // or
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.or();
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest or averageTime : " + (float)(time) / 1000 / num);

        // and
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.and();
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest and averageTime : " + (float)(time) / 1000 / num);

        // contains
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.contains("name", "lisi");
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest contains averageTime : " + (float)(time) / 1000 / num);

        // beginsWith
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.beginsWith("name", "lisi");
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest beginsWith averageTime : " + (float)(time) / 1000 / num);

        // endsWith
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.endsWith("name", "lisi");
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest endsWith averageTime : " + (float)(time) / 1000 / num);

        // isNull
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.isNull("name");
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest isNull averageTime : " + (float)(time) / 1000 / num);

        // isNotNull
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.isNotNull("name");
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest isNotNull averageTime : " + (float)(time) / 1000 / num);

        // like
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.like("name", "lisi");
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest like averageTime : " + (float)(time) / 1000 / num);

        // glob
        stime = System.nanoTime();
        for (int i = 0; i < num; i++){
            RdbPredicates predicates1 = new RdbPredicates("test");
            for (int j = 0; j < 10; j++) {
                predicates1.glob("name", "lisi");
            }
            predicates1 = null;
        }
        etime = System.nanoTime();
        time = etime - stime;
        HiLog.info(LABEL, "rdbTest glob averageTime : " + (float)(time) / 1000 / num);

        store = null;
        helper.deleteRdbStore(dbName);
}