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
    private RdbStore store;
    private int num = 1000;
    String createTable = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, name TEXT NOT NULL, "
                + "AGE INTEGER, salary REAL, data blob)";
    String deleteTable = "DELETE FROM test";
    
    public void createTable(int num, RdbStore store) {
        store.executeSql(createTable);
        for (int i=0; i<1000; i++){
            ValuesBucket value = new ValuesBucket();
            value.putInteger("id", i);
            value.putString("name", "lisi "+ i);
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
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            stime = System.nanoTime();
            resultSet.getColumnIndexForName("id");
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getColumnIndexForName averageTime : " + (float)(time) / 1000 / num);

        // getColumnNameForIndex
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            stime = System.nanoTime();
            resultSet.getColumnNameForIndex(1);
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getColumnNameForIndex averageTime : " + (float)(time) / 1000 / num);

        // goTo
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            stime = System.nanoTime();
            resultSet.goTo(1);
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goTo averageTime : " + (float)(time) / 1000 / num);

        // goToRow
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            stime = System.nanoTime();
            resultSet.goToRow(1);
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToRow averageTime : " + (float)(time) / 1000 / num);

        // goToFirstRow
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            stime = System.nanoTime();
            resultSet.goToFirstRow();
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToFirstRow averageTime : " + (float)(time) / 1000 / num);

        // goToLastRow
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            stime = System.nanoTime();
            resultSet.goToLastRow();
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToLastRow averageTime : " + (float)(time) / 1000 / num);

        // goToNextRow
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            stime = System.nanoTime();
            resultSet.goToNextRow();
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToNextRow averageTime : " + (float)(time) / 1000 / num);

        // goToPreviousRow
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            stime = System.nanoTime();
            resultSet.goToNextRow();
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest goToPreviousRow averageTime : " + (float)(time) / 1000 / num);

        // getBlob
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            int id = resultSet.getColumnIndexForName("name");
            resultSet.goToFirstRow();
            stime = System.nanoTime();
            resultSet.getBlob(id);
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getBlob averageTime : " + (float)(time) / 1000 / num);

        // getString
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            int id = resultSet.getColumnIndexForName("id");
            resultSet.goToFirstRow();
            stime = System.nanoTime();
            resultSet.getString(id);
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getString averageTime : " + (float)(time) / 1000 / num);

        // getLong
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            int id = resultSet.getColumnIndexForName("id");
            resultSet.goToFirstRow();
            stime = System.nanoTime();
            resultSet.getLong(id);
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getLong averageTime : " + (float)(time) / 1000 / num);

        // getDouble
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            int id = resultSet.getColumnIndexForName("id");
            resultSet.goToFirstRow();
            stime = System.nanoTime();
            resultSet.getDouble(id);
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest getDouble averageTime : " + (float)(time) / 1000 / num);

        // isColumnNull
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            int id = resultSet.getColumnIndexForName("id");
            resultSet.goToFirstRow();
            stime = System.nanoTime();
            resultSet.isColumnNull(id);
            etime = System.nanoTime();
            predicates = null;
            resultSet.close();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest isColumnNull averageTime : " + (float)(time) / 1000 / num);

        // close
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            ResultSet resultSet = store.query(predicates, null);
            int id = resultSet.getColumnIndexForName("id");
            resultSet.goToFirstRow();
            resultSet.isColumnNull(id);
            predicates = null;
            stime = System.nanoTime();
            resultSet.close();
            etime = System.nanoTime();
            resultSet = null;
            time = time + etime - stime;
        }
        deleteTable(store);
        HiLog.info(LABEL, "rdbTest close averageTime : " + (float)(time) / 1000 / num);

        // equalTo
        time = 0;
        createTable(num, store);
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.equalTo("name", "lisi 1");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest equalTo averageTime : " + (float)(time) / 1000 / num);

        // notEqualTo
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.notEqualTo("name", "lisi 1");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest notEqualTo averageTime : " + (float)(time) / 1000 / num);

        // beginWrap()
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.beginWrap();
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest beginWrap averageTime : " + (float)(time) / 1000 / num);

        // endWrap
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            predicates.beginWrap().equalTo("id", 1);
            stime = System.nanoTime();
            predicates.endWrap();
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest beginWrap averageTime : " + (float)(time) / 1000 / num);

        // or
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            RdbPredicates id = predicates.equalTo("id", 1);
            stime = System.nanoTime();
            id.or().equalTo("name", "lisi 2");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest or averageTime : " + (float)(time) / 1000 / num);

        // and
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            RdbPredicates id = predicates.equalTo("id", 1);
            stime = System.nanoTime();
            id.and().equalTo("name", "lisi 2");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest and averageTime : " + (float)(time) / 1000 / num);

        // contains
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.contains("name", "lisi 1");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest contains averageTime : " + (float)(time) / 1000 / num);

        // beginsWith
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.beginsWith("name", "lisi");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest beginsWith averageTime : " + (float)(time) / 1000 / num);

        // endsWith
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.endsWith("name", "lisi");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest endsWith averageTime : " + (float)(time) / 1000 / num);

        // isNull
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.isNull("name");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest isNull averageTime : " + (float)(time) / 1000 / num);

        // isNotNull
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.isNotNull("name");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest isNotNull averageTime : " + (float)(time) / 1000 / num);

        // like
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.like("name", "%is%");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest like averageTime : " + (float)(time) / 1000 / num);

        // glob
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.glob("name", "?i*i");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest glob averageTime : " + (float)(time) / 1000 / num);

        helper.deleteRdbStore(dbName);

    }
}