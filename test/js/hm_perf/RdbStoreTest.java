package com.example.myapplication;

import ohos.app.Context;
import ohos.data.DatabaseHelper;
import ohos.data.rdb.RdbPredicates;
import ohos.data.rdb.RdbStore;
import ohos.data.rdb.StoreConfig;
import ohos.data.resultset.ResultSet;
import ohos.hiviewdfx.HiLog;
import ohos.hiviewdfx.HiLogLabel;

public class RdbStoreTest {
    private static final HiLogLabel LABEL = new HiLogLabel(HiLog.LOG_APP, 0x00201, "Test-RDB");
    private static int num = 1000;
    String path = "android.db";
    DatabaseHelper helper = new DatabaseHelper((Context) this);
    StoreConfig config = StoreConfig.newDefaultConfig(path);
    RdbStore store = helper.getRdbStore(config, 1, null, null);
    String createTable = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, name TEXT NOT NULL, "
            + "AGE INTEGER, salary REAL, data blob)";

    //
    long stime = System.nanoTime();
    long etime = System.nanoTime();
    long time = 0;

    // getColumnIndexForName
    public void testGetColumnIndexForName() {
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
        HiLog.info(LABEL, "rdbTest getColumnIndexForName averageTime : " + (float)(time) / 1000 / num);
    }

    // getColumnNameForIndex
    public void testGetColumnNameForIndex() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest getColumnNameForIndex averageTime : " + (float)(time) / 1000 / num);
    }

    // goTo
    public void testGoTo() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest goTo averageTime : " + (float)(time) / 1000 / num);
    }

    // goToRow
    public void testGoToRow() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest goToRow averageTime : " + (float)(time) / 1000 / num);
    }

    // goToFirstRow
    public void testGogoToFirstRow() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest goToFirstRow averageTime : " + (float)(time) / 1000 / num);
    }

    // goToLastRow
    public void testGogoToLastRow() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest goToLastRow averageTime : " + (float)(time) / 1000 / num);
    }

    // goToNextRow
    public void testGogoToNextRow() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest goToNextRow averageTime : " + (float)(time) / 1000 / num);
    }

    // goToPreviousRow
    public void testGogoPreviousRow() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest goToPreviousRow averageTime : " + (float)(time) / 1000 / num);
    }

    // getBlob
    public void testGetBlob() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest getBlob averageTime : " + (float)(time) / 1000 / num);
    }

    // getString
    public void testGetString() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest getString averageTime : " + (float)(time) / 1000 / num);
    }

    // getLong
    public void testGetLong() {
        time = 0;
        for (int i = 0; i < num; i++) {
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
        HiLog.info(LABEL, "rdbTest getLong averageTime : " + (float) (time) / 1000 / num);
    }

    // getDouble
    public void testGetDouble() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest getDouble averageTime : " + (float)(time) / 1000 / num);
    }

    // isColumnNull
    public void testIsColumnNull() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest isColumnNull averageTime : " + (float)(time) / 1000 / num);
    }

    // close
    public void testClose() {
        time = 0;
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
        HiLog.info(LABEL, "rdbTest close averageTime : " + (float)(time) / 1000 / num);
    }

    // equalTo
    public void testEqualTo() {
        time = 0;
        for (int i = 0; i < num; i++){
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.equalTo("name", "lisi 1");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest equalTo averageTime : " + (float)(time) / 1000 / num);
    }

    // notEqualTo
    public void testNotEqualTo() {
        time = 0;
        for (int i = 0; i < num; i++) {
            RdbPredicates predicates = new RdbPredicates("test");
            stime = System.nanoTime();
            predicates.notEqualTo("name", "lisi 1");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest notEqualTo averageTime : " + (float) (time) / 1000 / num);
    }

    // beginWrap()
    public void testBeginWrap() {
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
    }

    // endWrap
    public void testEndWrap() {
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
    }

    // or
    public void testOr() {
        time = 0;
        for (int i = 0; i < num; i++) {
            RdbPredicates predicates = new RdbPredicates("test");
            RdbPredicates id = predicates.equalTo("id", 1);
            stime = System.nanoTime();
            id.or().equalTo("name", "lisi 2");
            etime = System.nanoTime();
            predicates = null;
            time = time + etime - stime;
        }
        HiLog.info(LABEL, "rdbTest or averageTime : " + (float) (time) / 1000 / num);
    }

    // and
    public void testAnd() {
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
    }

    // contains
    public void testContains() {
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
    }

    // beginsWith
    public void testBeginsWith() {
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
    }

    // endsWith
    public void testEndsWith() {
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
    }

    // isNull
    public void testIsNull() {
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
    }

    // isNotNull
    public void testIsNotNull() {
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
    }

    // like
    public void testLike() {
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
    }

    // glob
    public void testGlob() {
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
    }





}
