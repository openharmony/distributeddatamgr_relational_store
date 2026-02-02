/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
import RdbPredicatesEtsTest from './RdbstorePredicatesEts.test.ets';
import RdbPredicatesPrefEtsTest from './RdbPredicatesPerfEts.test.ets';
import RelationalStoreDataGroupId from './RdbGroupIdEts.test.ets';
import PerfStatEtsTest from './RdbstorePerfStatEts.test.ets';
import RdbRekeyEtsTest from './RdbstoreRekeyEts.test.ets';
import RdbQueryWithDuplicate from './RdbQueryWithDuplicate.test';
import RdbStoreErrorlogTest from './RdbOnErrorLog.test.ets';
import RDBstoreGetSqlInfoTest from './RdbstoreGetSqlInfoEts.test.ets';
import RdbStoreTransactionTest from './RdbStoreTransaction.test.ets';
import RdbstoreTransactionJsunit from './RdbstoreTransactionJsunit.test.ets';
import RdbStoreTransInsertJsunit from './RdbStoreTransInsertJsunit.test.ets';
import RdbStoreTransJsunit from './RdbStoreTransJsunit.test.ets';
import ExecuteSqlTest from './RdbStoreExecuteSql.test.ets';
import RdbstoreCustomTokenizerTest from './RdbstoreCustomTokenizerEts.ets';
import SetLocaleEtsTest from './RdbstoreSetLocaleEts.test.ets';
import RelationalStoreEtsTest from './RelationalStoreEtsTest.test.ets'
import RdbStoreDataChangeTestEts from './RdbstoreDataChangeEts.test.ets'
import RelationalStoreCloseTest from './RelationalStoreCloseTest.test.ets'
import RdbQueryWithoutRowCount from './RdbQueryWithoutRowCount.test';
import TransQueryWithoutRowCount from './TransQueryWithoutRowCount.test';
import RdbSetDistributedTable from './RdbSetDistributedTable.test';
import RdbStoreDeleteWithReturning from './RdbStoreDeleteWithReturning.test';
import RdbStoreBatchInsertWithReturning from './RdbStoreBatchInsertWithReturning.test';
import RdbStoreUpdateWithReturning from './RdbStoreUpdateWithReturning.test';
import ReturningMultiThreaded from './ReturningMultiThreaded.test';
import RdbStoreUndefinedTest from './RdbStoreUndefined.test';
import RdbStoregetRdbStoreSyncSyncEtsTest from './RdbStoreGetRdbStoreSyncEts.test'
export default function testsuite() {
  RdbPredicatesEtsTest();
  RdbPredicatesPrefEtsTest();
  RelationalStoreDataGroupId();
  PerfStatEtsTest();
  RdbQueryWithDuplicate();
  RdbRekeyEtsTest();
  RdbStoreErrorlogTest();
  RDBstoreGetSqlInfoTest();
  RdbStoreTransactionTest();
  RdbstoreTransactionJsunit();
  RdbStoreTransInsertJsunit();
  RdbStoreTransJsunit();
  ExecuteSqlTest();
  RdbstoreCustomTokenizerTest();
  SetLocaleEtsTest();
  RelationalStoreEtsTest();
  RdbStoreDataChangeTestEts();
  RelationalStoreCloseTest();
  RdbQueryWithoutRowCount();
  RdbSetDistributedTable();
  TransQueryWithoutRowCount();
  RdbStoreDeleteWithReturning();
  RdbStoreBatchInsertWithReturning();
  RdbStoreUpdateWithReturning();
  ReturningMultiThreaded();
  RdbStoreUndefinedTest();
  RdbStoregetRdbStoreSyncSyncEtsTest();
}