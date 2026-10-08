# RDB 用例知识库

本文件是 relational_store（关系型数据库）仓库测试用例的完整知识库，供 AI Agent 和开发者快速定位用例、理解测试结构、运行和修复测试。

---

## 1. 概述

| 指标 | 数值 |
|------|------|
| 用例总数 | 1964（HWTEST_F/HWTEST/HWTEST_P） |
| Fuzz 测试 | 47 个 fuzzer 文件 |
| 测试二进制 | 23 个（见第 4 节） |
| 测试 Fixture 类 | 75 个 |
| 测试框架 | OpenHarmony HWTEST（封装 GTest） |
| 测试宏格式 | `HWTEST_F(Fixture, CaseName, TestSize.LevelN)` |

测试源码在上游仓库 `relational_store/test/` 下，CMake 配置在 mock 仓库 `test/relational_store/` 下。

---

## 2. 用例目录

### 2.1 目录结构总览

```
relational_store/test/                          # 上游测试源码
├── interface/                                   # 接口层测试（721 用例）
├── native/
│   ├── rdb/
│   │   ├── unittest/                            # Native 核心测试（805 用例）
│   │   ├── mock/                               # Mock 辅助文件
│   │   ├── fuzztest/                            # Fuzz 测试（25 个 fuzzer）
│   │   └── distributedtest/                     # 分布式测试
│   ├── clouddata/unittest/                      # 云数据测试（72 用例）
│   ├── dataability/unittest/                    # DataAbility 测试（16 用例）
│   ├── appdatafwk/unittest/                    # AppDataFwk 测试（11 用例）
│   ├── rdb_service_adapter/unittest/            # 服务适配器测试（33 用例）
│   ├── rdb_data_share_adapter/unittest/         # DataShare 适配器测试（11 用例）
│   └── rdb_data_ability_adapter/unittest/       # DataAbility 适配器测试（2 用例）
├── ndk/
│   ├── unittest/                                # NDK C API 测试（291 用例）
│   └── fuzztest/                                # NDK Fuzz 测试（14 个 fuzzer）
└── test/interface/...                           # (同 interface/ 重复路径)

test/relational_store/                           # 本地 CMake 配置
├── CMakeLists.txt                               # 顶层入口，add_subdirectory 各子目录
├── rdb/
│   ├── CMakeLists.txt                           # Native 测试入口
│   ├── native_rdb_test.cmake                    # NativeRdbTest（P0 优先级）
│   ├── native_rdb_multiprocess_test.cmake       # NativeRdbMultiProcessTest
│   ├── native_rdb_multithread_test.cmake        # NativeRdbMultiThreadTest
│   ├── native_rdb_log_test.cmake                # NativeRdbLogTest
│   ├── native_rdb_security_test.cmake           # NativeRdbSecurityManagerTest
│   ├── delay_actuator_test.cmake                # DelayActuatorTest
│   ├── silent_proxy_test.cmake                  # SilentProxyTest
│   ├── dynamic_load_test.cmake                  # DynamicLoadTest
│   ├── sqlite_statement_test.cmake             # SqliteStatementTest
│   ├── global_resource_test.cmake               # GlobalResourceTest
│   ├── rdb_impl_sources.cmake                   # 实现源文件列表（OBJECT 库）
│   ├── security_manager_test_helper.cpp         # 安全管理测试辅助
│   └── *.cmake（已禁用，见 2.3）
├── interface/CMakeLists.txt                     # RdbInterfaceTest（P0 优先级）
├── ndk/CMakeLists.txt                           # NativeRdbNdkTest
├── clouddata/CMakeLists.txt                     # NativeCloudDataTest + CloudManagerMockTest
├── appdatafwk/CMakeLists.txt                    # NativeAppDataFwkTest
├── dataability/CMakeLists.txt                   # NativeDataAbilityTest
├── rdb_service_adapter/
│   ├── CMakeLists.txt                           # 4 个测试二进制
│   └── rdb_test_main.cpp                        # 自定义 test main
├── rdb_data_ability_adapter/CMakeLists.txt      # NativeDataAbilityAdapterTest
└── rdb_data_share_adapter/CMakeLists.txt        # RdbDataShareAdapterTest
```

### 2.2 用例分类统计

| 测试层 | 用例数 | 源码目录 | 说明 |
|--------|--------|----------|------|
| Native unittest | 805 | `relational_store/test/native/rdb/unittest/` | RDB 核心：CRUD、事务、加密、连接池、备份恢复 |
| Interface | 721 | `relational_store/test/interface/` | 接口层：公共 API 端到端验证 |
| NDK | 291 | `relational_store/test/ndk/unittest/` | C API：NDK 头文件 `oh_rdb_*.h` |
| CloudData | 72 | `relational_store/test/native/clouddata/unittest/` | 云同步：云端数据管理 |
| ServiceAdapter | 33 | `relational_store/test/native/rdb_service_adapter/unittest/` | 服务适配：IPC 代理、序列化 |
| DataAbility | 16 | `relational_store/test/native/dataability/unittest/` | DataAbility 谓词 |
| AppDataFwk | 11 | `relational_store/test/native/appdatafwk/unittest/` | AppData 框架：序列化 |
| DataShareAdapter | 11 | `relational_store/test/native/rdb_data_share_adapter/unittest/` | DataShare 适配器 |
| DataAbilityAdapter | 2 | `relational_store/test/native/rdb_data_ability_adapter/unittest/` | DataAbility 工具 |
| Fuzz | 47 个文件 | `relational_store/test/native/rdb/fuzztest/` + `ndk/fuzztest/` | 模糊测试 |
| **合计** | **1964** | | |

### 2.3 已禁用的 CMake 独有目标

以下目标曾从 NativeRdbTest 拆分创建，但 GN 中不存在对应目标，现已禁用以与 GN 对齐：

| 已禁用目标 | GN 等价物 | 状态 |
|---|---|---|
| `native_rdb_impl_test.cmake` (NativeRdbImplTest) | 合并入 NativeRdbTest | 已删除 |
| `connection_pool_test.cmake` (ConnectionPoolTest) | 合并入 NativeRdbTest | 已删除 |
| `store_core_test.cmake` (StoreCoreTest) | 合并入 NativeRdbTest | 已删除 |
| `utils_test.cmake` (UtilsTest) | 合并入 NativeRdbTest | 已删除 |
| `concurrent_test.cmake` (ConcurrentTest) | NativeRdbMultiThreadTest | 已删除 |
| `encrypt_test.cmake` (EncryptTest) | NativeRdbSecurityManagerTest | 已删除 |
| `backup_restore_test.cmake` (BackupRestoreTest) | 合并入 NativeRdbTest | 已删除 |
| `mockservice_test.cmake` (NativeRdbConditionTest, NativeRdbAsyncAfterOpenTest) | 合并入 NativeRdbTest | 已删除 |
| `rdb_db_info_dfx_test.cmake` (RdbDbInfoDfxTest) | 本地 mock 文件，上游不存在 | 已排除 |

---

## 3. 测试 Fixture 清单

### 3.1 Native unittest（34 个 Fixture）

| Fixture 类 | 测试文件 | 用例数 | 覆盖领域 |
|---|---|---|---|
| `RdbStoreImplTest` | rdb_store_impl_test.cpp | 130 | RDB 核心 CRUD、批插、查询、时间戳 |
| `RdbDoubleWriteTest` | rdb_double_write_test.cpp | 49 | 双写（RD + RDB） |
| `SqliteUtilsTest` | sqlite_utils_test.cpp | 46 | SQLite 工具函数 |
| `RdbDoubleWriteBinlogTest` | rdb_double_write_binlog_test.cpp | 46 | 双写 Binlog |
| `RdbSqliteSharedResultSetTest` | rdb_sqlite_shared_result_set_test.cpp | 44 | 共享结果集 |
| `RdbStorePredicateTest` | rdb_predicates_test.cpp | 43 | 谓词 |
| `RdbEncryptUpgradeTest` | rdb_encrypt_upgrade_test.cpp | 43 | 加密升级 |
| `RdbTransDBTest` | rdb_trans_db_test.cpp | 36 | 事务数据库 |
| `RdbRekeyVectorTest` | rdb_store_rekey_vector_test.cpp | 18 | Rekey 向量 |
| `TransactionTest` | transaction_test.cpp | 15 | 事务 |
| `ConnectionTest` | connection_test.cpp | 14 | 连接 |
| `RdbReplicaPathTest` | rdb_replica_path_test.cpp | 12 | 副本路径 |
| `CacheBlockTest` | cache_block_test.cpp | 12 | 缓存块 |
| `RdbRekeyTest` | rdb_store_rekey_test.cpp | 11 | Rekey |
| `RdbDbInfoTest` | rdb_db_info_test.cpp | 9 | 数据库信息 |
| `RdbStoreDistributedTest` | rdb_distributed_test.cpp | 2 | 分布式 |
| `RdbStoreBackupRestoreTest` | rdb_store_backup_restore_test.cpp | 1 | 备份恢复 |
| `RdbSecurityManagerTest` | rdb_security_manager_test.cpp | 7 | 安全管理 |
| `RdUtilsTest` | rd_utils_test.cpp | 7 | RD 工具 |
| `RdbEncryptTest` | rdb_encrypt_decrypt_test.cpp | 6 | 加密解密 |
| `RdbManagerTest` | rdb_manager_test.cpp | 5 | RDB 管理器 |
| `CleanDeviceDirtyDataTest` | clean_device_dirty_data_test.cpp | 5 | 清理脏数据 |
| `RdbStepResultSetTest` | rdb_step_result_set_test.cpp | 4 | 步骤结果集 |
| `RdbDoubleWriteConcurrentTest` | rdb_double_write_concurrent_test.cpp | 4 | 双写并发 |
| `RawDataParserTest` | raw_data_parser_test.cpp | 4 | 原始数据解析 |
| `BigIntegerTest` | big_integer_test.cpp | 1 | 大整数 |
| `ConnectionPoolTest` | connection_pool_test.cpp | 2 | 连接池 |
| `DelayActuatorTest` | delay_actuator_test.cpp | 2 | 延迟执行器 |
| `DelayNotifyTest` | delay_notify_test.cpp | 3 | 延迟通知 |
| `RdbUtilsTest` | rdb_utils_test.cpp | 8 | RDB 工具 |
| `RdbGetStoreTest` | rdb_get_store_test.cpp | 2 | GetStore |
| `RdbServiceProxyTest` | rdb_service_proxy_test.cpp | 1 | 服务代理 |
| `ConvertDBStatusNativeTest` | convert_db_status_native_test.cpp | 1 | DB 状态转换 |
| `RdbExecuteRdTest` | rdb_execute_rd_test.cpp | — | RD 执行（TestWithParam） |

### 3.2 Interface（41 个 Fixture，721 用例）

| Fixture 类 | 测试文件 | 用例数 | 覆盖领域 |
|---|---|---|---|
| `DuplicateColumnDataTest` | rdb_duplicate_column_data_test.cpp | 60 | 重复列数据 |
| `RdbInterfaceTransactionTest` | transaction_test.cpp | 48 | 事务 |
| `RdbStoreConfigTest` | rdb_store_config_test.cpp | 44 | 存储配置 |
| `RdbInterfaceStepResultSetTest` | rdb_step_result_set_test.cpp | 43 | 步骤结果集 |
| `RdbPredicatesInterfaceTest` | rdb_predicates_test.cpp | 40 | 谓词 |
| `CacheResultSetTest` | cache_result_set_test.cpp | 39 | 缓存结果集 |
| `RdbHelperTest` | rdb_helper_test.cpp | 35 | RDB Helper |
| `RdbStoreSubTest` | rdb_store_subscribe_test.cpp | 31 | 订阅 |
| `RdbInterfaceRekeyTest` | rdb_store_rekey_test.cpp | 31 | Rekey |
| `RdbInterfaceBackupRestoreTest` | rdb_store_backup_restore_test.cpp | 27 | 备份恢复 |
| `RdbReadOnlyTest` | rdb_read_only_test.cpp | 26 | 只读 |
| `RdbSqlUtilsTest` | rdb_sql_utils_test.cpp | 18 | SQL 工具 |
| `QueryWithCrudTest` | rdb_concurrent_querywithcurd_test.cpp | 15 | 并发查询 |
| `RdbInterfaceGetStoreTest` | rdb_get_store_test.cpp | 13 | GetStore |
| `RdbInterfaceEncryptTest` | rdb_encrypt_decrypt_test.cpp | 12 | 加密解密 |
| `ValuesBucketTest` | rdb_value_bucket_test.cpp | 10 | ValuesBucket |
| `RdbTransactionTest` | rdb_transaction_test.cpp | 10 | 事务 |
| `RdbStoreInterfaceTest` | rdb_store_interface_test.cpp | 9 | 存储接口 |
| `RdbStorePredicateJoinTest` | rdb_predicates_join_test.cpp | 9 | 谓词 JOIN |
| `RdbBigIntTest` | rdb_bigint_test.cpp | 9 | 大整数 |
| `RdbAttachTest` | rdb_attach_test.cpp | 9 | ATTACH |
| `RdbOpenCallbackTest` | rdb_open_callback_test.cpp | 8 | Open 回调 |
| `RdbMemoryDbTest` | rdb_memory_db_test.cpp | 8 | 内存数据库 |
| `RdbStepResultSetGetRowTest` | rdb_step_result_get_row_test.cpp | 6 | GetRow |
| `RdbRdDataAgingTest` | rdb_rd_data_aging_test.cpp | 6 | 数据老化 |
| `ValueObjectTest` | value_object_test.cpp | 5 | ValueObject |
| `RdbStorePredicateJoinBTest` | rdb_predicates_join_b_test.cpp | 5 | JOIN B |
| `RdbInterfaceStoreDistributedTest` | rdb_distributed_test.cpp | 5 | 分布式 |
| `RdbWalLimitTest` | rdb_wal_limit_test.cpp | 4 | WAL 限制 |
| `RdbCorruptTest` | rdb_corrupt_test.cpp | 2 | 损坏 |
| `RestrictedDBTest` | restricted_db_test.cpp | 1 | 受限数据库 |
| `RdbUpgradeTest` | rdb_upgrade_test.cpp | 1 | 升级 |
| `RdbCallbackIcuTest` | rdb_callback_icu_test.cpp | 1 | ICU 回调 |
| `RdbConcurrentTest` | rdb_store_concurrent_test.cpp | — | 并发（TestWithParam） |
| `RdbDeleteTest` | rdb_delete_test.cpp | — | 删除（TestWithParam） |
| `RdbExecuteTest` | rdb_execute_test.cpp | — | 执行（TestWithParam） |
| `RdbInterfaceExecuteRdTest` | rdb_execute_rd_test.cpp | — | RD 执行（TestWithParam） |
| `RdbStoreInsertTest` | rdb_insert_test.cpp | — | 插入（TestWithParam） |
| `RdbStoreUpdateTest` | rdb_update_test.cpp | — | 更新（TestWithParam） |
| `RdbRekeyExTest` | rdb_store_rekeyEx_test.cpp | — | RekeyEx（TestWithParam） |
| `FoundationStoreTest` | rdb_store_interface_test.cpp | — | Foundation Store |

### 3.3 NDK（17 个 Fixture，291 用例）

| Fixture 类 | 测试文件 | 用例数 | 覆盖领域 |
|---|---|---|---|
| `RdbNativeStoreTest` | rdb_store_test.cpp | 47 | NDK Store |
| `RdbTransactionCapiTest` | rdb_transaction_capi_test.cpp | 35 | 事务 C API |
| `RdbNativePredicatesTest` | rdb_predicates_test.cpp | 29 | 谓词 |
| `RdbStoreReturningTest` | rdb_store_returning_test.cpp | 28 | Returning |
| `RdbTransactionQueryWithoutRowCountTest` | rdb_transaction_query_without_rowCount_test.cpp | 22 | 事务查询 |
| `RdbQueryWithoutRowCountTest` | rdb_query_without_rowCount_test.cpp | 22 | 查询 |
| `RdbStoreCorruptHandlerTest` | rdb_store_corrupt_handler_test.cpp | 21 | 损坏处理 |
| `RdbNativeStoreConfigV2Test` | rdb_store_configv2_test.cpp | 21 | 配置 V2 |
| `RdbNativeAssetTest` | rdb_asset_test.cpp | 20 | 资产 |
| `RdbNativeCursorTest` | rdb_cursor_test.cpp | 12 | 游标 |
| `RdbVectorTest` | rdb_vector_test.cpp | 8 | 向量 |
| `RdbCryptoParamTest` | rdb_crypto_param_test.cpp | 8 | 加密参数 |
| `RdbStoreRekeyTest` | rdb_store_rekeyEx_test.cpp | 7 | Rekey |
| `RdbPerformanceTest` | rdb_performance_test.cpp | 5 | 性能 |
| `RdbCursorGetSizeTest` | rdb_cursor_getSize_test.cpp | 4 | 游标大小 |
| `RelationalCursorTest` | relational_cursor_test.cpp | 1 | 关系型游标 |
| `RdbNdkPredicatesPrefTest` | rdb_predicates_pref_test.cpp | 1 | 谓词前缀 |

### 3.4 其他层 Fixture

| 测试层 | Fixture 类 | 测试文件 | 用例数 |
|---|---|---|---|
| CloudData | `CloudDataTest` | cloud_data_test.cpp | 64 |
| CloudData | `CloudManagerMockTest` | cloud_manager_mock_test.cpp | 8 |
| ServiceAdapter | `RdbManagerImplTest` | rdb_manager_impl_test.cpp | 6 |
| ServiceAdapter | `ResultSetProxyTest` | result_set_proxy_test.cpp | 10 |
| ServiceAdapter | `ResultSetProxyAdapterTest` | result_set_proxy_adapter_test.cpp | 1 |
| ServiceAdapter | `RdbTypesUtilTest` | rdb_types_util_test.cpp | 11 |
| ServiceAdapter | `RdbServiceProxyTest` | rdb_service_proxy_test.cpp | 5 |
| DataAbility | `DataAbilityPredicatesTest` | data_ability_predicates_test.cpp | 16 |
| AppDataFwk | `SerializableTest` | serializable_test.cpp | 11 |
| DataShareAdapter | `RdbDataShareAdapterTest` | rdb_data_share_adapter_test.cpp | 11 |
| DataAbilityAdapter | `DataAbilityUtilsTest` | data_ability_utils_test.cpp | 2 |

---

## 4. 测试二进制清单

### 4.1 活跃测试目标

| 测试二进制 | 优先级 | CMake 入口 | 链接方式 | 用例数 |
|---|---|---|---|---|
| `NativeRdbTest` | P0 | rdb/native_rdb_test.cmake | 内联实现源码 + 共享库 | 805 |
| `RdbInterfaceTest` | P0 | interface/CMakeLists.txt | 共享库（不内联） | 721 |
| `NativeRdbNdkTest` | — | ndk/CMakeLists.txt | 共享库 | 291 |
| `NativeRdbMultiProcessTest` | — | rdb/native_rdb_multiprocess_test.cmake | 共享库 | 9 |
| `NativeRdbMultiThreadTest` | — | rdb/native_rdb_multithread_test.cmake | 共享库 | — |
| `NativeRdbLogTest` | — | rdb/native_rdb_log_test.cmake | 共享库 | 11 |
| `NativeRdbSecurityManagerTest` | — | rdb/native_rdb_security_test.cmake | 共享库 | 7 |
| `DelayActuatorTest` | — | rdb/delay_actuator_test.cmake | 共享库 | 2 |
| `SilentProxyTest` | — | rdb/silent_proxy_test.cmake | 内联实现源码 | 34 |
| `DynamicLoadTest` | — | rdb/dynamic_load_test.cmake | 内联实现源码 | 8 |
| `SqliteStatementTest` | — | rdb/sqlite_statement_test.cmake | 内联实现源码 | 3 |
| `GlobalResourceTest` | — | rdb/global_resource_test.cmake | 内联实现源码 | 1 |
| `NativeCloudDataTest` | — | clouddata/native_cloud_data_test.cmake | 共享库 | 64 |
| `CloudManagerMockTest` | — | clouddata/cloud_manager_mock_test.cmake | 共享库 | 8 |
| `NativeAppDataFwkTest` | — | appdatafwk/native_appdatafwk_test.cmake | 共享库 | 11 |
| `NativeDataAbilityTest` | — | dataability/native_dataability_test.cmake | 共享库 | 16 |
| `RdbManagerImplTest` | — | rdb_service_adapter/CMakeLists.txt | 内联 + 共享库 | 6 |
| `ResultSetProxyTest` | — | rdb_service_adapter/CMakeLists.txt | 内联 + 共享库 | 10+1 |
| `RdbTypesUtilTest` | — | rdb_service_adapter/CMakeLists.txt | 共享库 | 11 |
| `RdbServiceProxyTest` | — | rdb_service_adapter/CMakeLists.txt | 内联 + 共享库 | 5 |
| `NativeDataAbilityAdapterTest` | — | rdb_data_ability_adapter/CMakeLists.txt | 共享库 | 2 |
| `RdbDataShareAdapterTest` | — | rdb_data_share_adapter/CMakeLists.txt | 共享库 | 11 |

### 4.2 链接方式说明

| 方式 | 说明 | 适用场景 |
|---|---|---|
| 内联实现源码 + 共享库 | 编译上游 `.cpp` 为 OBJECT 库，与共享库共存（需 `--allow-multiple-definition`） | NativeRdbTest、ServiceAdapter 测试 |
| 仅共享库 | 链接 `relational_store` 共享库，不编译实现源码 | Interface、NDK、CloudData 等接口层测试 |
| 内联实现源码（不链接共享库） | 完全自包含，编译上游 `.cpp` 为 OBJECT 库 | SilentProxy、DynamicLoad、SqliteStatement、GlobalResource |

---

## 5. Mock 与辅助文件

### 5.1 Native RDB Mock

| 文件 | 路径 | 用途 |
|---|---|---|
| `connection_mock.h` | `relational_store/test/native/rdb/mock/` | 连接 Mock |
| `rdb_manager_mock.cpp/h` | `relational_store/test/native/rdb/mock/` | RDB 管理器 Mock |
| `rdb_service_mock.h` | `relational_store/test/native/rdb/mock/` | RDB 服务 Mock |
| `statement_mock.h` | `relational_store/test/native/rdb/mock/` | Statement Mock |
| `dataobs_mgr_client_mock.cpp/h` | `relational_store/test/native/rdb/mock/` | 数据观察者管理 Mock |
| `mock_global_resource.cpp/h` | `relational_store/test/native/rdb/unittest/mock_obs_manage_test/` | 全局资源 Mock |
| `mock_rdb_security_manager_test.cpp` | `relational_store/test/native/rdb/unittest/mock_obs_manage_test/` | 安全管理 Mock |
| `mock_shared_block_test.cpp` | `relational_store/test/native/rdb/unittest/sqlite_statement_test/` | SharedBlock Mock |
| `security_manager_test_helper.cpp` | `test/relational_store/rdb/` | 安全管理测试辅助（本地） |

### 5.2 CloudData Mock

| 文件 | 路径 | 用途 |
|---|---|---|
| `system_ability_manager_mock.cpp/h` | `relational_store/test/native/clouddata/unittest/mock/` | 系统能力管理器 Mock |

### 5.3 Mock 仓库级辅助

| 文件 | 路径 | 用途 |
|---|---|---|
| `mock_sys_ability.cpp` | `mock/src/` | 进程内 SA 注册表（替代 DLL 符号解析） |
| `rdb_test_main.cpp` | `test/relational_store/rdb_service_adapter/` | ServiceAdapter 自定义 test main |
| `platform_unistd.h` | `mock/include/` | POSIX 兼容层（force-include） |
| `preinclude_any.h` | `mock/include/` | 预包含 `<any>`（解决 `#define private public` 冲突） |

### 5.4 公共测试文件

| 文件 | 路径 | 用途 |
|---|---|---|
| `common.cpp/h` | `relational_store/test/native/rdb/unittest/` | Native 测试公共工具 |
| `rdb_test_common.cpp/h` | `relational_store/test/interface/` | Interface 测试公共工具 |
| `common.h` | `relational_store/test/ndk/unittest/` | NDK 测试公共工具 |
| `test_main.cpp` | `test/` | 通用 test main |
| `load_service.cpp` | `test/service/` | 服务加载入口 |
| `run_all_rdb_tests.cpp` | `test/` | 全量 RDB 测试聚合入口 |
| `run_test.sh` | `bin/` | 测试运行包装脚本 |

---

## 6. Fuzz 测试

### 6.1 Native RDB Fuzz（25 个）

| Fuzzer | 测试目标 |
|---|---|
| `abspredicates_fuzzer` | AbsPredicates |
| `absrdbpredicates_fuzzer` | AbsRdbPredicates |
| `absresultset_fuzzer` | AbsResultSet |
| `abssharedresultset_fuzzer` | AbsSharedResultSet |
| `biginteger_fuzzer` | BigInteger |
| `cacheresultset_fuzzer` | CacheResultSet |
| `clouddata_fuzzer` | CloudData |
| `cloudquery_fuzzer` | CloudQuery |
| `cloudshare_fuzzer` | CloudShare |
| `connection_fuzzer` | Connection |
| `rdbattach_fuzzer` | RdbAttach |
| `rdbbigint_fuzzer` | RdbBigInt |
| `rdbcallbackicu_fuzzer` | RdbCallbackIcu |
| `rdbcorrupt_fuzzer` | RdbCorrupt |
| `rdbdelete_fuzzer` | RdbDelete |
| `rdbdistributed_fuzzer` | RdbDistributed |
| `rdbdoublewrite_fuzzer` | RdbDoubleWrite |
| `rdbhelper_fuzzer` | RdbHelper |
| `rdbimpl_fuzzer` | RdbImpl |
| `rdbpredicates_fuzzer` | RdbPredicates |
| `rdbrdutils_fuzzer` | RdbRdUtils |
| `rdbrekeyvector_fuzzer` | RdbRekeyVector |
| `rdbsqlutils_fuzzer` | RdbSqlUtils |
| `rdbstore_fuzzer` | RdbStore |
| `rdstatement_fuzzer` | RdStatement |
| `returning_fuzzer` | Returning |
| `sharedblock_fuzzer` | SharedBlock |
| `storeconfig_fuzzer` | StoreConfig |
| `transaction_fuzzer` | Transaction |
| `transdb_fuzzer` | TransDB |
| `valueobject_fuzzer` | ValueObject |
| `valuesbucket_fuzzer` | ValuesBucket |
| `valuesbuckets_fuzzer` | ValuesBuckets |

### 6.2 NDK Fuzz（14 个）

| Fuzzer | 测试目标 |
|---|---|
| `dataasset_fuzzer` | DataAsset |
| `datavalue_fuzzer` | DataValue |
| `ohcursor_fuzzer` | OHCursor |
| `ohdatavalue_fuzzer` | OHDataValue |
| `ohdatavalues_fuzzer` | OHDataValues |
| `ohdatavaluesbuckets_fuzzer` | OHDataValuesBuckets |
| `ohpredicates_fuzzer` | OHPredicates |
| `ohrdbcryptoparam_fuzzer` | OHRdbCryptoParam |
| `ohrdbtransaction_fuzzer` | OHRdbTransaction |
| `ohvalueobject_fuzzer` | OHValueObject |
| `relationalstore_fuzzer` | RelationalStore |
| `relationalstorecapi_fuzzer` | RelationalStore C API |
| `valuebucket_fuzzer` | ValueBucket |

> Fuzz 测试目前未纳入 CMake 构建（GN 中有 `fuzztest` 模板，CMake 未转换）。如需运行 Fuzz 测试，需手动编译或在 OpenHarmony 真机环境执行。

---

## 7. 构建与运行

### 7.1 构建单个测试

```bash
# 构建指定测试二进制
./ninja.exe -C cmake-build-debug -j16 NativeRdbTest
./ninja.exe -C cmake-build-debug -j16 RdbInterfaceTest
./ninja.exe -C cmake-build-debug -j16 NativeRdbNdkTest
```

### 7.2 运行单个测试

```bash
# 运行完整测试二进制
./cmake-build-debug/bin/NativeRdbTest.exe

# 运行指定用例（GTest filter）
./cmake-build-debug/bin/NativeRdbTest.exe --gtest_filter="RdbStoreImplTest.*"

# 运行指定单个用例
./cmake-build-debug/bin/NativeRdbTest.exe --gtest_filter="RdbStoreImplTest.Rdb_BatchInsertTest_001"
```

### 7.3 通过 ctest 运行

```bash
# 运行所有 RDB 标签的测试
ctest --output-on-failure -L RDB -j8

# 运行指定测试
ctest --output-on-failure -R NativeRdbTest -j1

# 运行 Interface 层测试
ctest --output-on-failure -R RdbInterfaceTest -j1
```

### 7.4 测试标签

| 标签 | 覆盖范围 |
|---|---|
| `RDB` | 所有 RDB 测试 |
| `INTERFACE` | RdbInterfaceTest |
| `NDK` | NativeRdbNdkTest |
| `SERVICE_ADAPTER` | RdbManagerImplTest, ResultSetProxyTest, RdbTypesUtilTest, RdbServiceProxyTest |
| `MANAGER_IMPL` | RdbManagerImplTest |
| `RESULT_SET_PROXY` | ResultSetProxyTest |
| `TYPES_UTIL` | RdbTypesUtilTest |
| `SERVICE_PROXY` | RdbServiceProxyTest |

### 7.5 超时设置

| 测试二进制 | 超时（秒） |
|---|---|
| NativeRdbTest | 600 |
| RdbInterfaceTest | 1800 |
| NativeRdbNdkTest | 600 |
| ServiceAdapter 系列 | 300 |
| 其他 | 300 |

---

## 8. 已知问题与注意事项

### 8.1 符号冲突

| 问题 | 影响目标 | 解决方式 |
|---|---|---|
| `ExecuteTestOpenRdCallback::OnCreate/OnUpgrade` 重复定义 | RdbInterfaceTest | `--allow-multiple-definition`（两个上游测试文件定义相同类，ELF 可处理，PE/COFF 报错） |
| OBJECT 库与共享库符号重复 | NativeRdbTest, ServiceAdapter | `--allow-multiple-definition`（.o 文件覆盖共享库符号） |
| `TaskExecutor` 命名空间冲突 | 所有 RDB 测试 | `include_directories(BEFORE)` 确保 relational_store 头文件优先于 kv_store |

### 8.2 SA 依赖

部分测试依赖系统能力（SA）注册表。在 mock 环境中，`mock_sys_ability.cpp` 提供进程内 SA 注册表，替代 DLL 符号解析。以下测试**必须**包含 `mock_sys_ability.cpp`：

- RdbInterfaceTest
- NativeRdbNdkTest
- RdbManagerImplTest
- RdbServiceProxyTest

### 8.3 编译选项约束

| 测试目标 | 特殊编译选项 | 原因 |
|---|---|---|
| 所有 RDB 测试 | `-fno-access-control` | 访问私有成员 |
| 所有 RDB 测试 | `-include platform_unistd.h` | POSIX 兼容 |
| 所有 RDB 测试 | `-frtti` | RTTI 支持 |
| RdbTypesUtilTest | `-faccess-control`（覆盖全局 `-fno-access-control`） | 测试源码使用 `#define private public`，与全局 `-fno-access-control` 冲突 |
| RdbTypesUtilTest | `-include preinclude_any.h` | 预包含 `<any>` 防止 GCC 13 "redeclared with different access" 错误 |

### 8.4 测试数据目录

上游测试使用 `/data/test/`（设备路径），mock 环境改用项目内可写目录：

```cmake
set(RDB_MOCK_TEST_DIR ${CMAKE_SOURCE_DIR}/data/test)
```

测试运行时自动创建所需目录，无需手动准备。

### 8.5 测试宏说明

本仓库测试使用 OpenHarmony 测试框架的 `HWTEST_F` / `HWTEST` / `HWTEST_P` 宏，而非标准 GTest 的 `TEST_F` / `TEST` / `TEST_P`。差异：

| OpenHarmony 宏 | GTest 等价物 | 额外参数 |
|---|---|---|
| `HWTEST_F(Fixture, Name, TestSize.LevelN)` | `TEST_F(Fixture, Name)` | `TestSize.Level0`~`Level4`（执行优先级） |
| `HWTEST(Name, TestSize.LevelN)` | `TEST(Name)` | 同上 |
| `HWTEST_P(Fixture, Name)` | `TEST_P(Fixture, Name)` | 无 |

`TestSize.LevelN` 控制用例执行优先级：
- `Level0`：最高优先级，核心功能验证
- `Level1`：高优先级
- `Level2`：常规功能
- `Level3`：边界场景
- `Level4`：低频场景

---

## 9. 测试用例开发指南

### 9.1 新增用例

1. **确定测试层**：根据被测代码位置选择测试层（Native / Interface / NDK）
2. **选择或创建 Fixture**：优先复用已有 Fixture，仅在测试场景显著不同时新建
3. **编写用例**：使用 `HWTEST_F` 宏，命名格式 `功能描述_序号`（如 `Rdb_BatchInsertTest_001`）
4. **更新 CMakeLists**：如新增测试源文件，在对应 `.cmake` 文件的 source list 中添加
5. **验证**：构建并运行测试

### 9.2 用例命名规范

```
HWTEST_F(FixtureName, Module_Function_Description_001, TestSize.Level1)
```

- `Module`：模块缩写（如 `Rdb`、`Rd`）
- `Function`：功能名（如 `BatchInsert`、`Query`）
- `Description`：场景描述（可选）
- `序号`：从 `001` 开始递增

### 9.3 常用测试工具

| 工具/辅助 | 路径 | 用途 |
|---|---|---|
| `RdbStoreImplTest` | native/rdb/unittest/rdb_store_impl_test.cpp | RDB 核心功能测试基类 |
| `OpenCallback` 子类 | 各测试文件 | RDB 打开回调（建表、升级） |
| `common.cpp/h` | native/rdb/unittest/ | 测试公共工具（路径、清理等） |
| `rdb_test_common.cpp/h` | interface/ | Interface 层公共工具 |

---

## 10. 参考文档

| 文档 | 路径 | 说明 |
|---|---|---|
| [测试运行指南](./agents-test-guide.md) | docs/ | 测试环境设置、运行命令、Mock 系统 |
| [编译修复流程](./build_and_fix_workflow.md) | docs/ | 编译失败分类与修复模式 |
| [GN 到 CMake 转换](./agents-build-and-fix.md#gn-到-cmake-转换原则) | docs/ | GN 到 CMake 转换原则 |
| [relational_store AGENTS.md](../relational_store/AGENTS.md) | 模块根 | 模块级 Agent 指南 |
| [relational_store 代码规范](../relational_store/docs/code_standards.md) | 模块 docs/ | R1~R10 编码规范 |
| [RDB Native 架构](../relational_store/docs/rdb_native.md) | 模块 docs/ | 核心类关系、目录结构、SQLite 分层 |
| [错误码分层](../relational_store/docs/error_code_layers.md) | 模块 docs/ | 错误码定义与使用 |
| [动态加载](../relational_store/docs/dynamic_loading.md) | 模块 docs/ | dlopen/dlsym 动态加载 |
| [sync.ps1 文档](../bin/update/README.md) | bin/update/ | 同步工具完整文档 |
