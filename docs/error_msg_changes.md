# 14800000 / 14800021 msg 变更清单

##变化规则

    ## #14800021（SqlLog 追加）

        触发条件：native errCode ∈ { E_SQLITE_ERROR, E_SQLITE_SCHEMA, E_SQLITE_INTERRUPT }

    | 项目 | 变更前 | 变更后 | | -- -- -- | -- -- -- -- | -- -- -- -- | |
    E_SQLITE_ERROR | `"SQLite: Generic error. Possible causes: Insert failed or the updated data does not exist."` | `"SQLite: Generic error. Possible causes: Insert failed or the updated data does not exist. {sqliteDetail}"` |
    | E_SQLITE_SCHEMA | `"Inner error."` → 14800021 | `"Inner error. Database schema has changed. {sqliteDetail}"` | |
    E_SQLITE_INTERRUPT | `"Inner error."` → 14800021 | `"Inner error. Operation interrupted. {sqliteDetail}"` |

    > SqlLog 内容为 `SqlLog::GetLastErrMsg(dbPath)` 一次性消费；`
{
    sqliteDetail
}
` = sqlite3_errmsg 原文。

    ## #14800000（GetNativeErrMsg 合并 GetErrorString）

        触发条件：native errCode 未映射到 JS 标准错误码（如 E_ERROR、E_SQLITE_SCHEMA 等）

    | 项目 | 变更前 | 变更后 | | -- -- -- | -- -- -- -- | -- -- -- -- | |
    NATIVE_ERR_MSG_MAP 有条目 | `"Inner error."` | `"Inner error. {errMsg}"` | |
    NATIVE_ERR_MSG_MAP 无条目 | `"Inner error."` | `"Inner error."`（不变） |

    > 括号包裹去掉；errCode ∈ NATIVE_ERR_MSG_MAP 时追加标准描述（如 "Database schema has changed."、
                                                                    "Operation interrupted."），而非括号内的数字。

        -- -

        ##并发安全设计

        ## #1. 旧方案问题

            旧方案中 `RdbStoreImpl::lastErrMsg_`、`SqliteConnection::lastErrMsg_` 等是 **成员变量 **，存在以下并发问题：

        1. **跨线程污染 **：线程 A 执行 Insert
            设 `lastErrMsg_ = "table not found"`，线程 B 随后执行 Delete 设 `lastErrMsg_ =
        "db locked"`，线程 A 在 JS 回调中读到线程 B 的 errMsg → 14800021 msg 不匹配实际操作。 2. * *async worker 竞争 *
            *：NAPI async 模式下 exec lambda 在 worker 线程执行，JS 回调在 main 线程执行。exec lambda
                中 `rdbStore` 已 move 到 worker 线程，worker 执行完毕后 `rdbStore` 的 `lastErrMsg_` 可能被下一个 async
                    操作覆盖，JS 回调取到的 errMsg 已不是本次操作的。 3. *
            *Statement 生命周期 *
            *：`SqliteStatement::conn_` 是 `shared_ptr<
                Connection>`，旧代码在 `CreateStatementInner` 中先 `Prepare()` 再赋值 `conn_`。如果 `Prepare()` 失败，`conn_` 为
                 nullptr，`TryNotifyErrorLog` 中的 `conn_->SetLastErrorMsg()` 解引用空指针。

             ## #2. ErrMsgStore：线程隔离存储

             ####设计思路

                 将 `lastErrMsg_` 成员变量替换为全局单例 `ErrMsgStore`，以 `(
                     void *obj, thread_id)` 为复合键，天然实现线程隔离：

        - **同一对象 + 同一线程 ** → 同一个 errMsg slot - **同一对象 +
        不同线程 ** → 各线程各自的 errMsg slot，互不干扰 -
            **不同对象 ** → 完全独立的 errMsg slot

        ####关键数据结构

``` ErrMsgStore（全局单例，header -
        only）
├── Key = { void * obj, std::thread::id tid }
├── KeyHash = hash(obj) ^ (hash(tid) << 1)
├── map_ = unordered_map<Key, string, KeyHash>
└── mutex_ = std::mutex（所有操作加锁）
```

              ####API

              | 方法 | 语义 | | -- -- -- | -- -- -- | | `Get(obj)` | 读取 `(obj, this_thread)` 对应的 errMsg |
              | `Set(obj, msg)` | 写入 `(obj, this_thread)` 对应的 errMsg | | `Clear(obj)` |
              清除 `(obj, this_thread)` 对应的 errMsg | | `RemoveAll(obj)` |
              清除 `obj` 所有线程的 errMsg（析构时调用） |

              ####使用位置

              | 类 | GetLastErrorMsg | SetLastErrorMsg / Set | Clear / RemoveAll | | -- -- | -- -- -- -- -- -- -- -- |
              -- -- -- -- -- -- -- -- -- -- - | -- -- -- -- -- -- -- -- -- - |
              | `SqliteConnection` | `ErrMsgStore::Get(this)` | `SetLastErrorMsg → ErrMsgStore::Set(
                  this, msg)` | `ClearLastErrorMsg → Clear(this)`；析构 `RemoveAll(this)` |
              | `RdbStoreImpl` |
              先查 `ErrMsgStore::Get(
                  this)`，空则降级到 `ConnectionPool::GetLastErrorMsg()` | `CaptureLastError → ErrMsgStore::Set(this,
                  msg)` |
              析构 `RemoveAll(this)` |
              | `StepResultSet` | `ErrMsgStore::Get(this)` | `Set → ErrMsgStore::Set(this, msg)` |
              析构 `RemoveAll(this)` |

              ####线程隔离效果

                      -
                      线程 A Insert → `ErrMsgStore::Set(connA, "table not found")` 在 `(connA_ptr, thread_A_id)` slot -
                      线程 B Delete → `ErrMsgStore::Set(connA, "db locked")` 在 `(connA_ptr, thread_B_id)` slot -
                      线程 A JS回调 → `ErrMsgStore::Get(connA)` 读 `(connA_ptr, thread_A_id)` → "table not found" ✓ -
                      线程 B JS回调 → `ErrMsgStore::Get(connA)` 读 `(connA_ptr, thread_B_id)` → "db locked" ✓

                  > 测试 022 / 023（ConcurrentInsertSync /
                        Async ThreadIsolation）验证了此隔离效果。

                        ## #3. NAPI capturedErrMsg_：move 前捕获

                        ####问题

                            NAPI async 模式中，exec lambda 通常写为：

```cpp auto [errCode, count] = rdbStore->Insert(table, valuesBucket);
context->lastErrMsg_ = rdbStore->GetLastErrorMsg(); // ← 在 worker 线程
```

    但 `rdbStore` 是 `shared_ptr`，worker 线程执行完毕后回到 main 线程时，`rdbStore` 可能已被下一个
        async 操作使用，`GetLastErrorMsg()` 返回的 errMsg 可能已不是本次操作的结果。

    ####修复

    在 exec lambda 中将 `GetLastErrorMsg()` 的结果捕获到 `context->capturedErrMsg_`（局部 string），JS
    回调中使用 `capturedErrMsg_` 而非再次调用 `GetLastErrorMsg()`：

```cpp
    // exec lambda（worker 线程）
    auto [errCode, count] = rdbStore->Insert(table, valuesBucket);
context->capturedErrMsg_ = rdbStore->GetLastErrorMsg();

// callback lambda（main 线程）
ThrowInnerErrorExt(errCode, context->capturedErrMsg_); // ← 用捕获值，不再调 GetLastErrorMsg()
```

    ####涉及文件

    | 文件 | 修改 | | -- -- -- | -- -- -- | | `napi_rdb_store.cpp` |
    ExecuteSql / Execute 等 10 处 async exec lambda 加 `capturedErrMsg_` | | `napi_transaction.cpp` |
    Transaction CRUD 5 处 async exec lambda 加 `capturedErrMsg_` |
    | `napi_rdb_context.h` | `RdbStoreContextBase` 加 `capturedErrMsg_` 字段 |

    ## #4. NAPI Transaction：StealTransaction 防竞态

        ####问题

            Transaction 的 async exec lambda 中，`context->transaction_` 是 `shared_ptr<Transaction>`。如果 commit /
        rollback 在 main 线程先执行，transaction 对象可能已析构，worker 线程后续操作 crash。

        ####修复

`TransactionContext::StealTransaction()` 将 `transaction_` move 到局部变量，exec lambda 持有独立引用：

```cpp auto trans = context->StealTransaction(); // move 出来，context 不再持有
auto [errCode, count] = trans->Insert(table, valuesBucket);
context->capturedErrMsg_ = trans->GetLastErrorMsg();
```

    main 线程的 commit /
    rollback 同样通过 `StealTransaction()` 获取独立引用，避免跨线程 shared_ptr 竞态。

    ## #5. ConnectionPool::GetLastErrorMsg()：降级遍历

    ####问题

`RdbStoreImpl::
        GetLastErrorMsg()` 旧代码直接返回 `lastErrMsg_`（成员变量），并发下不可靠。使用 `ErrMsgStore` 后，`ErrMsgStore::Get(
            this)` 可能返回空（当前线程未执行过任何操作）。

    ####修复

`RdbStoreImpl::GetLastErrorMsg()` 改为两级查找：

    1. 先查 `ErrMsgStore::Get(this)`（当前线程的错误信息）
    2. 若空，降级到 `ConnectionPool::GetLastErrorMsg()`（遍历所有 writer
    /
    reader 连接的 ErrMsgStore）

```cpp std::string RdbStoreImpl::GetLastErrorMsg() const
{
    auto msg = ErrMsgStore::Instance().Get(this);
    if (!msg.empty()) {
        return msg;
    }
    if (connectionPool_ != nullptr) {
        return connectionPool_->GetLastErrorMsg();
    }
    return "";
}
```

`ConnectionPool::GetLastErrorMsg()` 遍历 writers → readers，取第一个非空 errMsg：

```cpp std::string ConnectionPool::GetLastErrorMsg() const
{
    for (auto &node : writers_.nodes_) {
        if (node != nullptr && node->connect_ != nullptr) {
            auto msg = node->connect_->GetLastErrorMsg();
            if (!msg.empty())
                return msg;
        }
    }
    for (auto &node : readers_.nodes_) {
        if (node != nullptr && node->connect_ != nullptr) {
            auto msg = node->connect_->GetLastErrorMsg();
            if (!msg.empty())
                return msg;
        }
    }
    return "";
}
```

    ## #6. TransDB::GetLastErrorMsg()：委托 Connection

    Transaction 模式下只有一条 Connection（无连接池），`TransDB` override `GetLastErrorMsg()` 委托到这条 Connection：

```cpp std::string TransDB::GetLastErrorMsg() const
{
    auto connection = conn_.lock();
    if (connection != nullptr) {
        return connection->GetLastErrorMsg(); // → ErrMsgStore::Get(connection)
    }
    return "";
}
```

    > 测试 007 / 008 /
          010 等验证了 Transaction SqlLog 路径的 errMsg 传递。

          ## #7. sqlite_connection conn_ 赋值顺序修复

          ####问题

              旧 `CreateStatementInner` 中：

```cpp std::shared_ptr<SqliteStatement>
                  statement = std::make_shared<SqliteStatement>(&config_);
int errCode = statement->Prepare(db, sql); // Prepare 可能失败
statement->conn_ = conn;                   // ← 赋值在 Prepare 之后
```

    如果 `Prepare()` 成功，statement
    执行时 `TryNotifyErrorLog` 需要通过 `conn_` 调用 `SetLastErrorMsg()`。但 `Prepare()` 失败时 `conn_` 为
    nullptr，`TryNotifyErrorLog` 中的 `conn_->SetLastErrorMsg()` 会空指针 crash。

    ####修复

    将 `conn_` 赋值移到 `Prepare()` **之前 **：

```cpp std::shared_ptr<SqliteStatement> statement = std::make_shared<SqliteStatement>(&config_);
statement->conn_ = conn;                   // ← 先赋值
int errCode = statement->Prepare(db, sql); // Prepare 失败时 TryNotifyErrorLog 可安全使用 conn_
```

    ## #8. InnerError /
    InnerErrorExt 构造函数：GetNativeErrMsg fallback

    ####问题

        旧 `InnerError` 构造函数 else 分支（`GetJsErrorCode` 返回 nullopt 时）：

```cpp code_ = E_INNER_ERROR;
msg_ = "Inner error."; // ← 丢弃了 msg 参数！
```

    对于 `E_EMPTY_TABLE_NAME`（未映射到 JS 标准码），`ThrowInnerError(
        E_EMPTY_TABLE_NAME, "")` 最终 msg 为 `"Inner error."` 而非 `"Inner error. The table must be not empty string."`。

    ####根因

`ThrowInnerError` 先计算 `opMsg`，传给 `InnerError(errCode, opMsg)`。但构造函数
    else 分支用硬编码 `"Inner error."` 替代了 `msg_ =
        "Inner error." + msg`，导致 `opMsg`（含原生错误描述）被丢弃。

        ####修复

        在 else 分支中拼接 `msg`，并引入 `GetNativeErrMsg()` 静态方法在构造函数内部生成原生错误描述：

```cpp
        // InnerError 构造函数 else 分支
        code_ = E_INNER_ERROR;
std::string nativeMsg = GetNativeErrMsg(code); // switch-case 硬编码映射
msg_ = "Inner error." + (nativeMsg.empty() ? "" : " " + nativeMsg) + msg;
```

`GetNativeErrMsg()` 是 header
            - only 的 `static` 方法，编译到每个使用 `InnerError` 的 SO 中，避免跨 SO 的 `std::map` static init 问题。

        > 测试 006 / 009（TransBatchInsertSync /
                  InsertSync EmptyTableName）验证了此修复。

                  -- -

              ##1 ETS（ANI）接口

              ## #1.1 RdbStore（有 dbPath → 14800021 +
              14800000）

              以下接口传 `store->GetPath()`，SqlLog 码追加 SqlLog，未映射码追加 GetNativeErrMsg：

    | 接口 | | -- -- -- | | insert / insertSync / insertWithConflict |
    | batchInsert / batchInsertSync / batchInsertWithConflict |
    | update / updateSync / updateDataShare / updateDataShareSync | |
    delete / deleteSync / deleteDataShare / deleteDataShareSync |
    | executeSql / executeSqlWithOptionArgs / execute / executeSync | | beginTransaction / beginTransSync |
    | commit / commitSync / commitWithTxId | | rollBack / rollbackSync | | backup / backupSync / restore / restoreSync
    | | setDistributedTables（4 overload） / obtainDistributedTableName |
    | cloudSync（4 overload） / stopCloudSync / emit | | cleanDirtyData（2 overload） / cleanDeviceDirtyData |
    | remoteQuery / attach / detach | | lockRow / unlockRow / lockCloudContainer / unlockCloudContainer |
    | createTransaction / rekey / rekeyEx / setLocale | | getVersion / setVersion / getRebuilt |
    | retainDeviceData / updateDistributedInfo |

    ## #1.2 RdbStore（无 dbPath → 仅 14800000）

    以下接口不传 dbPath，仅未映射码追加 GetNativeErrMsg：

    | 接口 | | -- -- -- | | openRdbStore（构造） |
    | getModifyTime / querySharingResource（3 overload） / queryLockedRow | | sync / syncEx（设备同步） |
    | on / off（dataChange / autoSyncProgress / statistics / common / sqliteErrorOccurred / perfStat） |

    ## #1.3 Transaction

`dbPath_` 从 `store->GetPath()` 传入。变量 errCode 的 ThrowInnerError 传 dbPath_；E_ERROR 码不触发 SqlLog，仅
    14800000。

    | 接口 | 14800021 | 14800000 | | -- -- -- | -- -- -- -- -- | -- -- -- -- -- | | commit / rollback | 有 | 有 |
    | insert / batchInsert / batchInsertWithConflict | 有 | 有 | | execute | 有 | 有 |
    | update / delete | — | 仅 14800000（E_ERROR） |
    | query / querySql / queryWithoutRowCount / querySqlWithoutRowCount | — | 仅 14800000（E_ERROR） |

    ## #1.4 LiteResultSet

    | 接口 | 14800021 | 14800000 | | -- -- -- | -- -- -- -- -- | -- -- -- -- -- | | goToNextRow | 有（dbPath_） | 有 | |
    其余 getter（getColumnType / getBlob / getString / getLong / getDouble / getAsset / getAssets / getValue
        / getFloat32Array / isColumnNull / getRow / getRowsSync / getColumnNames / getCurrentRowData / getRowsDataSync）
    | — | 仅 14800000 |

    -- -

        ##2 NAPI 接口

        ## #2.1 RdbStore async（RdbStoreContextBase → 14800021 +
        14800000）

        SetError override 追加 `" " +
        SqlLog(dbPath)`；OnComplete L244 也走 override。

    | 接口 | | -- -- -- | | insert / batchInsert / batchInsertWithConflict | | update / delete / replace |
    | query / querySql / queryByStep / queryWithoutRowCount / querySqlWithoutRowCount | | executeSql / execute |
    | backup / restore | | setDistributedTables / obtainDistributedTableName | | cloudSync / stopCloudSync |
    | attach / detach | | getVersion / setVersion / rekey / rekeyEx / setLocale |
    | cleanDirtyData / lockRow / unlockRow / remoteQuery / getModifyTime |
    | querySharingResource / queryLockedRow / queryLockedRowByStep | | lockCloudContainer / unlockCloudContainer / close
    | | createTransaction | | batchInsertWithReturning / updateWithReturning / deleteWithReturning |

    ## #2.2 RdbStore sync（opMsg `" " + SqlLog` → 14800021 +
        14800000）

        15 处 sync 方法 `opMsg =
    " " + SqlLog::GetLastErrMsg(dbPath)`。

    | 接口 | | -- -- -- | | beginTransaction / rollBack / commit |
    | subscribe / unsubscribe（statistics / log / sharedObserver / syncObserver） |
    | subscribeObserver / unsubscribeObserver / notify | | registerAutoSyncCallback / unregisterAutoSyncCallback |

    ## #2.3 RdbStore（EnhancedContext → 仅 14800000，丢失原始 msg）

    SetError 将所有 error 替换为 `InnerErrorExt(nativeCode)`，丢失 SqlLog 和自定义 msg。存量 bug。

    | 接口 | | -- -- -- | | sync / syncEx（设备同步） |
    | retainDeviceData / updateDistributedInfo / cleanDeviceDirtyData |

    ## #2.4 RdbStore observer（sync opMsg `" " + SqlLog`）

    | 接口 | | -- -- -- |
    | on / off（6 种 observer：statistics / log / sharedObserver / syncObserver / observer / autoSyncCallback） |

    ## #2.5 Transaction（TransactionContext → 14800021 + 14800000）

        继承 RdbStoreContextBase，同 RdbStore async。`capturedErrMsg_` 在 exec lambda 中捕获，避免 async worker 竞态。

    | 接口 | | -- -- -- | | commit / rollback | | insert / batchInsert / batchInsertWithConflict | | update / delete |
    | query / querySql / queryWithoutRowCount / querySqlWithoutRowCount | | execute |
    | batchInsertWithReturning / updateWithReturning / deleteWithReturning |

    ## #2.6 LiteResultSet

    | 接口 | 14800021 | 14800000 | | -- -- -- | -- -- -- -- -- | -- -- -- -- -- |
    | goToNextRow（sync opMsg `" " + SqlLog`） | 有 | 有 | | 其余 getter（InnerErrorExt(errCode) 不追加）
    | — | 仅 14800000（无 SqlLog） |

    -- -

       ##3 不变错误码

    | 错误码 | msg | 变化 | | -- -- -- - | -- -- - | -- -- -- | | 401 | "Invalid args." / "Parameter error..." | 不变 |
    | 14800001 | "Invalid args." | 不变 | | 14800010 | "Failed to open or delete..." | 不变 | | 14800012 |
    "ResultSet is empty or pointer index is out of bounds." | 不变 | | 14800013 |
    "Resultset is empty or column index is out of bounds." | 不变 | | 14800014 |
    "The RdbStore or ResultSet is already closed." | 不变 | | 801 | "Capability not support." | 不变 | | 202 |
    "Permission verification failed..." | 不变 |
