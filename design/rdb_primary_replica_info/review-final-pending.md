# 主备库信息接口整改任务单

日期：2026-10-08  
用途：供实现 Agent 按项整改 relational_store 主备库信息接口，并回填验证证据。

## 当前结论与约束

当前工作树尚有规格冲突、表名处理缺陷和测试覆盖缺口，不能按“36 个过滤用例通过”认定全部验收。最近一次验证记录为 NativeRdbTest 增量构建成功，PrimaryReplicaInfoTest.* 36/36 通过；该结果没有覆盖下列未测分支。

已确认的需求边界：

- 仅 Native C++ 内部接口；时间单位为 Unix 毫秒；精确行数；允许并行写入采样。
- 采用方案 A：复用现有主备连接；无备库句柄时不在诊断路径打开备库。主备时间归纳依约定计算。
- 用户已撤销“不删除损坏备库”规则。连接归还期间的存量 TryCheckPoint 错误处理语义继续适用，不新增诊断标志或额外清理保证。
- 不主动触发恢复或重建；这项边界不等同于禁止存量 checkpoint 错误处理。

## 整改项

### FIX-01 [P1] 统一无备库句柄和备库文件缺失契约

**证据：** 05-spec.md 的 AC-4.2/AC-4.4/EX-01/EX-02 与 BR-05 互相冲突；07-execution-plan.md 的 AC-4.2～4.5 验证描述也互相矛盾。实现入口为 sqlite_connection.cpp 的 CollectInitialFileInfo、TryReplayBinlog、CheckpointDatabases、CollectVersionsAndTables、RefreshSizesAfterCheckpoint。

**当前不一致：** 一处写备库字段全零，一处要求 DB/WAL 都 stat，BR-05 和实现则是无句柄时按配置路径 stat DB、WAL 标为 E_NOT_SUPPORT，并跳过依赖句柄的操作。执行计划写文件不存在返回 E_DB_NOT_EXIST；异常表又写整体 E_OK 和零值。按现行部分结果约定，应保留主库结果，并在备库对应字段显式表达失败/跳过。

**修复动作：**

1. 以当前方案 A 为基线，统一 AC、BR、EX、类型注释和设计/执行计划：无句柄时不打开备库；DB 按配置路径 stat；WAL、回放、备库 checkpoint、备库计数均为跳过状态。
2. 明确文件缺失状态。建议 replicaInfo.dbInfo.errCode = E_DB_NOT_EXIST、保留其余可用字段，接口整体返回 E_OK；若整体返回码另有已确认定义，必须在全部文档和实现中一致表达。
3. 明确请求了 tableName 但没有备库句柄时，replicaInfo.tables 是否包含该表以及如何表达 E_NOT_SUPPORT，避免“未请求”和“跳过”混淆。
4. 回填 07 中每个 AC 的真实测试名和验证状态；未运行或未覆盖的项不得标 Pass。

**验收：** 文档对“无句柄且文件存在/不存在”给出唯一预期；实现和专用测试逐字段符合预期；不打开或创建备库。

### FIX-02 [P1] 普通表校验必须排除 SQLite 系统表

**证据：** sqlite_connection.cpp 的 CountTable 先按 sqlite_master 中 type='table' 检查，再执行 COUNT(*)。该条件会将 sqlite_sequence 等 SQLite 内部表视为普通表；当前 ViewRejection_001 只覆盖视图。

**修复动作：**

1. 明确普通表的判定规则，排除 SQLite 内部对象（至少 sqlite_ 前缀系统表），并区分用户表、视图、索引和系统对象。
2. 增加系统表拒绝用例，例如创建 AUTOINCREMENT 表后查询 sqlite_sequence；断言该库 TableInfo.errCode != E_OK、count 不作为有效结果，另一库查询独立执行。
3. 修正文档中“视图/系统表均已验证”的完成状态；现有测试未覆盖系统表时标为待验证。

**验收：** 普通用户表（含 0 行）可以精确计数；视图和 SQLite 系统表都不能作为普通表成功返回。

### FIX-03 [P1] 支持规格承诺的合法特殊标识符并消除 SQL 拼接风险

**证据：** rdb_sql_utils.cpp 的 IsValidTableName 仅接受以英文字母开头的 ASCII 字母/数字/下划线及可选 schema.table；05-spec.md AC-3.4 同时承诺特殊标识符正确引用，并注明当前校验器拒绝中文、空格、引号和下划线开头。CountTable 当前将 namePart 直接拼入单引号 SQL 条件，再以双引号包裹表名。

**修复动作：**

1. 为诊断接口明确输入语法，支持 AC-3.4 要求的合法 SQLite 标识符；不要通过放宽全局校验后继续直接拼接 SQL。
2. 安全拆分 schema/table；SQL 标识符双引号内的双引号必须转义；sqlite_master 名称条件使用参数绑定，或对 SQL 字符串字面量进行正确转义。
3. 保留对非法/注入输入的拒绝行为。增加含空格、中文、双引号、下划线开头、schema-qualified 名称及注入字符串用例。
4. 主备分别执行计数；一侧缺表或失败不能伪造另一侧结果。

**验收：** 合法特殊名称计数正确；非法输入不执行额外 SQL；主备结果逐库独立。若实际接口约束无法支持 AC-3.4，先更新需求基线，不能只把当前限制写成已满足。

### FIX-04 [P1] 用真实无句柄状态验证备库文件采集

**证据：** primary_replica_info_test.cpp 的 ReplicaDbStatFromConfig_001 只调用 Fixture 的 MAIN_REPLICA store，没有关闭或注入移除 slaveConnection_；用例没有证明名称所述的“无连接”分支。

**修复动作：**

1. 通过可控测试夹具构造 slaveConnection_ 为空的连接状态，不要用“文件存在”推断句柄不存在。
2. 分别覆盖备库文件存在和文件缺失；检查 dbInfo、walInfo、checkpointErr、replayErr、请求表结果和归纳时间。
3. 验证诊断未创建文件，并验证整体返回值及 E_DB_NOT_EXIST 状态符合 FIX-01 的统一契约。
4. 更新用例说明和 AC 映射；未实际进入分支不得标 Pass。

**验收：** 测试能证明进入 no-slave-connection 路径，并对存在/缺失两个结果作唯一断言。

### FIX-05 [P2] MemoryDb 和 VectorDb 用例必须执行不支持分支

**证据：** primary_replica_info_test.cpp 中 MemoryDb_001 和 VectorDb_001 都使用 Fixture 提供的普通 MAIN_REPLICA store，并期待 E_OK；这些用例没有验证 RdbStoreImpl 对 isMemoryRdb_ 或 DB_VECTOR 的 E_NOT_SUPPORT 前置检查。

**修复动作：** 用可运行的测试构造或隔离单元夹具真正设置对应类型并调用接口，断言 E_NOT_SUPPORT 和空结果；如果本地 mock 环境无法创建该类型，明确记录为未验证，并提供目标环境验证任务，不把普通库正向测试计为 AC-5.4 通过。

**验收：** 每个不支持分支均有实际负向断言，或执行计划明确标记为未验证并记录后续环境与负责人。

### FIX-06 [P2] 并发写入用同步原语，不用固定延迟

**证据：** primary_replica_info_test.cpp 的 ConcurrentWrite_001 用 std::this_thread::sleep_for 等待 started；relational_store/docs/test_case_spec.md 明确禁止固定 sleep。started 在 writer 执行任何写入前置位，因此不能证明写操作与诊断采样重叠。

**修复动作：** 使用 condition_variable、barrier 或测试钩子建立确定的交叠点；查询开始后让写线程在采样窗口完成至少一次受控写入，再释放双方。确保断言失败时仍 join 线程并清理事务。断言查询结果和写入进展，不要求所有字段来自同一时点。

**验收：** 测试不含 sleep；同步关系能证明采样期间有写入进展；测试重复运行不依赖线程调度运气。

### FIX-07 [P2] 时间用例必须证明 checkpoint 前后 mtime 不同

**证据：** TimeNotOverwrittenByCheckpoint_001 已比较毫秒精度，但只在调用前 stat WAL，再比较接口结果；没有证明本次 checkpoint 改变了 WAL mtime。若 checkpoint 未改变时间，即使实现采集顺序错误，用例仍可能通过。

**修复动作：** 为测试建立可控的前后时间差（例如测试专用 checkpoint hook 或确定性的文件时间/维护步骤），断言 checkpoint 后 mtime 与采样前不同，且返回值仍等于采样前时间。不能靠重复运行次数代替触发条件。

**验收：** 用例每次运行都断言前后时间确实不同，并证明返回的是回放/checkpoint 前采样值。

### FIX-08 [P2] 补齐部分失败状态的故障验证并修正执行计划状态

**证据：** 当前 36 个用例没有覆盖 binlog 回放实际失败、stat 失败/部分扫描、主备 checkpoint BUSY/CORRUPT。CheckpointStatus_001 的成功状态不能证明错误映射；07-execution-plan.md 多处把未注入、未运行或名称与实际前置条件不符的场景记为 Pass。

**修复动作：**

1. 为可控路径增加故障注入，分别验证回放、stat、主库 checkpoint、备库 checkpoint 的错误码和逐项保留。
2. 验证这些局部失败时整体仍返回可用的主备信息；对无法在 mock 环境注入的内核路径，保留明确的未验证状态及目标环境验证步骤。
3. 清理 05/06/07 中与实现不符的预期、错误码、测试名和“Pass”标记；统一引用本报告定义的行为。
4. 记录实际构建命令、测试过滤器、通过/失败/跳过数及未执行验证，不将静态代码检查写成运行通过。

**验收：** 每个宣称 Pass 的 AC 都有真实测试或运行证据；故障分支有唯一状态断言；环境限制明确记录，不伪报通过。

## 实施顺序

1. 先完成 FIX-01，确定无句柄、文件缺失和部分结果字段契约。
2. 完成 FIX-02/FIX-03 的普通表判定与安全标识符处理。
3. 增加 FIX-04～FIX-08 的测试与故障验证。
4. 同步更新 05-spec.md、06-design.md、07-execution-plan.md 及测试映射表。
5. 构建 NativeRdbTest，运行主备信息过滤用例；再运行受影响的连接池和 checkpoint 回归。正式 GN/目标设备检查单独记录。

## 本轮验证记录

最近一次可核对的执行结果：NativeRdbTest 增量构建成功；PrimaryReplicaInfoTest.* 为 36 passed、0 failed、0 skipped。该结果不覆盖本任务列出的 no-handle、SQLite 系统表、特殊合法表名、实际并发重叠和故障注入。编写本任务单时未重跑实现测试。

