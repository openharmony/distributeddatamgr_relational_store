# U07 — DDMS / RDB 阻塞依赖 OH 契约

更新时间：2026-09-29  
状态：U07 的候选源码与行为契约研究完成；产品实际消费的 platform dependency revisions 未锁定，必须继续作为显式未知项。

## 结论与边界

当前 RDB/DDMS 链路中已确认需要处理的边界是：SAFWK/SAMgr 服务发布与发现、IPC/parcel 跨进程调用、IPC caller identity/AccessToken 校验，以及 DDMS 启动时的 DeviceManager 本地设备身份。BMS 仅在 HAP token 路径被触达时是阻塞依赖；SoftBus、账户/事件订阅、HUKS/加密和文件系统语义要等具体调用栈进入相应功能后再立 GAP，不能因它们出现在 `bundle.json` 就认定当前 RDB 首错由它们造成。

`U08` 的命名管道探针只证明独立进程间可收发简单帧；它不等价于 OH IPC 的 `MessageParcel`、RemoteObject、caller identity、同步/异步、死亡通知或 FD 传输。后续跨进程 RDB 功能必须逐项实现这些实际触达的语义，不能直接透传对象地址或固定返回成功。

## 版本基线与证据限制

`bin/update/.sync_state.json` 最近同步时间为 `2026-09-22`，仅锁定 8 个业务仓库；其中 `datamgr_service=b06ed9eb1a0d081ffdb624b9a49b08cc239fe700`、`relational_store=1535ba42c4985cb16af81195e95efab26fb56adc`、`kv_store=6fd3768d61eea536453598a6f66df3065f173300`。`bundle.json` 声明 platform 依赖组件名，但没有相应 commit SHA；当前工作区也没有产品 `manifest.xml`/repo lock 可把它们绑定到实际构建版本。`mock/innerkits/*/sdk_info.json` 是 SDK 目标/产物描述，不是上游源码版本锁。

以下 platform SHA 是本轮于 2026-09-29 从官方仓库固定下来的源码候选，用于可复查地定义候选契约；**它们不是本项目产品实际消费版本的证明**。

| 仓库 | 固定候选 SHA | 本轮核对的源码/符号 | 产品消费 SHA |
|---|---|---|---|
| `systemabilitymgr_safwk` | `5f518f8ef2bad5d7efdb295cce5c5ccc02805fda` | `SystemAbility::Publish`；见 [既有 SAFWK/SAMgr 契约](u09-gap-001-safwk-samgr-contract.md) | 未锁定 |
| `systemabilitymgr_samgr` | `878d611aa0918153be131063ce19f7c183f32ec4` | `SystemAbilityManager::AddSystemAbility`、`BaseSystemAbilityManager::AddSystemAbility`；见[既有契约](u09-gap-001-safwk-samgr-contract.md) | 未锁定 |
| `communication_ipc` | `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` | [`ipc_skeleton.cpp`](https://github.com/openharmony/communication_ipc/blob/bbb92dbb2f52aca54ab268307c9476ac1802f3ff/ipc/native/src/core/framework/source/ipc_skeleton.cpp)：`GetCallingPid/Uid/TokenID`、`GetSelfTokenID`、identity reset/set；`message_parcel.cpp`：RemoteObject/FD marshal | 未锁定 |
| `security_access_token` | `71bbdc92a72405a63826964951cd46b93e2818a9` | [`accesstoken_kit.cpp`](https://github.com/openharmony/security_access_token/blob/71bbdc92a72405a63826964951cd46b93e2818a9/interfaces/innerkits/accesstoken/src/accesstoken_kit.cpp)：`GetTokenTypeFlag`、`GetHapTokenInfo`、`VerifyAccessToken` | 未锁定 |
| `bundlemanager_bundle_framework` | `2fa234a99a17eabd5d5e1f60a2e004f464a27d71` | [`BundleMgrHostImpl::GetAppIdByBundleName`](https://github.com/openharmony/bundlemanager_bundle_framework/blob/2fa234a99a17eabd5d5e1f60a2e004f464a27d71/services/bundlemgr/src/bundle_mgr_host_impl.cpp#L4199-L4225) | 未锁定 |
| `distributedhardware_device_manager` | `ab507bb64f11d5b85ec545390279d2efa0d49d11` | [`DeviceManagerImpl::InitDeviceManager/GetLocalDeviceInfo`](https://github.com/openharmony/distributedhardware_device_manager/blob/ab507bb64f11d5b85ec545390279d2efa0d49d11/interfaces/inner_kits/native_cpp/src/device_manager_impl.cpp#L140-L177) | 未锁定 |

SAFWK/SAMgr 的固定候选行为和本地测试已在 [U09-GAP-001 契约](u09-gap-001-safwk-samgr-contract.md)中逐项记录。其 M3–M5 本地验收不关闭“产品消费 SHA 未锁定”这一 M1 风险。

工作区调用点采用当前 checkout 作为运行证据，而非伪装成干净上游副本：`kvstore_data_service.cpp` 和 `checker_manager.cpp` 存在既有本地差异；新增的 `rdb_manager_impl.cpp` 当前为 untracked。`.sync_state.json` 只用于说明同步基线，不代表这些文件在工作区未修改。下表的业务调用关系以当前文件为准；未对照产品 manifest 的依赖版本一律标为“候选”。

## 行为契约矩阵

| 依赖 / 触达级别 | 真实调用边界与候选 OH 契约 | 当前本地实现与缺口 | 宿主可接受简化 / 必须验证 |
|---|---|---|---|
| **SAFWK / SAMgr — 已确认，跨进程服务必要条件** | DDMS `StartService()` 经 `SystemAbility::Publish(this)` 发布 SA 1301；客户端从 SAMgr 按 SA ID 发现服务。候选 SAFWK 在空 remote、SAMgr 不可用或 AddSystemAbility 失败时不得报告 Publish 成功；候选 SAMgr 对有效重复 ID 以新 remote 替换旧对象，不能假定重复必拒绝。 | 本地 M4 已校正重复注册与 Publish 返回语义，`u09-publish-m4-007` 严格通过 4/4；完整契约和 SHA 限制见上述 U09 文档。独立 DDMS 服务态发现仍未验收。 | Windows 可用独立 discovery endpoint 替代 SAMgr，但注册、查询、下线、失败传播和重启代际必须测试。客户端未发现/服务退出必须失败，禁止退回进程内假 SA 1301。 |
| **IPC / parcel — 已确认，当前 U08 之后的主阻塞边界** | RDB 的 `GetFeatureInterface`、feature `SendRequest`、回调 RemoteObject 均跨同机进程。OH IPC 候选通过 active invoker 提供 caller PID/UID/token；当调用不是本机 IPC 时，候选 API 对 PID/UID 返回 `-1`、token 返回 `0`。`MessageParcel` 具有类型化数据、RemoteObject 和 FD marshal；`MessageOption` 区分同步/异步。候选实现入口为 `ipc_skeleton.cpp`、`ipc_object_stub.cpp`、`message_parcel.cpp`。 | `mock/src/mock_ipc.cpp` 当前 `GetCallingUid()` 恒为 1000、PID 为当前进程、token 取服务本进程 `GetSelfTokenID()`；identity reset/set、RemoteObject/FD marshal 也不是跨进程实现。U08 命名管道仅测 PING/ECHO/STOP，不测 parcel/回调。 | 可把 Binder 驱动替换成管道 RPC，但必须用结构化、带版本/长度/错误检查的协议；不能传 C++ 指针。验收要覆盖 sync/async、malformed parcel、RemoteObject/FD 实际触达项、调用失败透传、死亡/重启后陈旧句柄失效。 |
| **Caller identity + AccessToken — 已确认，RDB 权限边界** | 当前 `RdbServiceImpl::IsValidAccess` 从 `IPCSkeleton::GetCallingUid/GetCallingTokenID` 建立 `StoreInfo` 并调用 `CheckerManager::IsValid`。本仓 `SystemChecker` 接受 native/shell token；`BundleChecker` 只接受 HAP token 且 `GetHapTokenInfo` 成功、bundleName 精确匹配。候选 AccessToken 中 `GetTokenTypeFlag` 从 token type 位识别类型，`GetHapTokenInfo` 对非 HAP token 返回参数错误，HAP 信息从 manager 查询；权限验证须区分 granted/denied。 | `mock/src/mock_access_token.cpp` 有若干测试适配默认值：非零未知 token 可默认 grant，HAP token 信息可按测试 token 位合成；`mock/src/mock_ipc.cpp` 又把远程 calling token 替成服务端 self token。单进程用例不能证明身份隔离。 | 测试清单的 PID/UID/token 只能由 host 验证的连接上下文映射，客户端不得任意声明 token。两个客户端各自授权/拒绝，验证嵌套调用身份恢复、GetCalling 与 GetSelf 区分、客户端退出后上下文不残留。未注册 token 必须明确失败，不可默认放行。 |
| **BMS / user mapping — HAP 路径条件阻塞** | `BundleChecker::GetBundleAppId` 以 `uid / BASE_USER_RANGE` 得到 userId，调用 SA 401 的 `GetAppIdByBundleName(bundle,userId)`。本轮官方候选要求调用方具备 `GET_BUNDLE_INFO_PRIVILEGED` 权限或属于该 bundle；BMS/DataMgr 不可用、userId 无效、bundle 查询失败时返回空字符串；成功才返回 appId。 | `mock/src/mock_bundle_mgr_stub.cpp` 为系统 checker 路径合成非空 appId；`mock_bundle_manager.cpp` 对通用路径也有 `bundleName + _appId` 默认值。它没有覆盖 BMS 权限拒绝、未知 bundle、无效 user 和服务缺失。native-token SystemChecker 路径不会触发 BMS，因此当前仅凭 native-token 用例不能宣称 HAP 契约通过。 | 如果下一批只跑 native-token LOCAL_ONLY RDB，可暂不要求 BMS；一旦用 HAP 两客户端验证，就必须先加有效/错 bundle/无权限/未知 bundle/无服务用例，不能用通用固定 appId 假成功。 |
| **DeviceManager / local device identity — 已确认，DDMS 启动依赖；SoftBus 另论** | `KvStoreDataService::OnStart` 调用 `DmAdapter::Init(executors)`，最多等待 50×500ms 直到本地 UUID 非空；`Initialize/StartService` 后续用本地 UUID 建立 metadata 身份。候选 DeviceManager `InitDeviceManager` 要求非空 pkg 与 callback，底层服务初始化有界重试，失败返回错误；`GetLocalDeviceInfo` 需把 IPC/服务端错误传回，不能伪造默认设备。 | 当前 `mock/src/mock_device_manager_adapter_combined.cpp` 的 `Init` 是空操作，`GetLocalDevice()` 无委托时直接返回固定 `localuuid`；`mock/src/mock_device_manager.cpp` 多数 API 无条件成功，`GetLocalDeviceInfo` 固定返回静态身份。它能让单设备启动，但没有 ready/unavailable/failure 状态机。 | 当前 LOCAL_ONLY RDB 可以使用显式配置的、稳定的单机 UUID，不实现“远端设备在线”；必须有延迟 ready/启动失败负测。任何 remote sync/session 成功必须真实进入后续 SoftBus/communicator 路径，不得由固定设备 ID 推导成功。 |
| **EventCenter / ExecutorPool — 服务内部本地组件；生命周期契约待链路触达** | 当前 `OnStart` 构建 executor 并用 `EventCenter::Defer` 延迟事件；EventCenter 是 datamgr_service 本地实现，不是 `eventhandler` 直接等价物。U06 `SetSearchable` 在本地 feature mock 只验证状态 reply，没有搜索事件后端。 | U09-M5 已在单进程真实服务消费者中跑通启动和 feature 获取；不证明异步队列、回调调度、停止排空、取消和线程无残留。 | 在 InitNotifier/异步回调/服务停止首次接入前列为未验收，不宣称 OH 调度器等价。后续按实际调用源码和固定候选版本建 GAP。 |
| **SoftBus、Account/CommonEvent、HUKS/加密、文件系统 — 条件候选，当前不是已证实首错** | DDMS 依赖清单包含相关组件；它们分别在远端 DB 通信、账户/系统事件、加密数据库及持久化路径被触达。当前失败定位没有证明它们导致 `GetFeatureInterface`/`GetRdbService` 的首错。 | 本轮没有为这些依赖锁定官方 SHA，也没有将通用 mock 的无条件返回视为真实契约。远端同步、HAP user lifecycle、加密 store 与重启持久化尚未验收。 | 第一次有调用栈/日志证明进入时才建独立 GAP；先核源码和版本，再测错误/断连/损坏/重启语义。不得仅为当前 LOCAL_ONLY RDB 引入远程成功语义。 |

## 后续可验收拆分

| ID | 单步验证内容 | 通过条件 | 状态 |
|---|---|---|---|
| U07-A | 候选源码版本/调用符号审计 | 每个已确认边界有仓库、固定 SHA、文件/符号；consumer SHA 未知显式标出 | 完成（本文件） |
| U07-B | 行为契约表 | 参数、身份、错误、同步/异步、生命周期、persist/host simplification 均有来源；候选事实不冒充产品事实 | 完成（本文件及 U09 契约） |
| U07-C | 产品依赖版本对齐 | 从产品 manifest/构建锁证明实际消费的 SAFWK/SAMgr/IPC/AccessToken/BMS/DM SHA，并与候选做 API/行为差异核对 | 未完成：当前工作区无 manifest/lock；不阻塞继续做本地 U09/U10，但对应 GAP 仍保留版本风险 |
| U07-D | 将契约映射成实现测试 | IPC/身份/DM 生命周期先拆为 M3 探针；BMS/HUKS/SoftBus 仅在路径触达后纳入 | 后续步骤；不能用本文件替代运行验收 |

### 结项判定

U07 的研究输出已满足“固定源码候选、关键符号、行为矩阵、未知项显式隔离”，因此可以继续后续步骤。产品实际消费 SHA 仍未知是一个**保留风险**，不是把官方 master 当事实的理由；它继续阻止 U09-GAP-001 的精确消费版本 M1 关闭。若之后取得产品 manifest，应补记实际 revision 与差异，不覆盖本轮候选来源记录。

本轮仅做只读源码核对和文档更新；没有执行构建/测试，也没有修改任何上游/mock/test 源码。下一步从 U09 的真实服务宿主启动依赖继续，逐项添加可失败、可重试、可观测的验收；之后进入 IPC caller context 和对象句柄契约测试。
