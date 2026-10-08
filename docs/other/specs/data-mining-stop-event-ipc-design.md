# Data Mining: Pipeline 停止、事件通知与 IPC 接口设计

> **日期**: 2026-05-21（更新：2026-05-30）
> **状态**: Draft
> **开发模式**: TDD（先写测试，再实现）

---

## 1. 需求概要

### 1.1 Pipeline 停止

根据 `@hms.data.etlExtension.d.ts` 中 `stopDataMining(scene, taskId?)` 接口定义：

- 按 scene + taskId 停止指定任务
- 不传 taskId 则停止该 scene 下所有任务
- taskId 在应用进程（ETLClient）TriggerPipeline 时生成，通过 IPC 传递到 SA 侧
- 停止行为：优雅停止 + 可配置超时后强制中断
- Source/Operator/Sink 均暴露 `Stop()` 纯虚函数，子类必须实现停止逻辑

### 1.2 事件通知

- Pipeline 完成时发出终止事件：SUCCESS / FAILURE / INTERRUPT
- Pipeline 执行过程中发出进度事件：PROGRESS（含 finishCount/totalCount）
- 事件携带 triggerMode（MANUAL/AUTO），由 DDMS Dispatch 指定
- 事件经订阅过滤后通过 `ReportEvent` IPC 发送到应用进程
- `hasSubscriber` 控制所有事件；`hasProgressSubscriber` 额外控制 PROGRESS 事件

### 1.3 IPC 接口

**IDataMiningService（DDMS → ETL SA）** 提供 4 个 IPC 方法：

| 方法 | 用途 |
|------|------|
| `Dispatch(string)` | SOURCE_DATA 和 TRIGGER_SOURCE（JSON 序列化的 DispatchRequest） |
| `StopPipeline(scene, taskId)` | 停止指定 pipeline |
| `RegisterEventCallback(IRemoteObject)` | DDMS 注册事件回调 stub 到 ETL SA |
| `UpdateSubscription(scene, hasSubscriber, hasProgressSubscriber)` | 更新订阅状态 |

**DDMS 客户端接口（Client → DDMS）** 提供 observer 管理方法：

| 方法 | 用途 |
|------|------|
| `SubscribeEvent(observerId, scene, optionsJson, IRemoteObject)` | 注册事件 observer（多 observer 支持） |
| `UnsubscribeEvent(scene, observer)` | 取消注册事件 observer（传 scene + observer 对象，使用方无需感知 observerId） |

**多 observer 设计要点**：
- 每个 Client 进程可注册多个 observer，每个 observer 有独立的 `EventOptions` 配置
- 每个 Client 进程在 DDMS 中共享一个 remote 对象（`IRemoteObject`），由所有 observer 复用
- observerId 由 Client 端生成和传递，DDMS 不负责 ID 分配
- 客户端侧使用 `DataMiningEventObserver` 基类，使用方继承并实现 `OnEvent()` 方法
- 客户端通过 `std::shared_ptr<DataMiningEventObserver>` 管理 observer 生命周期
- 重复订阅检测在客户端侧进行：同一 scene + 同一 observer 对象（指针比较）不允许重复订阅
- 同一 scene 可以订阅多个不同的 observer，每个 observer 独立回调
- DDMS 侧维护 `scene → tokenId` 索引，回调时按 scene 快速查找匹配的 observer
- 回调路径：ETL SA → 回调 stub → DDMS 按 scene 分发 → 各 Client 的 `ThrottledEventObserverProxy` → IPC 回传 observerId + event → Client 端根据 observerId 分发到对应 observer
- DDMS 回调时通过 IPC MessageParcel 携带 observerId，客户端根据 observerId 路由到对应的 `DataMiningEventObserver` 实例
- observer 注册信息持久化在 DDMS 侧，ETL 进程退出/重启不影响 observer
- ETL SA 不依赖 ETLClient，通过 DDMS 注册的回调 stub 上报事件

### 1.4 Source 批次处理

根据大数据量 Source 分批处理的需求：

- Source 基类增加 `GetRemainDataCount()` 虚方法，默认返回 0（一次性处理完毕）
- 需要批次处理的 Source 重写此方法，返回剩余未处理的数据条数
- PipelineRuntime 内部循环调用 `Trigger()` 直到 `GetRemainDataCount()` 返回 0
- 每处理完一批数据，做一次进度回调（`ProgressCallback`）
- Source 自己控制每次 `Trigger()` 推送多少条数据，框架不干预批次大小
- 每批 DAG 执行完全隔离，创建新的 `TriggerDispatchState` 和 `SourceDispatchNotifier`
- 循环过程中检查 `IsStopping()`，为 true 时跳出循环

### 1.5 测试

- 所有测试通过公共接口驱动，验证行为输出，不直接访问私有成员
- 使用 demo 插件进行端到端验证

---

## 2. 架构设计

### 2.1 进程架构

```
┌──────────────┐    ┌─────────────────┐    ┌──────────────────────┐
│  应用进程     │    │   DDMS 进程      │    │   ETL SA 进程        │
│  (ETLClient) │    │ (ServiceImpl)   │    │ (RuntimeManager)     │
└──────┬───────┘    └───────┬─────────┘    └──────────┬───────────┘
       │                     │                         │
       │ TriggerPipeline     │                         │
       │ (scene, pipeline,   │                         │
       │  source, context,   │                         │
       │  taskId)            │                         │
       ├────────────────────►│                         │
       │  IPC: Dispatch      │                         │
       │  Data: JSON含taskId │                         │
       │                     │ TriggerSourceInRuntime  │
       │                     ├────────────────────────►│
       │                     │  Dispatch(TRIGGER)      │
       │                     │  + taskId + triggerMode │
       │                     │                         │
       │                     │           ┌─────────────┤
       │                     │           │ Store: taskId→TaskEntry
       │                     │           │ PipelineRuntime::TriggerSource()
       │                     │           │ 注入 ProgressCallback(taskId,pipeline,source)
       │                     │           └─────────────┤
       │                     │                         │
       │ StopPipeline        │                         │
       │ (scene, taskId)     │                         │
       ├────────────────────►│                         │
       │  IPC: StopPipeline  │                         │
       │                     │ Stop(scene, taskId)     │
       │                     ├────────────────────────►│
       │                     │                         │
       │                     │ RegisterEventCallback   │
       │                     │ (EventDispatcherStub)   │
       │                     ├────────────────────────►│
       │                     │                         │
       │                     │ UpdateSubscription      │
       │                     │ (scene, has, hasProgress)│
       │                     ├────────────────────────►│
       │                     │                         │
       │ SubscribeEvent      │                         │
       │ (observerId, scene, │                         │
       │  options, remote)   │                         │
       ├────────────────────►│                         │
       │                     │                         │
       │ UnsubscribeEvent    │                         │
       │ (observerId, scene) │                         │
       ├────────────────────►│                         │
       │                     │                         │
       │                     │    事件上报（ETL SA → DDMS）
       │                     │◄────────────────────────│
       │                     │  notifier_->ReportEvent()│
       │                     │                         │
       │    事件回调（DDMS→Client）                     │
       │◄────────────────────│                         │
       │  ThrottledObserver  │                         │
       │  -> OnEvent()       │                         │
       │  -> callbackProxy_  │                         │
```

### 2.2 IPC 接口

**IDataMiningService（ETL SA 侧，DDMS 调用）**：

```cpp
class IDataMiningService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DataMining.IDataMiningService");

    virtual int32_t Dispatch(const std::string &dispatchContent) = 0;
    virtual int32_t StopPipeline(const std::string &sceneName, int64_t taskId) = 0;
    virtual int32_t RegisterEventCallback(const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t UpdateSubscription(
        const std::string &scene, bool hasSubscriber, bool hasProgressSubscriber) = 0;
};
```

**DDMS 客户端接口（DDMS 侧，Client 调用）**：

SubscribeEvent/UnsubscribeEvent 由 DDMS 的 `DataMiningManager` 提供，供应用进程调用。不经过 `IDataMiningService`。

### 2.3 IPC Message Code 分配（IDataMiningService）

| Code | 方法 | 参数 (MessageParcel) |
|------|------|----------------------|
| 0 | Dispatch | string (JSON DispatchRequest) |
| 1 | StopPipeline | string sceneName + int64 taskId |
| 2 | RegisterEventCallback | IRemoteObject (callback stub) |
| 3 | UpdateSubscription | string scene + bool hasSubscriber + bool hasProgressSubscriber |

### 2.4 DispatchKind 枚举

`Dispatch` 方法仅处理两种类型：

```cpp
enum class DispatchKind : int32_t {
    SOURCE_DATA = 0,
    TRIGGER_SOURCE = 1,
};
```

停止、订阅、事件上报通过独立的 IPC 方法处理，不经过 `Dispatch`。

### 2.5 接口可见性分类

**Public**（SO 对外暴露，应用/外部模块可调用）：

| 所在 SO | 接口 | 状态 |
|---------|------|------|
| `etl_client.so` | `ETLClient::TriggerPipeline` | 已有 |
| `etl_client.so` | `ETLClient::SetSceneEnabled` | 已有 |
| `etl_client.so` | `ETLClient::SavePipelineResult` | 已有 |
| `etl_client.so` | `ETLClient::StopPipeline` | **新增** |
| `etl_client.so` | `ETLClient::SubscribeEvent` | **新增** |
| `etl_client.so` | `ETLClient::UnsubscribeEvent` | **新增** |
| `etl_client.so` | `DataMiningEventObserver` 基类 | **新增** — 用户继承实现 `OnEvent()` |
| ~~`etl_client.so`~~ | ~~`ETLClient::ReportEvent`~~ | **已移除** |

**Inner**（数据管理内部 IPC，不对外暴露）：

| IPC 通道 | 接口 | 状态 |
|----------|------|------|
| DDMS → ETL SA | `IDataMiningService::Dispatch` | 已有 |
| DDMS → ETL SA | `IDataMiningService::StopPipeline` | **新增** |
| DDMS → ETL SA | `IDataMiningService::RegisterEventCallback` | **新增** |
| DDMS → ETL SA | `IDataMiningService::UpdateSubscription` | **新增** |
| Client → DDMS | `IEtlService::TriggerPipeline` | 已有（增加 taskId 输出） |
| Client → DDMS | `IEtlService::SetSceneEnabled` | 已有 |
| Client → DDMS | `IEtlService::SavePipelineResult` | 已有 |
| Client → DDMS | `IEtlService::StopPipeline` | **新增** |
| Client → DDMS | `IEtlService::SubscribeEvent` | **新增**（含 observerId） |
| Client → DDMS | `IEtlService::UnsubscribeEvent` | **新增** |
| Client → DDMS | `IEtlService::OnEventCallback` | **新增** — DDMS → Client 内部回调 |
| Client → DDMS | `IEtlService::UpdateSubscription` | **新增** — DDMS → ETL SA 推送 |
| ~~Client → DDMS~~ | ~~`IEtlService::ReportEvent`~~ | **已移除** |
| ETL SA → DDMS | `IDataMiningEventNotifier::ReportEvent` | **新增** — 独立回调通道 |
| DDMS → Client | `IDataMiningEventObserverBroker::OnEventRemote` | **修改** — 增加 observerId |

**Inner**（非 IPC 内部类）：

| 类 / 方法 | 所属 | 状态 |
|-----------|------|------|
| `DataMiningManager::DispatchEvent` | DDMS 内部 | **新增** — 按 scene 分发，锁外回调 |
| `DataMiningManager::SubscribeEvent` | DDMS 内部 | **新增** |
| `DataMiningManager::UnsubscribeEvent` | DDMS 内部 | **新增** |
| `EventDispatcherStub` | DDMS 内部 | **新增** — 包装 NotifierStub 注册到 ETL SA |
| `ThrottledEventObserverProxy` | DDMS 内部 | **新增** — 事件过滤/节流 + observerId 回传 |
| `DataMiningRuntimeManager::ReportEvent` | ETL SA 内部 | **修改** — 通过 NotifierProxy IPC |
| `DataMiningRuntimeManager::RegisterEventCallback` | ETL SA 内部 | **修改** — `iface_cast` 存储 notifier |
| `DataMiningRuntimeManager::UpdateSubscriptionCache` | ETL SA 内部 | **新增** |
| `DataMiningEventObserverStub` (shared) | Client 内部 | **新增** — 所有 observer 共享一个 stub |

---

## 3. 调用流程

### 3.1 Trigger 流程

```
应用进程(ETLClient)     DDMS进程(ServiceImpl)    ETL SA进程(RuntimeManager)
       │                        │                          │
       │ taskId = GenerateId()  │                          │
       │                        │                          │
       │ TriggerPipeline        │                          │
       │ (scene, pipeline,      │                          │
       │  source, context,      │                          │
       │  taskId)               │                          │
       ├───────────────────────►│                          │
       │  IPC: Dispatch         │                          │
       │  JSON 含 taskId        │                          │
       │                        │ TriggerSourceInRuntime   │
       │                        ├─────────────────────────►│
       │                        │  Dispatch(TRIGGER)       │
       │                        │  + taskId + triggerMode  │
       │                        │                          │
       │                        │             ┌────────────┤
       │                        │             │ taskEntries_[taskId] = {
       │                        │             │   sceneName, pipelineNames,
       │                        │             │   triggerMode, runtimes,
       │                        │             │   pipelineStatuses,
       │                        │             │   sourceProgresses }
       │                        │             │ TriggerSource()
       │                        │             │ 注入 ProgressCallback
       │                        │             └────────────┤
       │                        │                          │
       │                        │  Reply: int32 status     │
       │◄───────────────────────┤                          │
       │  int32 status          │                          │
```

### 3.2 Stop 流程（按 taskId）

```
应用进程(ETLClient)     DDMS进程(ServiceImpl)    ETL SA进程(RuntimeManager)
       │                        │                          │
       │ StopPipeline           │                          │
       │ (scene, taskId)        │                          │
       ├───────────────────────►│                          │
       │  IPC: StopPipeline     │                          │
       │                        │ Stop(scene, taskId)      │
       │                        ├─────────────────────────►│
       │                        │                          │
       │                        │             ┌────────────┤
       │                        │             │ 1. [Lock] Lookup taskEntries_[taskId]
       │                        │             │    Verify sceneName match
       │                        │             │ 2. [Lock] Collect runtimes + pipelineNames
       │                        │             │    Collect INTERRUPT event data
       │                        │             │    (scene, taskId, triggerMode,
       │                        │             │     sourceProgresses)
       │                        │             │ 3. [Lock] Erase taskEntries_[taskId]  ← 防双事件
       │                        │             │    [Unlock]
       │                        │             │ 4. PipelineRuntime::Stop()
       │                        │             │    ├─ stopping_ = true
       │                        │             │    ├─ reject new dispatches
       │                        │             │    ├─ SourceProxy::Stop()
       │                        │             │    ├─ OperatorProxy::Stop()
       │                        │             │    └─ SinkProxy::Stop()
       │                        │             │ 5. ReportEvent(INTERRUPT)  ← 锁外
       │                        │             │ 6. [Lock] Remove from runtimes_ map
       │                        │             └────────────┤
       │                        │                          │
       │                        │  Reply: int32 status     │
       │◄───────────────────────┤                          │
```

> **注意**：Stop 后 runtime 从 `runtimes_` map 中移除，下次同 pipeline 的 Trigger/Dispatch 会通过 `BuildRuntime` 创建新实例。并发安全参见 [6.13 Stop 并发安全](#613-stop-并发安全防止双事件)。

### 3.3 Stop 流程（taskId=0，停止 scene 下所有）

```
       │ StopPipeline           │                          │
       │ (scene, taskId=0)      │                          │
       ├───────────────────────►│                          │
       │                        │ Stop(scene, 0)           │
       │                        ├─────────────────────────►│
       │                        │             ┌────────────┤
       │                        │             │ [Lock] Iterate taskEntries_
       │                        │             │ Filter by sceneName
       │                        │             │ For each match:
       │                        │             │   Collect runtime + event data
       │                        │             │   Erase taskEntry             ← 防双事件
       │                        │             │ [Unlock]
       │                        │             │ For each match:
       │                        │             │   PipelineRuntime::Stop()
       │                        │             │   ReportEvent(INTERRUPT)
       │                        │             │ [Lock] Remove from runtimes_ map
       │                        │             └────────────┤
```

### 3.4 PipelineRuntime 内部 Stop 调用链

```
PipelineRuntime::Stop(timeoutMs)
  │
  ├─ stopping_.store(true)
  │     DispatchFromTracked / TriggerSourceTracked 入口检查:
  │     if stopping_ → return E_INVALID_STATE
  │
  ├─ AcquireRuntimeSnapshot()
  │
  └─ for each node in topoOrder:
       ├─ if node.source: SourceProxy::Stop()
       │    ├─ lock → initialized_=false, local=source_ → unlock
       │    └─ local->Stop()  [锁外调用，不阻塞其他 Trigger/Process/Save]
       ├─ if node.op: OperatorProxy::Stop()
       │    ├─ lock → local=op_ → unlock
       │    └─ local->Stop()  [锁外调用]
       └─ if node.sink: SinkProxy::Stop()
            ├─ lock → local=sink_ → unlock
            └─ local->Stop()  [锁外调用]
```

> **注**：Proxy 层采用"锁内拷贝 shared_ptr、锁外调用插件"模式（见 6.14 节），确保 Stop 不会因为 Trigger/Process/Save 正在执行而被阻塞。

### 3.5 终止事件流程

Pipeline 完成（正常/异常/被停止）后触发：

```
NotifyDispatchComplete(taskId, pipelineName, status)
  │
  ├─ 1. pipelineStatuses[pipelineName] = status
  │
  ├─ 2. pipelineStatuses.size() == taskEntry.pipelineNames.size()?
  │     └─ No → return（等待其他 pipeline 完成）
  │
  ├─ 3. 确定终止状态（优先级 FAILURE > INTERRUPT > SUCCESS）
  │     - 任一 pipeline FAILURE → 整体 FAILURE
  │     - 全部 SUCCESS 但有被 Stop 的 → INTERRUPT
  │     - 全部 SUCCESS 且无 Stop → SUCCESS
  │
  ├─ 4. 构造 DataMiningEvent(taskId, triggerMode, 终止状态, 汇总的 sourceProgresses)
  │
  ├─ 5. ReportEvent(event)
  │     ├─ !HasSubscribers(scene) → skip
  │     ├─ PROGRESS && !HasProgressSubscribers(scene) → skip
  │     └─ 否则 → notifier_->ReportEvent(event.ToJson())
  │               （通过 DataMiningEventNotifierProxy IPC 发送）
  │
  └─ 6. taskEntries_.erase(taskId)
        （仅在发出事件后删除）
```

### 3.6 进度事件流程

Source 批次完成时触发：

```
ProgressCallback(taskId, pipelineName, sourceName, finishCount, totalCount)
  │
  └─ OnSourceBatchComplete(...)
       │
       ├─ 1. 更新 TaskEntry 的 sourceProgresses（finishCount += delta）
       │
       ├─ 2. HasProgressSubscribers(scene)?
       │     └─ No → return（跳过 IPC）
       │
       ├─ 3. 汇总所有 source 进度：
       │     totalFinish = sum(所有 source 的 finishCount)
       │     totalCount = sum(所有 source 的 totalCount)
       │
       └─ 4. ReportEvent(PROGRESS 事件)
```

### 3.7 Source 批次循环流程（PipelineRuntime 内部）

PipelineRuntime 的 `TriggerSourceTracked` 增加批次循环逻辑。每次 `Trigger()` 推送一批数据，DAG 执行完毕后检查 `GetRemainDataCount()`，若 > 0 则继续下一批：

```
PipelineRuntime::TriggerSourceTracked(fromNode, context, instanceId, onAsyncComplete)
  │
  ├─ snapshot = AcquireRuntimeSnapshot()
  ├─ node = snapshot->nodes[fromNode]
  ├─ ExecutionResult result
  ├─ int64_t finishedCount = 0
  │
  └─ while (!IsStopping()):
       ├─ triggerState = make_shared<TriggerDispatchState>()
       │    triggerState->asyncComplete = nullptr  // 中间批次不需要
       ├─ notifier = SourceDispatchNotifier(this, fromNode, instanceId, triggerState)
       ├─ node.source->Trigger(context, notifier)
       │
       ├─ [锁内检查结果]
       │    lock(triggerState->mutex)
       │    triggerState->triggerReturned = true
       │    if triggerState->resultReady:
       │        result = triggerState->result       // 同步 Source
       │    else:
       │        result = { status, false }           // 异步 Source，不进循环
       │
       ├─ if !IsSuccessStatus(result.status): break
       │
       ├─ finishedCount += 本批 RecordBatch->Count()
       ├─ remainCount = node.source->GetRemainDataCount()
       ├─ totalCount = finishedCount + remainCount
       │
       ├─ [触发进度回调]
       │    if (progressCallback_ != nullptr):
       │        progressCallback_(0, pipelineName, fromNode, finishedCount, totalCount)
       │
       └─ if remainCount <= 0: break

  // 全部完成，通知上层
  if (onAsyncComplete != nullptr):
      onAsyncComplete(result)
  return result
```

**设计要点**：
- 每轮循环创建新的 `TriggerDispatchState` 和 `SourceDispatchNotifier`，状态完全隔离
- 对于同步 Source（Trigger 内部同步调用 Notify），Trigger 返回后 `resultReady` 已为 true
- 对于异步 Source，`resultReady` 为 false，不进入批次循环（异步 Source 不适合批次模式）
- `GetRemainDataCount()` 默认返回 0，现有 Source 不进入循环，行为不变

### 3.8 RegisterEventCallback 流程

DDMS 启动 ETL SA 后，注册回调 stub：

```
DDMS进程(ServiceImpl)              ETL SA进程(RuntimeManager)
     │                                   │
     │ RegisterEventCallback             │
     │ (EventDispatcherStub)             │
     ├──────────────────────────────────►│
     │  IPC: RegisterEventCallback       │
     │  MessageParcel: IRemoteObject     │
     │                                   │
     │                        ┌──────────┤
     │                        │ iface_cast<IDataMiningEventNotifier>
     │                        │ 存储到 eventNotifier_ 成员
     │                        │ 后续 ReportEvent 通过 notifier proxy
     │                        │ 回调 DDMS 的 notifier stub
     │                        └──────────┤
     │                                   │
     │  Reply: int32 status              │
     │◄──────────────────────────────────┤
```

### 3.9 Subscribe 流程（Client → DDMS）

SubscribeEvent/UnsubscribeEvent 由 Client 直接调用 DDMS 的 DataMiningManager，不经过 IDataMiningService。

**客户端侧预处理**：
1. 客户端生成 observerId
2. 客户端检查重复订阅：同 scene + 同 observer 对象（`shared_ptr::get()` 指针比较）已存在 → 直接返回错误
3. 通过检查后才发起 IPC 调用到 DDMS

**IPC 流程**：

```
Client进程              DDMS进程(ServiceImpl)
     │                        │
     │ 1. 生成 observerId     │
     │ 2. 检查重复：同scene   │
     │    + 同observer指针?   │
     │    └─ 是 → return      │
     │       E_DUPLICATE      │
     │                        │
     │ SubscribeEvent         │
     │ (observerId, scene,    │
     │  optionsJson)          │
     │ + remote(Stub对象)     │
     ├───────────────────────►│
     │  IPC: SubscribeEvent   │
     │  MessageParcel含:      │
     │   observerId + scene   │
     │   + optionsJson        │
     │   + IRemoteObject(remote)│
     │                        │
     │             ┌──────────┤
     │             │ 3. token = GetCallingTokenID()
     │             │ 4. 从 MessageParcel 读取 remote
     │             │ 5. 查找/创建 clients_[token]
     │             │ 6. 解析 optionsJson → EventOptions
     │             │ 7. 创建 ThrottledEventObserverProxy(options, remote)
     │             │ 8. clients_[token].observers[scene].push_back({observerId, proxy})
     │             │ 9. sceneToTokens_[scene].push_back(token)（去重）
     │             │ 10. RecalcSubscriptionCache(scene)
     │             │    → 更新 HasSubscribers/HasProgressSubscribers
     │             │    → 通知 ETL SA UpdateSubscription（聚合结果）
     │             │ 11. 首次注册该 token 时：
     │             │    注册 DeathRecipient 到 remote
     │             └──────────┤
     │                        │
     │  Reply: int32 status   │
     │◄───────────────────────┤
```

### 3.10 Unsubscribe 流程

```
Client进程              DDMS进程(ServiceImpl)
     │                        │
     │ 1. 根据 observer + scene │
     │    查找 clientObservers_ │
     │    获取内部 observerId   │
     │                        │
     │ UnsubscribeEvent       │
     │ (observerId, scene)    │
     ├───────────────────────►│
     │  IPC: UnsubscribeEvent │
     │                        │
     │             ┌──────────┤
     │             │ 2. token = GetCallingTokenID()
     │             │ 3. 查找 clients_[token]
     │             │ 4. 在 clients_[token].observers[scene] 中
     │             │    找到匹配 observerId 的 proxy 并移除
     │             │ 5. 若 observers[scene] 为空：
     │             │    从 sceneToTokens_[scene] 移除 token
     │             │ 6. RecalcSubscriptionCache(scene)
     │             │ 7. 若该 token 下所有 observer 已清空：
     │             │    移除 ClientInfo，注销 DeathRecipient
     │             └──────────┤
     │                        │
     │ 8. 从 clientObservers_ │
     │    中移除 entry        │
     │                        │
     │  Reply: int32 status   │
     │◄───────────────────────┤
```

### 3.11 事件分发流程（ETL SA → DDMS → Client）

ETL SA 通过回调 stub 上报事件，DDMS 分发给匹配的 observer，并通过 IPC MessageParcel 回传 observerId：

```
ETL SA进程                 DDMS进程(ServiceImpl)               Client进程
     │                           │                                │
     │ eventNotifier_            │                                │
     │ → ReportEvent(eventJson)  │                                │
     ├──────────────────────────►│                                │
     │  通过 NotifierProxy IPC    │                                │
     │                           │                                │
     │                 ┌─────────┤                                │
     │                 │ EventNotifierStub::OnRemoteRequest      │
     │                 │ 1. 读取 eventJson                       │
     │                 │ 2. callback_ → 解析 JSON               │
     │                 │ 2. sceneToTokens_[event.scene]          │
     │                 │    → 获取所有相关 token                  │
     │                 │ 3. 对每个 token：                        │
     │                 │    clients_[t].observers[scene]          │
     │                 │    → 遍历每个 ObserverEntry              │
     │                 │ 4. proxy->OnEvent(event, entry.observerId)│
     │                 │    ├─ ShouldDeliver? 过滤                │
     │                 │    ├─ ShouldReportProgress? 节流         │
     │                 │    └─ OnEventRemote(observerId, json)   │
     │                 │       MessageParcel:                     │
     │                 │         WriteInt64(observerId)  ← 新增   │
     │                 │         WriteString(eventJson)           │
     │                 └─────────┤                                │
     │                           │                                │
     │                           │  ThrottledObserver回调         │
     │                           ├───────────────────────────────►│
     │                           │  Stub::OnRemoteRequest         │
     │                           │  → 读取 observerId             │
     │                           │  → 解析 eventJson              │
     │                           │                                │
     │                           │              ┌─────────────────┤
     │                           │              │ 共享 Stub 回调    │
     │                           │              │ 1. lock: 查找    │
     │                           │              │    observer by Id│
     │                           │              │    复制 shared_ptr│
     │                           │              │ 2. unlock        │
     │                           │              │ 3. observer->    │
     │                           │              │    OnEvent(event)│
     │                           │              └─────────────────┤
```

---

## 4. 数据结构

### 4.1 DispatchRequest

**文件**: `data_mining_service/include/runtime/transport_types.h`

```cpp
struct DispatchRequest {
    int32_t kind = 0;              // SOURCE_DATA(0) 或 TRIGGER_SOURCE(1)
    std::string sceneName;
    std::string pipelineName;
    std::string fromNode;
    int64_t taskId = 0;
    TriggerMode triggerMode = TriggerMode::MANUAL;

    // plugins, pipeline 定义等...
};
```

`Marshal`/`Unmarshal` 序列化包含 `taskId` 和 `triggerMode`。

### 4.2 TaskEntry

**文件**: `data_mining_service/include/runtime/data_mining_runtime_manager.h`

```cpp
struct TaskEntry {
    std::string sceneName;
    std::vector<std::string> pipelineNames;
    std::map<std::string, std::shared_ptr<PipelineRuntime>> runtimes;
    TriggerMode triggerMode = TriggerMode::MANUAL;
    std::map<std::string, int32_t> pipelineStatuses;     // pipelineName → 完成状态

    struct SourceProgress {
        std::string pipelineName;
        std::string sourceName;
        int64_t finishCount = 0;
        int64_t totalCount = 0;
    };
    std::vector<SourceProgress> sourceProgresses;
};

std::unordered_map<int64_t, TaskEntry> taskEntries_;  // mutex_ 保护
```

**TaskEntry 生命周期：**
- Trigger 时从请求中提取 taskId 并存入 `taskEntries_`
- Stop 时发出 INTERRUPT 事件后立即清理 TaskEntry 和对应 runtime（参见 [6.12 Stop 后重新触发](#612-stop-后重新触发)）
- 自然完成时 `OnSourceBatchComplete` 发出 SUCCESS/FAILURE 事件后执行 `taskEntries_.erase(taskId)`

### 4.3 ProgressCallback

**文件**: `data_mining_service/include/runtime/pipeline_runtime.h`

```cpp
using ProgressCallback = std::function<void(int64_t taskId,
                                             const std::string &pipelineName,
                                             const std::string &sourceName,
                                             int64_t finishCount, int64_t totalCount)>;
```

### 4.4 多 Observer 管理数据结构

#### 4.4.1 客户端侧 Observer 基类

**文件**: `data_mining/include/data_mining_event_observer.h`

```cpp
class DataMiningEventObserver {
public:
    virtual ~DataMiningEventObserver() = default;
    virtual void OnEvent(const DataMiningEvent &event) = 0;
};
```

客户端侧使用 `std::shared_ptr<DataMiningEventObserver>` 管理 observer 生命周期。使用方继承此基类并实现 `OnEvent()` 方法。

#### 4.4.2 客户端侧 Observer 管理

**文件**: `data_mining/include/etl_client.h`

```cpp
class EtlClient {
public:
    // 订阅：传入 observer 智能指针、scene、options
    int64_t SubscribeEvent(const std::string &scene,
                           const EventOptions &options,
                           std::shared_ptr<DataMiningEventObserver> observer);

    // 取消订阅：传入 scene + observer 对象，使用方无需感知 observerId
    int32_t UnsubscribeEvent(const std::string &scene,
                             const std::shared_ptr<DataMiningEventObserver> &observer);

private:
    struct ClientObserverEntry {
        int64_t observerId;
        std::string scene;
        std::shared_ptr<DataMiningEventObserver> observer;
        EventOptions options;
    };

    // 客户端侧 observer 注册表
    std::vector<ClientObserverEntry> clientObservers_;

    // 客户端侧共享 stub：所有 observer 共用一个 stub，DDMS 每个客户端（token）只看到一个 remote 对象
    sptr<DataMiningEventObserverStub> sharedStub_;

    // 根据 observer 对象查找 observerId（用于 UnsubscribeEvent）
    std::optional<int64_t> FindObserverId(
        const std::shared_ptr<DataMiningEventObserver> &observer, const std::string &scene);

    // 根据 observerId 查找 observer（用于 IPC 回调路由）
    std::shared_ptr<DataMiningEventObserver> FindObserverById(int64_t observerId);

    // 重复订阅检测：同一 scene + 同一 observer 对象（shared_ptr::get() 指针比较）
    bool IsDuplicateObserver(const std::string &scene,
                             const std::shared_ptr<DataMiningEventObserver> &observer) const;
};
```

#### 4.4.3 DDMS 侧 Observer 管理数据结构

**文件**: `datamgr_service/services/distributeddataservice/service/data_mining/include/data_mining_manager.h`

```cpp
struct ObserverEntry {
    int64_t observerId;
    std::shared_ptr<ThrottledEventObserverProxy> proxy;
};

struct ClientInfo {
    std::unordered_map<std::string,                                               // scene
        std::vector<ObserverEntry>>                                               // 该 scene 下的 observer（含 observerId）
        > observers;
};

// 主索引：callerTokenID → ClientInfo
std::unordered_map<uint32_t, ClientInfo> clients_;

// scene 索引：快速查找某 scene 下有哪些 tokenId
std::unordered_map<std::string, std::vector<uint32_t>> sceneToTokens_;
```

**EventDispatcherStub（DDMS 侧回调 stub，注册到 ETL SA）**：

```cpp
class EventDispatcherStub final {
public:
    explicit EventDispatcherStub(DataMiningManager &manager)
        : notifierStub_(new DataMiningEventNotifierStub(
            [&manager](const std::string &eventJson) -> int32_t {
                DataMiningEvent event;
                if (!DataMiningEvent::FromJson(eventJson, event)) {
                    return E_PARSE_FAILED;
                }
                manager.DispatchEvent(event);
                return E_OK;
            }))
    {
    }

    sptr<IRemoteObject> AsRemoteObject() const { return notifierStub_; }

private:
    sptr<DataMiningEventNotifierStub> notifierStub_;
};
```

**ETL SA 侧回调存储**：

```cpp
// DataMiningRuntimeManager 中
sptr<IDataMiningEventNotifier> eventNotifier_;  // DDMS 通过 RegisterEventCallback 注册的 notifier

void RegisterEventCallback(const sptr<IRemoteObject> &callback) {
    std::lock_guard<std::mutex> lock(subscriptionMutex_);
    eventNotifier_ = iface_cast<IDataMiningEventNotifier>(callback);
}

void ReportEvent(const DataMiningEvent &event) {
    if (!HasSubscribers(event.scene)) return;
    if (event.eventType == EventType::PROGRESS && !HasProgressSubscribers(event.scene)) return;
    sptr<IDataMiningEventNotifier> notifier;
    {
        std::lock_guard<std::mutex> lock(subscriptionMutex_);
        notifier = eventNotifier_;
    }
    if (notifier == nullptr) return;
    notifier->ReportEvent(event.ToJson());
}
```

**数据结构说明**：
- `clients_`：以 Client 进程的 `callerTokenID`（`IPCSkeleton::GetCallingTokenID()`）为 key
- `ClientInfo.observers`：以 scene 为 key，值为该 scene 下的 `ObserverEntry` 列表，每个 entry 包含 `observerId` 和 `ThrottledEventObserverProxy`
- 每个 `ThrottledEventObserverProxy` 持有独立的 `EventOptions`（过滤和节流配置）和指向 Client 端 remote 的 `callbackProxy_`
- 同一个 Client 进程的所有 observer 共享同一个 `sptr<IRemoteObject>`（即同一个 `callbackProxy_`）
- `sceneToTokens_`：以 scene 为 key，值为订阅了该 scene 的所有 tokenId 列表，用于回调时快速查找
- `ObserverEntry.observerId`：客户端生成的唯一标识，DDMS 回调时通过 IPC MessageParcel 回传此 id

**订阅缓存聚合**：

```cpp
void RecalcSubscriptionCache(const std::string &scene) {
    bool hasSubscriber = false;
    bool hasProgressSubscriber = false;
    for (auto &[token, client] : clients_) {
        auto obsIt = client.observers.find(scene);
        if (obsIt == client.observers.end()) continue;
        for (auto &entry : obsIt->second) {
            hasSubscriber = true;
            // 检查 proxy 的 options 是否包含进度订阅
            if (entry.proxy->GetOptions().isReportProgress) {
                hasProgressSubscriber = true;
            }
        }
    }
    // 通知 ETL SA 的聚合结果保持不变
    UpdateSubscriptionCache(scene, hasSubscriber, hasProgressSubscriber);
}
```

**Client 死亡检测**：

```cpp
class ClientDeathRecipient : public IRemoteObject::DeathRecipient {
    void OnRemoteDied(const wptr<IRemoteObject> &object) override {
        auto remote = object.promote();
        // 遍历 clients_ 找到匹配的 remote（通过 observer 的 GetRemoteObject()）
        // 移除该 token 对应的 ClientInfo
        // 清理 sceneToTokens_ 中相关条目
        // 重新聚合订阅缓存
    }
};
```

首次为某 token 创建 ClientInfo 时，注册 DeathRecipient 到 remote。同一 Client 下的所有 observer 共享同一个 remote，只需注册一次。

### 4.5 UpdateSubscriptionCache（ETL SA 侧，不变）

**文件**: `data_mining_service/include/runtime/data_mining_runtime_manager.h`

```cpp
void UpdateSubscriptionCache(const std::string &scene,
                             bool hasSubscriber,
                             bool hasProgressSubscriber);
```

存储两个独立的布尔标志：`HasSubscribers(scene)` 和 `HasProgressSubscribers(scene)`。

此接口对 ETL SA 侧不变，DDMS 内部通过 RecalcSubscriptionCache 聚合后调用。

---

## 5. 修改文件清单

### 5.1 算子接口 (`data_mining/include/`)

| 文件 | 变更 |
|------|------|
| `source.h` | `OnStop()` → `Stop()`（纯虚函数重命名）；新增 `virtual int64_t GetRemainDataCount() { return 0; }` |
| `operator.h` | 新增 `virtual int32_t Stop() = 0;` |
| `sink.h` | 新增 `virtual int32_t Stop() = 0;` |

### 5.2 SA IPC 接口层 (`data_mining_service/include/client/`)

| 文件 | 变更 |
|------|------|
| `idata_mining_service.h` | 新增 `StopPipeline`, `RegisterEventCallback` 纯虚方法；恢复 `UpdateSubscription` |
| `data_mining_service_proxy.h` | 新增 3 个方法声明 |
| `data_mining_service_stub.h` | 新增 3 个 handler 声明 |
| `data_mining_client.h` | 新增 3 个方法声明 |

### 5.3 SA IPC 实现层 (`data_mining_service/src/client/`)

| 文件 | 变更 |
|------|------|
| `data_mining_service_proxy.cpp` | 3 个方法实现：WriteInterfaceToken + 参数序列化 + SendRequest + 读 reply |
| `data_mining_service_stub.cpp` | `OnRemoteRequest` 新增 case 1/2/3 分支 + 3 个私有 handler |
| `data_mining_client.cpp` | 3 个方法实现：获取 proxy → 调用接口方法 |

### 5.4 ETL 层 (`data_mining/include/` + `data_mining/src/`)

| 文件 | 变更 |
|------|------|
| `etl_service.h` | 新增 `StopPipeline(scene, taskId)` 纯虚函数；`TriggerPipeline` 增加 taskId 输出参数 |
| `etl_client.h` | 新增 `StopPipeline(scene, taskId)`；`TriggerPipeline` 增加 `int64_t *taskId = nullptr` 输出参数；新增 `SubscribeEvent(scene, options, shared_ptr<DataMiningEventObserver>)`；新增 `UnsubscribeEvent(scene, shared_ptr<DataMiningEventObserver>)`（使用方无需感知 observerId）；新增 `ClientObserverEntry`/`clientObservers_`/`FindObserverId()`/`IsDuplicateObserver()` |
| `etl_client.cpp` | 实现 `StopPipeline()`；`TriggerPipeline()` 生成 taskId 写入 JSON；`SubscribeEvent()` 客户端侧重复检测 + IPC 调用；`UnsubscribeEvent()` 内部查找 observerId 后 IPC 调用 + 客户端侧清理 |
| `etl_service_proxy.h/.cpp` | 新增 `StopPipeline()` override；`TriggerPipeline()` JSON 包含 taskId |
| `data_mining_event_observer_base.h` | **新增文件**：`DataMiningEventObserver` 基类，`OnEvent()` 纯虚函数 |
| `data_mining_event_observer.h` | **新增文件**：`DataMiningEventObserverProxy`/`DataMiningEventObserverStub` IPC Proxy/Stub（内联实现），`OnEventRemote` 签名含 `observerId` 参数 |
| `idata_mining_event_notifier.h` | **新增文件**：`IDataMiningEventNotifier` IRemoteBroker 接口，`ReportEvent` 纯虚函数 |
| `data_mining_event_notifier_proxy.h/.cpp` | **新增文件**：IPC Proxy，`TF_ASYNC` 发送 ReportEvent |
| `data_mining_event_notifier_stub.h/.cpp` | **新增文件**：IPC Stub，接收 ReportEvent 回调 |

### 5.5 SA Transport 类型 (`data_mining_service/include/runtime/` + `src/runtime/`)

| 文件 | 变更 |
|------|------|
| `transport_types.h` | `DispatchKind` 仅保留 SOURCE_DATA/TRIGGER_SOURCE；`DispatchRequest` 新增 `taskId`、`triggerMode` |
| `transport_types.cpp` | Marshal/Unmarshal 序列化 `taskId` 和 `triggerMode` |

### 5.6 SA Proxy 层 (`data_mining_service/`)

| 文件 | 变更 |
|------|------|
| `source_proxy.h/.cpp` | `OnStop()` → `Stop()` override；新增 `GetRemainDataCount()` 转发；Trigger/Subscribe/Stop 采用"锁内拷贝 shared_ptr、锁外调用插件"模式（见 6.14 节） |
| `operator_proxy.h/.cpp` | 新增 `int32_t Stop()`；Process/Stop 采用同样模式 |
| `sink_proxy.h/.cpp` | 新增 `int32_t Stop()`；Save/Stop 采用同样模式 |

### 5.7 PipelineRuntime (`data_mining_service/`)

| 文件 | 变更 |
|------|------|
| `pipeline_runtime.h` | 新增 `Stop(timeoutMs=30000)`, `IsStopping()`, `std::atomic<bool> stopping_{false}`；`ProgressCallback` 签名含 taskId/pipelineName/sourceName |
| `pipeline_runtime.cpp` | 实现 Stop()；`DispatchFromTracked`/`TriggerSourceTracked` 入口加 stopping 检查；`TriggerSourceTracked` 增加批次循环逻辑（见 3.7 节）；每批完成后调用 `ProgressCallback` |

### 5.8 SA 服务层 (`data_mining_service/`)

| 文件 | 变更 |
|------|------|
| `data_mining_service.h/.cpp` | 新增 `StopPipeline`/`RegisterEventCallback`/`UpdateSubscription` override，委托到 RuntimeManager |
| `data_mining_runtime_manager.h` | 新增 `Stop(scene, taskId)`；增强 `TaskEntry`（triggerMode, pipelineStatuses, sourceProgresses）；新增 `eventNotifier_` 成员（`sptr<IDataMiningEventNotifier>`）；`RegisterEventCallback` 通过 `iface_cast` 转型并存储；`UpdateSubscriptionCache` 含 `hasProgressSubscriber`；新增 `ReportEvent` 方法（通过 `DataMiningEventNotifierProxy` 回调） |
<<<<<<< Updated upstream:docs/specs/data-mining-stop-event-ipc-design.md
| `data_mining_runtime_manager.cpp` | **Stop/Event 部分**：trigger 时存 taskEntries_ 含 triggerMode；Stop() 不删 TaskEntry；NotifyDispatchComplete 发出终止事件后删除；OnSourceBatchComplete 进度聚合；ReportEvent 通过 `DataMiningEventNotifierProxy` IPC 回调 DDMS；Dispatch 拒绝 kind 2/3/4。**批次处理部分**：`PrepareDispatchExecution` 中当 taskId!=0 时注册 ProgressCallback（见 6.15 节）；移除 `onAsyncComplete` 中冗余的 `OnSourceBatchComplete(taskId, ..., 0, 0)` 调用 |
=======
| `data_mining_runtime_manager.cpp` | trigger 时存 taskEntries_ 含 triggerMode；Stop() 发出 INTERRUPT 事件后清理 taskEntry 和 runtime（参见 6.12）；NotifyDispatchComplete 发出终止事件后删除；OnSourceBatchComplete 进度聚合；ReportEvent 通过 `DataMiningEventNotifierProxy` IPC 回调 DDMS；Dispatch 拒绝 kind 2/3/4 |
>>>>>>> Stashed changes:claude/docs/specs/data-mining-stop-event-ipc-design.md

### 5.9 DDMS 集成层 (`datamgr_service/`)

| 文件 | 变更 |
|------|------|
| `data_mining_manager.h` | 新增 `StopPipelineByTaskId(scene, taskId)`；新增 `SubscribeEvent`/`UnsubscribeEvent` 方法；新增 `ObserverEntry`/`ClientInfo`/`sceneToTokens_` 数据结构；新增 `RecalcSubscriptionCache`/`DispatchEvent` 方法；新增 `EventDispatcherStub`；新增 `ClientDeathRecipient`；启动时调用 `RegisterEventCallback` 注册 stub |
| `data_mining_manager.cpp` | `StopPipelineByTaskId()` 调用 `client->StopPipeline()`；`SubscribeEvent` 管理 `clients_`/`sceneToTokens_` 并调用 `RecalcSubscriptionCache`；`UnsubscribeEvent` 移除 observer 并调用 `RecalcSubscriptionCache`；`RecalcSubscriptionCache` 聚合后通知 ETL SA `UpdateSubscription`；`DispatchEvent` 按 scene 分发给匹配 observer（携带 observerId） |
| `throttled_event_observer_proxy.h` | 新增 `GetOptions()` 访问器方法；`OnEvent` 签名新增 `observerId` 参数 |
| `throttled_event_observer_proxy.cpp` | `OnEvent` 新增 observerId 参数，透传给 `OnEventRemote(observerId, eventJson)` |

### 5.10 Mock 基础设施 (`mock/`)

| 文件 | 变更 |
|------|------|
| `mock/src/mock_dlfcn.cpp` | 扩展 `g_libraryMappings` 支持 data mining demo 插件；添加 sentinel handle 机制（见第 7 节） |

---

## 6. 关键设计决策

### 6.1 TaskId 生成与传递

taskId 在应用进程（ETLClient）生成，通过 TriggerPipeline 的 IPC JSON 请求传递到 SA 侧存储。

```cpp
// ETLClient
std::atomic<int64_t> nextObserverId_{1};

int64_t ETLClient::SubscribeEvent(...) {
    int64_t observerId = nextObserverId_.fetch_add(1);
    // ... validate and IPC call
}
```

`SubscribeEvent` 内部通过 `nextObserverId_` 递增生成 observerId。`TriggerPipeline` 通过输出参数 `int64_t *taskId` 返回给调用方。

### 6.2 Operator/Sink Stop() 为纯虚函数

Source/Operator/Sink 的 `Stop()` 均为纯虚函数，子类必须实现停止逻辑。所有 mock 类和 Tracking 类需实现 `Stop()`。

### 6.3 优雅停止 + 可配置超时

```cpp
int32_t PipelineRuntime::Stop(int32_t timeoutMs = 30000) {
    stopping_.store(true);
    auto snapshot = AcquireRuntimeSnapshot();
    for (auto &nodeName : snapshot->topoOrder) {
        // 遍历节点调 Stop()
    }
    // TODO: 后续实现带超时的 condition_variable wait
    return E_OK;
}
```

- `stopping_` 在 `DispatchFromTracked`/`TriggerSourceTracked` 入口检查，为 true 时返回 `E_INVALID_STATE`
- `timeoutMs` 参数保留在签名中，为后续扩展准备

### 6.4 Stop() 清理 Runtime 和 TaskEntry

`Stop()` 在停止 runtime 后，主动发送 INTERRUPT 终止事件，然后从 `runtimes_` map 和 `taskEntries_` 中清理对应条目。

**清理流程**（关键：taskEntry 的 erase 必须在锁内**先于** runtime->Stop() 和 ReportEvent）：
1. **在锁内**收集要停止的 runtimes、对应的 pipelineName、以及 task entry 事件数据（sceneName、taskId、triggerMode、sourceProgresses）
2. **在锁内**从 `taskEntries_` 移除对应的 task entry（原子操作：拿锁+删除，防止双事件）
3. 锁外调用 `runtime->Stop()` 停止每个 runtime
4. 锁外调用 `ReportEvent(INTERRUPT)` 发送中断事件（使用步骤 1 收集的数据）
5. **在锁内**从 `runtimes_` map 移除已停止的 runtime

**并发安全：防止双事件**（详见 6.13）：

taskEntry 的 erase 是"谁负责发终止事件"的判定标准。`Stop()` 和异步完成回调（`OnSourceBatchComplete`）竞争同一个 taskEntry，通过在锁内先 erase 保证唯一性：
- Stop 先拿到锁 → erase taskEntry → 异步回调后发现 `find(taskId)` 返回 end → 跳过，不发事件。只有 INTERRUPT。
- 异步回调先拿到锁 → erase taskEntry + 发 SUCCESS/FAILURE → Stop 发现 `find(taskId)` 返回 end → 返回 E_NOT_FOUND，不发事件。只有 SUCCESS/FAILURE。

**注意**：同一个 runtime 可能被多个 task entry 引用（同 pipeline 名被多场景复用），从 `runtimes_` 移除时需确保不被其他 task entry 引用。

**与自然完成的区别**：自然完成通过 `OnSourceBatchComplete` 发出 SUCCESS/FAILURE 事件并清理 task entry。Stop 则主动发出 INTERRUPT 事件并立即清理，pipeline 不会自然完成。

### 6.5 终止事件状态机

```
                    ┌──────────┐
                    │ SUCCESS  │ ← 所有 pipeline 正常完成
                    └────┬─────┘
                         │
    ┌──────────┐    ┌────┴─────┐    ┌──────────┐
    │ FAILURE  │◄───│  优先级    │───►│ INTERRUPT│
    │(任一失败) │    │  判定      │    │(被停止)  │
    └──────────┘    └──────────┘    └──────────┘
```

优先级：`FAILURE > INTERRUPT > SUCCESS`

- 任一 pipeline FAILURE → 整体事件为 FAILURE
- 全部 SUCCESS 但有被 Stop 的 → 整体事件为 INTERRUPT
- 全部 SUCCESS 且无 Stop → 整体事件为 SUCCESS

### 6.6 ReportEvent 订阅过滤与多 Observer 分发

ETL SA 通过 `DataMiningEventNotifierProxy`（`eventNotifier_`）上报事件，不再依赖 ETLClient。DDMS 收到回调后，通过 `sceneToTokens_` 查找匹配的 token，遍历每个 token 下的 `ObserverEntry` 进行分发。每个 proxy 根据自身的 `EventOptions` 独立过滤。分发时携带 observerId，通过 IPC MessageParcel 回传给客户端。

**ETL SA 侧 ReportEvent**（使用 DataMiningEventNotifierProxy）：
```cpp
void ReportEvent(const DataMiningEvent &event) {
    if (!HasSubscribers(event.scene)) return;
    if (event.eventType == EventType::PROGRESS && !HasProgressSubscribers(event.scene)) return;
    sptr<IDataMiningEventNotifier> notifier;
    {
        std::lock_guard<std::mutex> lock(subscriptionMutex_);
        notifier = eventNotifier_;
    }
    if (notifier == nullptr) return;
    notifier->ReportEvent(event.ToJson());
}
```

**DDMS 侧 DispatchEvent**（携带 observerId，锁外回调）：
```cpp
void DispatchEvent(const DataMiningEvent &event) {
    // 锁内：收集快照，不执行回调
    std::vector<std::pair<std::shared_ptr<ThrottledEventObserverProxy>, int64_t>> snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sceneToTokens_.find(event.scene);
        if (it == sceneToTokens_.end()) return;
        for (uint32_t token : it->second) {
            auto clientIt = clients_.find(token);
            if (clientIt == clients_.end()) continue;
            auto obsIt = clientIt->second.observers.find(event.scene);
            if (obsIt == clientIt->second.observers.end()) continue;
            for (auto &entry : obsIt->second) {
                snapshot.emplace_back(entry.proxy, entry.observerId);
            }
        }
    }
    // 锁外：执行回调，避免长时间持锁
    for (auto &[proxy, observerId] : snapshot) {
        proxy->OnEvent(event, observerId);
    }
}
```

> **注意**：`EventManager` 已被确认为死代码，将在本次实现中删除（见 6.16 节）。

**ThrottledEventObserverProxy::OnEvent**（新增 observerId 参数）：
```cpp
void ThrottledEventObserverProxy::OnEvent(const DataMiningEvent &event, int64_t observerId) {
    // 过滤和节流逻辑不变
    if (!ShouldDeliver(event)) return;
    // ...
    // 回调时通过 IPC 传递 observerId
    DataMiningEventObserverProxy proxy(callbackProxy_);
    proxy.OnEventRemote(observerId, event.ToJson());
}
```

**DataMiningEventObserverProxy::OnEventRemote**（新增 observerId 参数）：
```cpp
void OnEventRemote(int64_t observerId, const std::string &eventJson) {
    // IPC MessageParcel:
    //   WriteString(interfaceToken)
    //   WriteInt64(observerId)      ← 新增
    //   WriteString(eventJson)
}
```

**客户端共享 Stub::OnRemoteRequest**（读取 observerId，回调路由）：
```cpp
// OnRemoteRequest: IPC 回调入口
int64_t observerId = data.ReadInt64();
std::string eventJson = data.ReadString();
// 解析 event，调用 callback_(observerId, event)

// 共享 Stub 的回调（所有 observer 共用一个 stub）：
// 1. lock(callbackMutex_) → FindObserverById(observerId) → 复制 shared_ptr
// 2. unlock
// 3. observer->OnEvent(event)  ← 不在锁内执行用户回调
```

### 6.7 PrepareDispatchExecution

- `effectiveTaskId = request.taskId`（非自生成）
- `mode = request.triggerMode`
- 存入 TaskEntry
- 注入 ProgressCallback，绑定 taskId/pipelineName

### 6.8 IPC 方法拆分（IDataMiningService）

| 方法 | 参数类型 | 设计理由 |
|------|---------|---------|
| `Dispatch` | JSON string | SOURCE_DATA/TRIGGER_SOURCE 共享复杂 JSON 结构 |
| `StopPipeline` | scene + taskId | 简单参数，无需 JSON 序列化，类型安全 |
| `RegisterEventCallback` | IRemoteObject | DDMS 注册回调 stub 到 ETL SA，替代 ETLClient |
| `UpdateSubscription` | scene + 2 bool | DDMS 将聚合后的订阅状态同步到 ETL SA |

**DDMS 客户端接口**：

| 方法 | 参数类型 | 设计理由 |
|------|---------|---------|
| `SubscribeEvent` | observerId + scene + optionsJson + IRemoteObject | observerId 由 Client 生成；optionsJson 使用 EventOptions 的 JSON 序列化 |
| `UnsubscribeEvent` | observerId + scene | 使用方传 observer 对象 + scene，客户端内部查找 observerId 后发起 IPC |

好处：类型安全、不共用 DispatchRequest 验证路径、Stub 路由使用 `OnRemoteRequest` 的 `switch/case`。

### 6.9 多 Observer 设计决策

**observerId 由 Client 端生成**：observer 隔离在各自 Client 的 `ClientInfo` 中，不存在跨进程冲突。Client 端使用递增计数器即可。

**客户端侧 DataMiningEventObserver 基类**：客户端定义 observer 基类，使用方继承实现 `OnEvent()` 方法。通过 `std::shared_ptr<DataMiningEventObserver>` 管理生命周期。

**客户端侧重复订阅检测**：重复订阅检测在客户端侧进行。判定规则：同一 scene + 同一 observer 对象（`shared_ptr::get()` 指针比较）不允许重复订阅。同一 scene 可以订阅多个不同的 observer 对象。客户端在发起 IPC 前先检查，如果重复则直接返回错误，不发起 IPC。

**DDMS 侧 ObserverEntry 携带 observerId**：DDMS 侧的 `ObserverEntry` 结构包含 `observerId` 和 `proxy`。回调时通过 IPC MessageParcel 将 observerId 回传给客户端，客户端根据 observerId 路由到对应的 `DataMiningEventObserver` 实例。

**客户端侧共享 Stub（一个 Client 一个 Stub）**：客户端侧所有 observer 共享一个 `DataMiningEventObserverStub`（`sharedStub_`），在首次 `SubscribeEvent` 时懒创建。该 stub 接收 IPC 回调（携带 `observerId`），通过 `FindObserverById()` 查找对应的 observer 对象后回调。好处：DDMS 侧每个 Client（token）只看到一个 `IRemoteObject`，减少 IPC 对象数量；客户端侧也只需管理一个 stub 生命周期。

**回调路由不在锁内执行**：共享 stub 的回调函数在接收到 IPC 回调时，先在锁内查找 observer（复制 `shared_ptr`），再在锁外调用 `observer->OnEvent(event)`。避免在持锁期间执行用户回调，防止死锁和长时间锁占用。

**每个 Client 只有一个 remote 对象**：同一 Client 进程的所有 observer 共享同一个 `sptr<IRemoteObject>`（即 `sharedStub_->AsObject()`）。DDMS 侧的 `ThrottledEventObserverProxy` 各自持有这个 remote 的引用，回调时独立使用。

**回调 notifier 替代 ETLClient**：ETL SA 不依赖 `ETLClient`。DDMS 通过 `RegisterEventCallback` 注册一个 `EventDispatcherStub`（内部持有 `DataMiningEventNotifierStub`）到 ETL SA，ETL SA 通过 `iface_cast` 转型后存储为 `eventNotifier_`。事件上报时通过 `DataMiningEventNotifierProxy` IPC 回调 DDMS，DDMS 内部按 scene 分发给匹配的 `ThrottledEventObserverProxy`。

**DDMS 侧持久化 observer**：observer 注册信息存储在 DDMS 的 `clients_`/`sceneToTokens_` 中，ETL 进程退出/重启不影响 observer。只有 Client 进程退出（DeathRecipient 触发）才清理。

**场景索引**：`sceneToTokens_` 提供 scene → tokenId 的快速查找，避免事件分发时遍历所有 client。

### 6.10 ETL 非常驻进程与 Observer 的关系

ETL 进程不是常驻的，但 observer 的注册和管理完全在 Client ←→ DDMS 之间进行：

| 场景 | 影响 | 处理 |
|------|------|------|
| ETL 退出，无运行中任务 | observer 不受影响 | DDMS 侧 observer 数据不变 |
| ETL 退出，有运行中任务 | 事件中断 | 终止事件由 RuntimeManager 自行生成（超时或 death detection） |
| ETL 重启 | observer 不受影响 | DDMS 重新调用 `RegisterEventCallback` 注册 stub；新任务触发后事件正常分发 |
| Client 退出 | 需清理 observer | DeathRecipient 触发，移除该 token 的 ClientInfo 和 sceneToTokens_ 相关条目 |

ETL SA 的角色仅是事件源（通过 `DataMiningEventNotifierProxy` 上报），不参与 observer 的分发逻辑。ETL SA 不依赖 ETLClient，通过 `eventNotifier_` notifier 回调 DDMS。

### 6.11 DataMiningEventNotifier 接口设计

ETL SA 向 DDMS 上报事件使用独立的 `IDataMiningEventNotifier` IPC 接口（Proxy/Stub 模式），替代了直接创建 `DataMiningEventObserverProxy` 的方式。此设计遵循 RdbNotifier 模式，使事件上报通道与主服务 IPC 分离。

**接口定义**：

```cpp
// data_mining_service/include/client/idata_mining_event_notifier.h
class IDataMiningEventNotifier : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DataMining.IDataMiningEventNotifier");
    virtual int32_t ReportEvent(const std::string &eventJson) = 0;
};
```

**注册流程**：

1. DDMS 在 `SetRuntimeClient` 时创建 `DataMiningEventNotifierStub`（包装 `DispatchEvent` 回调）
2. 通过 `DataMiningClient::RegisterEventCallback(notifierStub->AsRemoteObject())` 注册到 ETL SA
3. ETL SA 在 `RegisterEventCallback` 中通过 `iface_cast<IDataMiningEventNotifier>(callback)` 转型并存储为 `eventNotifier_`

**回调流程**：

```
ETL SA (DataMiningRuntimeManager::ReportEvent)
  → notifier_->ReportEvent(event.ToJson())
  → DataMiningEventNotifierProxy::ReportEvent  [IPC, TF_ASYNC]
  → DataMiningEventNotifierStub::OnRemoteRequest
  → callback_(eventJson)
  → DataMiningEvent::FromJson → manager.DispatchEvent(event)
```

**设计优势**：
- ETL SA 不再直接依赖 `DataMiningEventObserverProxy`（运行时专用类）
- 事件上报通道与主服务 IPC（`IEtlService`）完全分离
- 使用 `TF_ASYNC` 异步发送，ETL SA 不需要等待 DDMS 响应
- DDMS 侧的 `EventDispatcherStub` 更简洁，仅持有 `DataMiningEventNotifierStub`

**移除的接口**：
- `ETLClient::ReportEvent` — 原本用于 ETL SA → DDMS 的公共 API，现已不需要
- `IEtlService::ReportEvent` — 对应的 IPC 接口
- `EtlIpcCode::REPORT_EVENT` — 对应的 IPC 消息码
- `DataMiningServiceImpl::OnReportEvent/ReportEvent` — 对应的服务端实现

<<<<<<< Updated upstream:docs/specs/data-mining-stop-event-ipc-design.md
### 6.14 Proxy 层 Stop/执行并行优化

**问题**：每个 Proxy（SourceProxy、OperatorProxy、SinkProxy）内部使用 `mutex_` 保护插件指针和初始化状态。当前 Trigger/Process/Save 在 `lock(mutex_)` 内部调用底层插件方法，而 Stop() 也需要获取同一把锁来调用 `source_->Stop()` / `op_->Stop()` / `sink_->Stop()`。如果算子正在执行（Trigger/Process/Save 持有锁），Stop() 必须阻塞等待，无法及时中断。

```
当前（串行化）：
Trigger():  lock(mutex_) → source_->Trigger() [长时间阻塞] → unlock
Stop():     lock(mutex_) → [等待 Trigger 释放锁] → source_->Stop()
```

**方案**：`mutex_` 只保护指针和初始化状态，不保护插件调用。锁内拷贝 `shared_ptr`，锁外调用插件方法。

```
优化后（并行）：
Trigger():  lock → EnsureInit → 拷贝 source_ 到 local → unlock → local->Trigger()
Stop():     lock → 拷贝 source_ → initialized_=false → unlock → local->Stop()
```

**具体变更**：

**SourceProxy::Trigger()** — 拆成两段：
```cpp
int32_t SourceProxy::Trigger(shared_ptr<Context> context, shared_ptr<AsyncNotifier> notifier) {
    // 锁内：初始化 + 拷贝指针
    shared_ptr<Source> localSource;
    shared_ptr<TriggerLifecycleNotifier> lifecycleNotifier;
    bool instanceAlive = false;
    {
        lock_guard lock(mutex_);
        int32_t status = EnsureInitializedLocked();
        instanceAlive = source_ != nullptr;
        if (!IsSuccessStatus(status) || source_ == nullptr) {
            // ... error handling
        } else {
            lifecycleNotifier = make_shared<TriggerLifecycleNotifier>(...);
            localSource = source_;  // shared_ptr 拷贝
        }
    }
    // 锁外：调用插件
    int32_t ret;
    if (localSource != nullptr) {
        ret = localSource->Trigger(context, lifecycleNotifier);
    } else {
        ret = ...; // error
    }
    // ... lifecycleNotifier handling
}
```

**SourceProxy::Stop()** — 同样拆成两段：
```cpp
int32_t SourceProxy::Stop() {
    shared_ptr<Source> local;
    {
        lock_guard lock(mutex_);
        initialized_ = false;
        local = source_;
    }
    if (local == nullptr) return E_OK;
    return local->Stop();  // 锁外调用
}
```

**OperatorProxy::Process()** 和 **SinkProxy::Save()** 同理：锁内拷贝 `op_`/`sink_` 到局部变量，锁外调用。

**安全性分析**：
- `shared_ptr` 拷贝保证插件实例在调用期间不被析构（即使 Stop 后触发了 library reload 回调清空 `source_`）
- `initialized_` 标志被 Stop 设为 false，下次 Trigger 会重新初始化
- 底层插件的 Trigger 和 Stop 可以并行执行（由插件实现保证线程安全）
- library reload 回调仍受 `mutex_` 保护，不会在执行期间清空指针

**SourceProxy::Subscribe()** 同样适用此优化。

### 6.15 Source 批次处理：ProgressCallback 注册与进度驱动

**问题**：PipelineRuntime 内部循环处理多批数据时，进度需要每批回调一次，但完成事件只在最后触发一次。需要正确串联 PipelineRuntime 的 `ProgressCallback` 和 RuntimeManager 的 `OnSourceBatchComplete`。

**方案**：在 `PrepareDispatchExecution` 中，当 `taskId != 0` 时给 runtime 注册 `ProgressCallback`：

```cpp
// PrepareDispatchExecution 中
if (execution.taskId != 0) {
    execution.runtime->SetProgressCallback(
        [this, taskId](int64_t, const std::string &pipelineName,
                       const std::string &sourceName,
                       int64_t finishCount, int64_t totalCount) {
            OnSourceBatchComplete(taskId, pipelineName, sourceName, finishCount, totalCount);
        });
}
```

**进度回调路径**：
1. PipelineRuntime 每批完成后调用 `progressCallback_(finishCount, totalCount)`
2. 回调触发 `OnSourceBatchComplete(taskId, pipelineName, sourceName, finishCount, totalCount)`
3. `OnSourceBatchComplete` 更新 TaskEntry 的 sourceProgresses，并通过 `ReportEvent` 上报 PROGRESS 事件

**完成事件路径**：
- `onAsyncComplete` 只在全部批次完成时被调用一次
- 回调内执行 `lifecycleTracker_.FinishDispatch` + `NotifyDispatchComplete`（发送最终 SUCCESS/FAILURE 事件）
- 移除 `onAsyncComplete` 内原有的 `OnSourceBatchComplete(taskId, ..., 0, 0)` 冗余调用，因为进度已通过 `ProgressCallback` 驱动

**向后兼容**：
- `GetRemainDataCount()` 默认返回 0，现有 Source 不进入批次循环
- 不进入循环时行为与改造前完全一致（单次 Trigger → 单次完成回调）

**注意**：`PrepareDispatchExecution` 中每次 Dispatch 都会 `SetProgressCallback`，覆盖之前注册的回调。这是预期行为——同一 PipelineRuntime 的并发 Dispatch 通过 `instanceId` 隔离，每个 Dispatch 路径绑定各自的 taskId。如果 Pipeline 复用时 taskId 不同，回调自然切换到新的 lambda（捕获新的 taskId）。

### 6.16 EventManager 死代码清理

**现状**：`EventManager` 类（`datamgr_service/.../data_mining/include/event_manager.h`）是旧的 observer 管理，已被 `DataMiningManager` 的 `clients_` / `sceneToTokens_` 系统完全取代。

**死代码证据**：
- `Subscribe()`、`Unsubscribe()`、`OnEvent()` 从未被调用
- `observers_` 始终为空，因此 `HasObserversForScene()` 永远返回 `false`
- `OnEtlSaDied()` 无法发送任何事件（`activeTaskIds_` 有数据但 `observers_` 为空）
- `event_manager.cpp` **不在 BUILD.gn 的 sources 列表中**（已不参与编译）

**DataMiningServiceImpl 中的 3 处引用需迁移**：

| 引用位置 | 当前代码 | 迁移方案 |
|---------|---------|---------|
| `OnInitialize()` | 创建 `eventManager_` + 注册 SA 死亡回调 | 删除 `eventManager_` 创建；SA 死亡回调直接在 `DataMiningManager` 中处理（已有 `DispatchEvent` 能力） |
| `TriggerPipelineByScene()` | `eventManager_->AddActiveTask(scene, taskId, mode)` | 活跃任务跟踪已在 ETL SA 侧的 `DataMiningRuntimeManager::taskEntries_` 中管理，DDMS 侧不需要重复跟踪；直接删除 |
| `PushSubscriptionState()` | `eventManager_->HasObserversForScene(scene)` / `HasProgressObserversForScene()` | 改为从 `DataMiningManager` 的 `sceneToTokens_` / `clients_` 计算聚合结果（已有 `RecalcSubscriptionCache` 基础设施） |

**删除文件清单**：

| 文件 | 操作 |
|------|------|
| `datamgr_service/.../data_mining/include/event_manager.h` | **删除** |
| `datamgr_service/.../data_mining/src/event_manager.cpp` | **删除** |
| `datamgr_service/.../data_mining/test/event_manager_test.cpp` | **删除** |
| `datamgr_service/.../data_mining/data_mining_service_impl.h` | 移除 `#include "event_manager.h"` 和 `eventManager_` 成员 |
| `datamgr_service/.../data_mining/data_mining_service_impl.cpp` | 移除 3 处 `eventManager_` 引用；`PushSubscriptionState` 改为调用 `DataMiningManager` 方法 |

**PushSubscriptionState 迁移**：

```cpp
// 迁移前（使用 EventManager）
void DataMiningServiceImpl::PushSubscriptionState(const std::string &scene)
{
    if (scene.empty() || eventManager_ == nullptr) return;
    bool hasSubscriber = eventManager_->HasObserversForScene(scene);
    bool hasProgressSubscriber = eventManager_->HasProgressObserversForScene(scene);
    manager_->PushSubscriptionState(scene, hasSubscriber, hasProgressSubscriber);
}

// 迁移后（使用 DataMiningManager 的聚合数据）
void DataMiningServiceImpl::PushSubscriptionState(const std::string &scene)
{
    // RecalcSubscriptionCache 已在 Subscribe/Unsubscribe 时被调用，
    // 订阅状态已通过 UpdateSubscriptionCache → UpdateSubscription IPC 推送到 ETL SA。
    // DDMS 侧 PushSubscriptionState 不再需要。
}
```

实际上 `PushSubscriptionState` 的调用时机是在 `DataMiningManager::SubscribeEvent` / `UnsubscribeEvent` 内部已经通过 `RecalcSubscriptionCache` → `UpdateSubscriptionCache` 完成了对 ETL SA 的推送。因此 `DataMiningServiceImpl::PushSubscriptionState` 可以整体删除或改为空实现。
=======
### 6.12 Stop 后重新触发

**问题**：旧实现中 `Stop()` 只设置 `stopping_=true`，不移除 runtime，也不清理 task entry。后续同 pipeline 的 Trigger/Dispatch 通过 `runtimes_` map 复用已停止的 runtime，因 `stopping_==true` 被拒绝（返回 `E_INVALID_STATE`），导致无法重新触发。

**解决方案**：Stop 后立即清理 runtime 和 task entry，下次触发时创建新 runtime 实例。

**触发链路分析**：

```
Stop(scene, taskId)
  → [Lock] 收集 runtime + pipelineName + 事件数据
  → [Lock] taskEntries_.erase(taskId)   ← 先删，防双事件
  → [Unlock]
  → runtime->Stop()                     // 设置 stopping_=true
  → ReportEvent(INTERRUPT)              // 通知订阅方
  → [Lock] runtimes_.erase(name)        // 移除 runtime
  → [Unlock]

下次 Trigger(scene, pipeline, ..., newTaskId)
  → AcquireRuntimeForDispatch
    → runtimes_.find(name) → null（已移除）
    → BuildRuntime(name)   // 创建全新 PipelineRuntime 实例
  → PrepareDispatchExecution
    → taskEntries_[newTaskId] = { ... }  // 新 task entry
  → ExecuteDispatch        // 正常执行
```

**关键点**：
- `AcquireRuntimeForDispatch` 本身已支持 runtime 不存在时自动走 `BuildRuntime` 创建，无需修改 Dispatch 路径
- `PipelineRuntime` 不需要 Reset 方法，每次创建全新实例
- 同一个 runtime（pipeline name）可能被多个 task entry 引用，从 `runtimes_` 移除时需检查引用计数

**测试要点**：
1. Stop 后同 taskId 重新触发 → 创建新 runtime → 成功执行
2. Stop 后不同 taskId 触发同 pipeline → 创建新 runtime → 成功执行
3. Stop(scene, 0) 停止所有后重新触发 → 成功
4. Stop 时 INTERRUPT 事件正确发出（含 scene、taskId、triggerMode）

### 6.13 Stop 并发安全：防止双事件

**竞态场景**：`Stop()` 和异步完成回调（`OnSourceBatchComplete`）竞争同一个 taskEntry，都试图发出终止事件。

**两条竞争路径**：

```
路径 A — Stop():
  [Lock]  收集事件数据 + pipelineName
  [Lock]  taskEntries_.erase(taskId)     ← 关键：先删除
  [Unlock]
  runtime->Stop()
  ReportEvent(INTERRUPT)

路径 B — 异步回调 → OnSourceBatchComplete():
  [Lock]  taskEntries_.find(taskId)
  [Lock]  if (not found) → return       ← Stop 已删 → 跳过
  [Lock]  收集数据 + erase + shouldEmit
  [Unlock]
  ReportEvent(SUCCESS/FAILURE)
```

**保证**：taskEntry 的 erase 在锁内完成，与 find 原子互斥。先 erase 的一方"赢得"发事件权。

| 时序 | 结果 | 事件 |
|------|------|------|
| Stop 先拿锁 → erase → 回调后 find 为空 | Stop 发 INTERRUPT，回调跳过 | 单次 INTERRUPT |
| 回调先拿锁 → erase + 发事件 → Stop find 为空 | 回调发 SUCCESS/FAILURE，Stop 返回 E_NOT_FOUND | 单次 SUCCESS/FAILURE |
| Stop 被调用两次同 taskId | 第一次 erase 成功，第二次 E_NOT_FOUND | 单次 INTERRUPT |

**Stop(scene, 0) 场景**：锁内遍历所有匹配的 taskEntry 并逐个 erase。异步回调对每个 taskId 独立判断，互不影响。
>>>>>>> Stashed changes:claude/docs/specs/data-mining-stop-event-ipc-design.md

---

## 7. Mock 环境支持

demo 插件通过 `DATA_MINING_REGISTER_MODULE` 宏（`__attribute__((constructor))`）在程序启动时自动注册到 `PluginRegistry`。Mock dlopen 需要对 demo 插件返回有效 handle，使 `PluginLoader::Acquire` 能正常走 dlopen → GetModule 流程。

### 7.1 g_libraryMappings 扩展

**文件**: `mock/src/mock_dlfcn.cpp`

```cpp
const LibraryMapping g_libraryMappings[] = {
    // 现有映射 ...

    // Data Mining demo 插件
    { "libdemo_timer_source_plugin", "demo_timer_source_plugin", false },
    { "libdemo_log_sink_plugin", "demo_log_sink_plugin", false },
    { "libdemo_normalize_operator_plugin", "demo_normalize_operator_plugin", false },
    { "libdemo_nested_source_plugin", "demo_nested_source_plugin", false },
    { "libdemo_flatten_operator_plugin", "demo_flatten_operator_plugin", false },
    { "libdemo_audit_sink_plugin", "demo_audit_sink_plugin", false },
    { "libdemo_fail_sink_plugin", "demo_fail_sink_plugin", false },
    { "libdemo_subscribe_source_plugin", "demo_subscribe_source_plugin", false },
    { "libdemo_extension_plugin", "demo_extension_plugin", false },

    { nullptr, nullptr, false }
};
```

### 7.2 Sentinel Handle

当 `LoadNativeLibrary` 返回 nullptr 但请求的文件名匹配 demo 插件模式时，返回 sentinel handle：

```cpp
static char g_sentinel = 0;

if (realHandle == nullptr && requestedName.find("demo_") != std::string::npos
    && requestedName.find("_plugin") != std::string::npos) {
    g_realHandles[actualPath] = &g_sentinel;
    g_handleToLib[&g_sentinel] = actualPath;
    return &g_sentinel;
}
```

安全性：`PluginLoader::Acquire` 在 dlopen 成功后只调用 `PluginRegistry::GetModule`，不调用 `dlsym`。

### 7.3 使用前提

1. demo 插件 .cpp 文件编译进测试可执行文件（触发 constructor 注册）
2. 通过 Dispatch 传递 plugins + pipeline 配置
3. `PluginLoader::Acquire` 正常走 dlopen → GetModule 流程

---

## 8. 测试设计

### 8.1 测试策略

- **Client 测试**：通过 `DataMiningClient` 构造真实的 Proxy → Stub → Service 链路，验证 IPC 序列化/反序列化
- **Service 测试**：直接操作 `DataMiningService` 实例，验证 SA 层委托到 RuntimeManager
- **RuntimeManager 测试**：直接操作 `DataMiningRuntimeManager`，验证核心逻辑
- **Demo E2E 测试**：通过 demo 插件跑完整链路

### 8.2 测试原则

1. 优先实现不需要预设状态的用例
2. 需要预设状态的场景通过公共接口（Dispatch/Stop/SubscribeEvent/UnsubscribeEvent）间接达成
3. 验证行为输出（返回值、副作用），而非验证内部状态
4. 不直接访问私有成员

### 8.3 Mock 更新

| 文件 | 变更 |
|------|------|
| `data_mining_service/test/runtime/mock_helpers.h` | MockSource: `OnStop()` → `Stop()`；MockOperator/MockSink 新增 `Stop()`；MockSource 新增 `GetRemainDataCount()` 可重写 |
| `data_mining_service/test/runtime/pipeline_runtime_test_utils.h` | TrackingSource/Operator/Sink 新增 `Stop()`；`MakeMinimalTriggerDispatchRequest` 已有（增加 taskId 参数支持） |

### 8.4 测试工具函数

`pipeline_runtime_test_utils.h` 中已有 `MakeMinimalTriggerDispatchRequest`（构造包含 demo_timer_source → demo_log_sink 的最小 DispatchRequest），支持 taskId 参数。

```cpp
inline DispatchRequest MakeMinimalTriggerDispatchRequest(
    const std::string &pipelineName = "test_pipeline",
    const std::string &fromNode = "source_node",
    const std::string &sceneName = "test_scene",
    int64_t taskId = 0);
```

### 8.5 Client 测试 (`data_mining_service/test/client/data_mining_client_test.cpp`)

构造真实 Proxy → Stub → Service IPC 链路。

| # | 测试用例 | 描述 |
|---|---------|------|
| 1 | `StopPipeline_ThroughIpcChain001` | Service 预注册 runtime + task entry，`client->StopPipeline("scene", 42)` → E_OK |
| 2 | `StopPipeline_NotFoundThroughIpc002` | 不注册 task entry，`client->StopPipeline("unknown", 9999)` → E_NOT_FOUND |
| 3 | `SubscribeEvent_ThroughIpcChain003` | `client->SubscribeEvent(1, "scene", optionsJson)` → E_OK，验证 observer 被注册 |
| 4 | `UnsubscribeEvent_ThroughIpcChain004` | 先 Subscribe 再 `client->UnsubscribeEvent(1, "scene")` → E_OK |
| 5 | `RegisterEventCallback_ThroughIpcChain005` | `client->RegisterEventCallback(stub)` → E_OK，验证 eventNotifier_ 已设置 |
| 6 | `UpdateSubscription_ThroughIpcChain006` | `client->UpdateSubscription("scene", true, true)` → E_OK |
| 7 | `NewMethods_NullService_ReturnsInvalidState007` | 通过 SAMGR 取消注册 SA，各方法 → E_INVALID_STATE |
| 8 | `DispatchSucceedsThroughClient` | 通过 `client_->Dispatch(request)` 传递完整配置 → E_OK |
| 9 | `SubscribeEvent_MultipleObservers008` | 同一 scene 注册多个 observer（不同 id），验证均被注册 |
| 10 | `SubscribeEvent_DifferentScenes009` | 同一 Client 注册不同 scene 的 observer，验证独立管理 |

### 8.6 Service 测试 (`data_mining_service/test/data_mining_service_test.cpp`)

直接构造 `DataMiningService` 实例，需要预设状态的用例通过 Dispatch 间接达成。

| # | 测试用例 | 描述 |
|---|---------|------|
| 1 | `StopPipeline_DelegatesToManager001` | 先 Dispatch（taskId=42 + demo 插件配置），再 `StopPipeline("scene", 42)` → E_OK |
| 2 | `StopPipeline_ReturnsNotFound002` | `service.StopPipeline("unknown", 9999)` → E_NOT_FOUND |
| 3 | `StopPipeline_CancelIdleOnNewRequest003` | 验证 `CancelIdle()` 被触发 |
| 4 | `RegisterEventCallback_DelegatesToManager004` | `RegisterEventCallback(stub)` 后 `ReportEvent()` 通过 stub 回调验证事件被分发 |
| 5 | `UpdateSubscription_DelegatesToManager005` | `UpdateSubscription("scene", true, true)` 后 `ReportEvent()` 验证行为 |
| 6 | `ReportEvent_UsesCallbackStub006` | 先 `RegisterEventCallback(stub)`，再触发事件 → 验证通过 stub 回调 |
| 7 | `ReportEvent_NoCallbackStub_Skips007` | 不注册 stub，触发事件 → 不崩溃，跳过回调 |
| 8 | `Dispatch_NoLongerHandlesStopPipeline008` | DispatchRequest kind=2 → E_INVALID_ARGUMENT |
| 9 | `Dispatch_NoLongerHandlesUpdateSubscription009` | DispatchRequest kind=4 → E_INVALID_ARGUMENT |
| 10 | `DispatchSucceedsWithValidPipeline010` | 完整 DispatchRequest（TRIGGER_SOURCE + demo 插件）→ E_OK |
| 11 | `DispatchSucceedsWithSourceData011` | SOURCE_DATA DispatchRequest，验证数据流经 pipeline |
| 12 | `DumpDataMiningInfoSkipsWhenServiceStopped` | 不调用 `OnStart()`，Dump 无输出 |
| 13 | `DumpDataMiningInfoPrintsHeaderWhenRunning` | 调用 `OnStart()`，Dump 有输出 |
| 14 | `SubscribeEvent_MultipleObserversDifferentOptions012` | 同一 scene 注册两个 observer（一个有进度一个无），验证独立过滤 |
| 15 | `SubscribeEvent_RecalcSubscriptionCache013` | Subscribe/Unsubscribe 后验证聚合的订阅状态正确更新 |

### 8.7 Stub 序列化测试（内联到 service_test）

验证 `OnRemoteRequest` 的 code 路由和 MessageParcel 序列化：

| # | 测试用例 | 描述 |
|---|---------|------|
| 1 | `OnRemoteRequest_StopPipeline_Code1` | MessageParcel: token + sceneName + taskId(42) → OnRemoteRequest(1) |
| 2 | `OnRemoteRequest_RegisterEventCallback_Code2` | MessageParcel: token + IRemoteObject → OnRemoteRequest(2) → E_OK |
| 3 | `OnRemoteRequest_UpdateSubscription_Code3` | MessageParcel: token + scene + hasSubscriber(true) + hasProgressSubscriber(true) → OnRemoteRequest(3) → E_OK |
| 4 | `OnRemoteRequest_UnknownCode_ReturnsError` | OnRemoteRequest(99) → -1 |
| 5 | `OnRemoteRequest_InvalidToken_ReturnsError` | code 0-3 分别用错误 token → 均返回 -1 |

### 8.8 RuntimeManager 测试 (`data_mining_runtime_manager_test.cpp`)

预设状态通过 Dispatch 传递 plugins + pipeline + taskId 间接达成。

**修改现有测试：**

| # | 测试用例 | 描述 |
|---|---------|------|
| 1 | `DispatchWithStopPipeline_RoutesToStop023` | 改为直接调用 `manager.Stop("dispatch_scene", 77)`，验证 runtime 停止，task entry 已清理，runtime 从 runtimes_ 移除 |

**新增测试：**

| # | 测试用例 | 描述 |
|---|---------|------|
| 2 | `Stop_WithValidTaskId_StopsRuntime001` | `manager.Stop(scene, taskId)` → runtime `stopping_` 为 true，task entry 已清理，runtime 从 runtimes_ 移除 |
| 3 | `Stop_WithUnknownTaskId_ReturnsNotFound002` | `manager.Stop("", 9999)` → E_NOT_FOUND |
| 4 | `Stop_WithWrongSceneName_ReturnsInvalidArgument003` | 注册 scene "A"，`manager.Stop("B", taskId)` → E_INVALID_ARGUMENT |
| 5 | `Stop_WithZeroTaskId_StopsAllMatchingScene004` | 同 scene 多个 task entries，`manager.Stop(scene, 0)` → 所有 runtimes 停止且清理 |
| 6 | `Dispatch_RejectsOldStopPipelineKind005` | DispatchRequest kind=2 → E_INVALID_ARGUMENT |
| 7 | `Dispatch_RejectsOldUpdateSubscriptionKind006` | DispatchRequest kind=4 → E_INVALID_ARGUMENT |
| 8 | `Stop_EmitsInterruptEvent007` | 预设订阅状态，`manager.Stop(scene, taskId)` → 验证通过 notifier 发出 INTERRUPT 事件（含正确 scene、taskId、triggerMode） |
| 9 | `Stop_ThenRetrigger_CreatesNewRuntime008` | 先 Dispatch（taskId=A），Stop(scene, A)，再 Dispatch（taskId=B）→ 新 runtime 创建，执行成功 |
| 10 | `Stop_ThenRetrigger_SameTaskId009` | 先 Dispatch（taskId=A），Stop(scene, A），再 Dispatch（taskId=A）→ 新 runtime 创建，执行成功 |
| 11 | `Stop_WithZeroTaskId_ThenRetrigger010` | 先 Dispatch 多个 task，Stop(scene, 0)，再 Dispatch 新 task → 新 runtime 创建，执行成功 |
| 12 | `Stop_DoubleStopSameTaskId_NoDoubleEvent011` | Stop(scene, taskId) 后再次 Stop(scene, taskId) → 第二次返回 E_NOT_FOUND，仅一次 INTERRUPT 事件 |
| 13 | `Stop_AsyncCompletionRace_NoDoubleEvent012` | 预设订阅 + 同步 source（立即完成），Dispatch 后立即 Stop → 验证仅一次事件（SUCCESS 或 INTERRUPT，不重复） |

### 8.9 Event/Subscription 测试 (`event_report_test.cpp`)

直接测试 `DataMiningRuntimeManager::UpdateSubscriptionCache()`。方法签名和行为不变。无需修改。

**关键测试场景：**

- **终止事件链**：Stop → ReportEvent(INTERRUPT) → 清理 runtime + task entry；自然完成 → SUCCESS；失败 → FAILURE；混合 → FAILURE
- **triggerMode 链**：DDMS Dispatch with triggerMode → ETL SA stores → event carries triggerMode
- **Progress 链**：Source batch complete → ProgressCallback → OnSourceBatchComplete → PROGRESS event；无进度订阅者 → skip IPC；多 source 聚合
- **Subscription 过滤**：hasSubscriber=false → skip all；hasProgressSubscriber=false → skip PROGRESS

### 8.10 Source 批次处理测试

#### 8.10.1 测试工具类（pipeline_runtime_test_utils.h 新增）

```cpp
// 可配置的批次 Source，用于测试批次循环逻辑
class TrackingBatchSource final : public Source {
public:
    TrackingBatchSource(int64_t totalCount, int64_t batchSize)
        : totalCount_(totalCount), batchSize_(batchSize), current_(0) {}

    std::string GetName() const override { return "TrackingBatchSource"; }
    int32_t OnInitialize() override { return E_OK; }  // 由 SourceProxy 内部调用

    int32_t Trigger(std::shared_ptr<Context> context, std::shared_ptr<AsyncNotifier> notifier) override
    {
        ++triggerCount_;
        if (triggerStatus_ != E_OK) {
            return triggerStatus_;
        }
        if (notifier == nullptr) {
            return E_INVALID_ARGUMENT;
        }
        int64_t count = std::min(batchSize_, totalCount_ - current_);
        auto batch = MakeMultiRecordBatch(count);
        current_ += count;
        batchCounts_.push_back(count);
        return notifier->Notify(context, "batch.topic", batch);
    }

    int64_t GetRemainDataCount() override { return totalCount_ - current_; }

    int32_t Subscribe(const std::string &, std::shared_ptr<Context>,
        std::shared_ptr<AsyncNotifier>) override { return E_OK; }
    int32_t Unsubscribe(const std::string &, std::shared_ptr<Context>) override { return E_OK; }
    int32_t Stop() override { ++stopCount_; return E_OK; }

    // 跟踪状态
    int32_t triggerStatus_ = E_OK;
    int32_t triggerCount_ = 0;
    int32_t stopCount_ = 0;
    int64_t current_ = 0;
    std::vector<int64_t> batchCounts_;  // 每批实际推送的条数

private:
    int64_t totalCount_;
    int64_t batchSize_;
};

// 创建包含 N 条记录的 RecordBatch
inline std::shared_ptr<RecordBatch> MakeMultiRecordBatch(int64_t count)
{
    auto schema = Schema::Create({ { "value", FieldType::INT32 } });
    auto batch = RecordBatch::Create(schema);
    for (int64_t i = 0; i < count; ++i) {
        auto record = Record::Create(schema);
        record->SetInt32("value", static_cast<int32_t>(i));
        batch->Append(record);
    }
    return batch;
}
```

#### 8.10.2 PipelineRuntime 批次处理测试（pipeline_runtime_test.cpp）

所有测试使用 `PipelineRuntimeFacadeTest` fixture，直接构造 runtime 并手动填充节点。

| # | 测试用例 | 描述 |
|---|---------|------|
| 1 | `BatchProcessing_TriggersMultipleBatchesUntilComplete021` | TrackingBatchSource(100, 30)：验证 Trigger 被调用 4 次（30+30+30+10），最终 GetRemainDataCount()=0 |
| 2 | `BatchProcessing_ProgressCallbackFiredPerBatch022` | 注册 ProgressCallback，验证每批触发一次，finishCount 依次为 30/60/90/100，totalCount 动态计算（100） |
| 3 | `BatchProcessing_CompletionCallbackFiredOnce023` | 传入 onAsyncComplete 回调，验证只在全部批次完成后触发一次，status=E_OK |
| 4 | `BatchProcessing_StoppingBreaksLoop024` | 在 ProgressCallback 中第二次调用时执行 runtime->Stop()，验证只处理了 2 批后循环中断，onAsyncComplete 仍被调用 |
| 5 | `BatchProcessing_DefaultGetRemainDataCountNoLoop025` | 使用 TrackingSource（GetRemainDataCount 默认返回 0），验证行为不变：单次 Trigger、单次完成回调、triggerCount=1 |
| 6 | `BatchProcessing_TriggerErrorBreaksLoop026` | 第三批时 triggerStatus_=E_ERROR，验证循环中断，onAsyncComplete 收到错误状态 |
| 7 | `BatchProcessing_SingleBatchNoProgressCallback027` | TrackingBatchSource(10, 10)：只有 1 批，验证 GetRemainDataCount()=0，不进入循环的下一次迭代，ProgressCallback 触发一次（最后一批也触发） |
| 8 | `BatchProcessing_ExactMultipleBatches028` | TrackingBatchSource(90, 30)：恰好 3 批，验证 Trigger 调用 3 次，无余量批次 |
| 9 | `BatchProcessing_LargeBatchCoversAll029` | TrackingBatchSource(50, 100)：batchSize > totalCount，单批处理完毕，GetRemainDataCount() 立即返回 0 |
| 10 | `BatchProcessing_BatchSizeOne030` | TrackingBatchSource(3, 1)：每批 1 条，验证 Trigger 调用 3 次，ProgressCallback 每次触发，finishCount 依次 1/2/3 |
| 11 | `BatchProcessing_DAGExecutesPerBatch031` | Source → Operator → Sink 链路，TrackingOperator/TrackingSink，验证每批 DAG 完整执行（processCount/saveCount 随批次递增） |
| 12 | `BatchProcessing_EmptySourceNoLoop032` | TrackingBatchSource(0, 10)：totalCount=0，GetRemainDataCount() 始终返回 0，验证 Trigger 不被调用，onAsyncComplete 被调用 |

#### 8.10.3 测试用例伪代码示例

**用例 1** — `BatchProcessing_TriggersMultipleBatchesUntilComplete021`：

```cpp
HWTEST_F(PipelineRuntimeFacadeTest, BatchProcessing_TriggersMultipleBatchesUntilComplete021, TestSize.Level1)
{
    auto runtime = std::make_shared<PipelineRuntime>(MakeManager());
    auto source = std::make_shared<TrackingBatchSource>(100, 30);  // 100 条，每批 30
    runtime->nodes_["batch_source"] = MakeSourceRuntimeNode("batch_source", source);
    runtime->topoOrder_ = { "batch_source" };
    RefreshRuntimeSnapshot(runtime);

    auto result = runtime->TriggerSourceTracked("batch_source", MakeContext(), "inst_1");
    EXPECT_EQ(result.status, E_OK);
    EXPECT_EQ(source->triggerCount_, 4);        // 30+30+30+10
    EXPECT_EQ(source->GetRemainDataCount(), 0);
    EXPECT_EQ(source->batchCounts_.size(), 4U);
    EXPECT_EQ(source->batchCounts_[0], 30);
    EXPECT_EQ(source->batchCounts_[1], 30);
    EXPECT_EQ(source->batchCounts_[2], 30);
    EXPECT_EQ(source->batchCounts_[3], 10);      // 最后一批余量
}
```

**用例 2** — `BatchProcessing_ProgressCallbackFiredPerBatch022`：

```cpp
HWTEST_F(PipelineRuntimeFacadeTest, BatchProcessing_ProgressCallbackFiredPerBatch022, TestSize.Level1)
{
    auto runtime = std::make_shared<PipelineRuntime>(MakeManager());
    auto source = std::make_shared<TrackingBatchSource>(100, 30);
    runtime->nodes_["batch_source"] = MakeSourceRuntimeNode("batch_source", source);
    runtime->topoOrder_ = { "batch_source" };
    RefreshRuntimeSnapshot(runtime);

    std::vector<std::pair<int64_t, int64_t>> progressCalls;  // (finishCount, totalCount)
    runtime->SetProgressCallback([&](int64_t, const std::string &, const std::string &,
        int64_t finishCount, int64_t totalCount) {
        progressCalls.push_back({finishCount, totalCount});
    });

    runtime->TriggerSourceTracked("batch_source", MakeContext(), "inst_1");

    ASSERT_EQ(progressCalls.size(), 4U);
    EXPECT_EQ(progressCalls[0].first, 30);    // finishCount
    EXPECT_EQ(progressCalls[0].second, 100);  // totalCount = 30 + 70(remain)
    EXPECT_EQ(progressCalls[1].first, 60);
    EXPECT_EQ(progressCalls[1].second, 100);
    EXPECT_EQ(progressCalls[2].first, 90);
    EXPECT_EQ(progressCalls[2].second, 100);
    EXPECT_EQ(progressCalls[3].first, 100);
    EXPECT_EQ(progressCalls[3].second, 100);
}
```

**用例 3** — `BatchProcessing_CompletionCallbackFiredOnce023`：

```cpp
HWTEST_F(PipelineRuntimeFacadeTest, BatchProcessing_CompletionCallbackFiredOnce023, TestSize.Level1)
{
    auto runtime = std::make_shared<PipelineRuntime>(MakeManager());
    auto source = std::make_shared<TrackingBatchSource>(100, 30);
    runtime->nodes_["batch_source"] = MakeSourceRuntimeNode("batch_source", source);
    runtime->topoOrder_ = { "batch_source" };
    RefreshRuntimeSnapshot(runtime);

    int32_t completionCount = 0;
    PipelineRuntime::ExecutionResult completionResult;
    auto result = runtime->TriggerSourceTracked("batch_source", MakeContext(), "inst_1",
        [&](const PipelineRuntime::ExecutionResult &r) {
            ++completionCount;
            completionResult = r;
        });

    // 同步 Source：onAsyncComplete 在 TriggerSourceTracked 内部循环结束后调用
    EXPECT_EQ(completionCount, 1);
    EXPECT_EQ(completionResult.status, E_OK);
}
```

**用例 4** — `BatchProcessing_StoppingBreaksLoop024`：

```cpp
HWTEST_F(PipelineRuntimeFacadeTest, BatchProcessing_StoppingBreaksLoop024, TestSize.Level1)
{
    auto runtime = std::make_shared<PipelineRuntime>(MakeManager());
    auto source = std::make_shared<TrackingBatchSource>(100, 30);
    runtime->nodes_["batch_source"] = MakeSourceRuntimeNode("batch_source", source);
    runtime->topoOrder_ = { "batch_source" };
    RefreshRuntimeSnapshot(runtime);

    int32_t batchIndex = 0;
    runtime->SetProgressCallback([&](int64_t, const std::string &, const std::string &,
        int64_t, int64_t) {
        ++batchIndex;
        if (batchIndex == 2) {
            runtime->Stop();  // 第二批完成后触发停止
        }
    });

    auto result = runtime->TriggerSourceTracked("batch_source", MakeContext(), "inst_1");
    // 第二批完成后 IsStopping() 检查为 true，跳出循环
    EXPECT_EQ(source->triggerCount_, 2);  // 只处理了 2 批
    EXPECT_TRUE(runtime->IsStopping());
}
```

**用例 5** — `BatchProcessing_DefaultGetRemainDataCountNoLoop025`：

```cpp
HWTEST_F(PipelineRuntimeFacadeTest, BatchProcessing_DefaultGetRemainDataCountNoLoop025, TestSize.Level1)
{
    auto runtime = std::make_shared<PipelineRuntime>(MakeManager());
    auto source = std::make_shared<TrackingSource>();  // 默认 GetRemainDataCount() 返回 0
    runtime->nodes_["source_node"] = MakeSourceRuntimeNode("source_node", source);
    runtime->topoOrder_ = { "source_node" };
    RefreshRuntimeSnapshot(runtime);

    auto result = runtime->TriggerSourceTracked("source_node", MakeContext(), "inst_1");
    EXPECT_EQ(result.status, E_OK);
    EXPECT_EQ(source->triggerCount_, 1);  // 行为不变：单次 Trigger
}
```

**用例 11** — `BatchProcessing_DAGExecutesPerBatch031`：

```cpp
HWTEST_F(PipelineRuntimeFacadeTest, BatchProcessing_DAGExecutesPerBatch031, TestSize.Level1)
{
    auto runtime = std::make_shared<PipelineRuntime>(MakeManager());
    auto source = std::make_shared<TrackingBatchSource>(60, 20);  // 3 批
    auto op = std::make_shared<TrackingOperator>();
    auto sink = std::make_shared<TrackingSink>();

    runtime->nodes_["src"] = MakeSourceRuntimeNode("src", source);
    runtime->nodes_["op"] = MakeOperatorRuntimeNode("op", op);
    runtime->nodes_["sink"] = MakeSinkRuntimeNode("sink", sink);
    runtime->parents_["op"] = { "src" };
    runtime->parents_["sink"] = { "op" };
    runtime->topoOrder_ = { "src", "op", "sink" };
    RefreshRuntimeSnapshot(runtime);

    auto result = runtime->TriggerSourceTracked("src", MakeContext(), "inst_1");
    EXPECT_EQ(result.status, E_OK);
    EXPECT_EQ(source->triggerCount_, 3);
    EXPECT_EQ(op->processCount_, 3);    // 每批 DAG 都经过 Operator
    EXPECT_EQ(sink->saveCount_, 3);     // 每批 DAG 都到达 Sink
}
```

### 8.11 Demo E2E 测试 (`data_mining_service/test/demo/etl_demo_test.cpp`)

在 `EtlSaDemoTest` fixture 上新增：

| # | 测试用例 | 描述 |
|---|---------|------|
| 1 | `ServiceStopPipeline_StopsRunningDemoPipeline001` | Dispatch 触发 → Stop 停止 → 验证 runtime 从 runtimes_ 移除，task entry 清理 |
| 2 | `ServiceSubscribeEvent_ForDemoScene002` | SubscribeEvent → 验证 observer 注册成功，事件可被分发 |
| 3 | `ServiceFullCycle_TriggerThenSubscribeThenStop003` | 完整生命周期：Trigger → SubscribeEvent → Stop → 验证 INTERRUPT 事件发出 |
| 4 | `ServiceReportEvent_WithSubscriptionEnabled004` | 预设 SubscribeEvent → ReportEvent → 验证无错误 |
| 5 | `ServiceSubscribeEvent_MultipleObservers005` | 同一 scene 多个 observer，验证各自独立过滤 |
| 6 | `ServiceStop_ThenRetrigger_CreatesNewRuntime006` | Dispatch 触发 → Stop → 再次 Dispatch → 新 runtime 创建，成功执行 |

### 8.12 ETL 层测试

| 文件 | 变更 |
|------|------|
| `data_mining/test/unittest/etl_service_proxy_test.cpp` | 新增 StopPipeline 测试 |
| `data_mining/test/unittest/etl_client_test.cpp` | 新增 StopPipeline 测试 + TriggerPipeline 返回 taskId 测试 |
| `data_mining/test/unittest/data_mining_event_observer_test.cpp` | 新增 Observer Stub/Proxy 测试 |

### 8.13 测试变更总结

| 测试文件 | 操作 |
|---------|------|
| `test/client/data_mining_client_test.cpp` | 移除 `FakeDataMiningService`，改为 Proxy-Stub-Service 链路，新增 10 个测试（含多 observer 测试） |
| `test/data_mining_service_test.cpp` | 新增 15 个 service 测试 + 6 个 stub 序列化测试（含 SubscribeEvent/UnsubscribeEvent） |
| `test/runtime/data_mining_runtime_manager_test.cpp` | 修改 1 个测试，新增 12 个直接方法测试（含 Stop 清理 + 重新触发 + INTERRUPT 事件 + 并发防双事件） |
| `test/runtime/event_report_test.cpp` | 无变更 |
<<<<<<< Updated upstream:docs/specs/data-mining-stop-event-ipc-design.md
| `test/runtime/pipeline_runtime_test.cpp` | 新增 12 个批次处理测试（见 8.10 节） |
| `test/demo/etl_demo_test.cpp` | 新增 5 个 E2E 测试（含多 observer 测试） |
=======
| `test/demo/etl_demo_test.cpp` | 新增 6 个 E2E 测试（含多 observer + Stop 后重新触发） |
>>>>>>> Stashed changes:claude/docs/specs/data-mining-stop-event-ipc-design.md
| `test/unittest/etl_service_proxy_test.cpp` | 新增 StopPipeline 测试 |
| `test/unittest/etl_client_test.cpp` | 新增 StopPipeline + taskId 测试 |
| `test/unittest/data_mining_event_observer_test.cpp` | 新增 Observer 测试 |
| `test/throttled_event_observer_proxy_test.cpp` | 新增 GetOptions 测试（如需要） |

### 8.14 测试用例重构指导

重构现有测试时按以下方式消除私有成员访问：

**类型 A — 不需要修改的用例**（已通过公共接口测试）：
- `DispatchReturnsErrorWhenContentInvalid001`, `DispatchReturnsErrorWhenPipelineMissing002`
- `StartAndStopCanBeInvoked003`, `DispatchRejectsOversizedPayload005`
- `StopPipeline_ReturnsNotFound002`
- `Dispatch_NoLongerHandlesStopPipeline008`, `Dispatch_NoLongerHandlesUpdateSubscription009`
- `OnRemoteRequest_UnknownCode_ReturnsError`, `OnRemoteRequest_InvalidToken_ReturnsError`
- `DispatchUsesInjectedService001`, `DispatchPropagatesRemoteError002`

**类型 B — 通过公共接口行为验证替代内部状态检查**：

| 原用例 | 重构方案 |
|--------|---------|
| `SubscribeEvent_DelegatesToManager004` | `SubscribeEvent()` 后 `ReportEvent()` 验证行为差异 |
| `UnsubscribeEvent_ClearsObserver005` | 同上 |
| `OnRemoteRequest_SubscribeEvent_Code2` | MessageParcel code=2，验证 reply |
| `ReportEvent_DelegatesToManager006` | 先 `SubscribeEvent()` 再 `ReportEvent()` |
| `ReportEvent_ThroughService005` | 通过 client 调用，同上思路 |

**类型 C — 通过 Dispatch 成功路径预设状态**：

| 原用例 | 重构方案 |
|--------|---------|
| `StopPipeline_DelegatesToManager001` | 先 Dispatch（taskId=42 + demo 插件）创建状态，再 `StopPipeline("scene", 42)` |
| `StopPipeline_CancelIdleOnNewRequest003` | 同上 |
| `OnRemoteRequest_StopPipeline_Code1` | 同上，再通过 MessageParcel code=1 |
| `StopPipeline_StopsRuntime002` (client_test) | 同上，通过 client 调用 |
| `OnIdleRespectsLogicalPipelineInstances004` | 先 Dispatch 触发异步执行，立即 `OnIdle()` → -1；完成后 `OnIdle()` → 0 |

**类型 D — 通过行为间接验证 private 方法**：

| 原用例 | 重构方案 |
|--------|---------|
| `OnProxyDiedClearsCachedProxy003` | 先 Dispatch 成功，SAMGR 移除 SA 触发 death notification，再次 Dispatch → 错误 |
| `ServiceDeathRecipientOnRemoteDiedClearsOwner004` | 通过行为验证 |
| `GetServiceLockedReturnsCachedService006` | 连续两次 Dispatch 成功，间接验证缓存 |
| `NewMethods_ReturnErrorWhenNoService007` | SAMGR 取消注册 SA，各方法 → E_INVALID_STATE |

---

## 9. 实现顺序（TDD 模式）

每个 Step 遵循 **红-绿-重构** 循环。

```
Step 1:  [接口] source.h (OnStop→Stop), operator.h (+Stop), sink.h (+Stop)
         → 更新 mock_helpers.h, pipeline_runtime_test_utils.h 中的所有子类
         → 编译通过现有测试

Step 2:  [Mock] mock_dlfcn.cpp 扩展支持 demo 插件
         → 验证 mock dlopen 返回 sentinel handle
         → 验证 PluginRegistry 能找到 demo 模块

Step 3:  [工具] pipeline_runtime_test_utils.h 添加 MakeMinimalTriggerDispatchRequest

Step 4:  [TDD] data_mining_service_test.cpp Dispatch 成功路径测试
         [实现] Dispatch 带 demo 插件配置端到端工作

Step 5:  [TDD] client/service 层 StopPipeline 测试
         [实现] IDataMiningService 新增 3 个虚拟方法
         [实现] Proxy/Stub/Client/Service 各层实现
         [实现] RuntimeManager Dispatch 拒绝 kind 2/3/4

Step 6:  [TDD] etl_service_proxy_test.cpp StopPipeline 测试
         [实现] etl_service.h, etl_service_proxy.h/.cpp

Step 7:  [TDD] etl_client_test.cpp StopPipeline + taskId 测试
         [实现] etl_client.h/.cpp

Step 8:  [实现] source_proxy.h/.cpp (OnStop→Stop), operator_proxy.h/.cpp (+Stop), sink_proxy.h/.cpp (+Stop)

Step 9:  [实现] transport_types.h/.cpp (DispatchKind 精简, +taskId, +triggerMode)

Step 10: [TDD] pipeline_runtime_test.cpp Stop 测试
         [实现] pipeline_runtime.h/.cpp (+Stop, +stopping_, ProgressCallback 签名)

Step 10.5: [接口] source.h 新增 GetRemainDataCount() 虚方法
           [实现] source_proxy.h/.cpp 新增 GetRemainDataCount() 转发
           [TDD] pipeline_runtime_test.cpp 批次处理测试（见 8.10 节）
           [实现] pipeline_runtime.cpp TriggerSourceTracked 批次循环逻辑
           [实现] data_mining_runtime_manager.cpp PrepareDispatchExecution 注册 ProgressCallback

Step 11: [TDD] data_mining_runtime_manager_test.cpp Stop/TaskId/Event 测试
         [实现] data_mining_runtime_manager.h/.cpp（完整事件系统）

Step 12: [实现] data_mining_manager.h/.cpp（DDMS 集成）

Step 13: [TDD] event_report_test.cpp 终止事件/进度/订阅过滤测试

Step 14: [TDD] Demo E2E 测试

Step 15: 重构测试消除私有成员访问（service_test → client_test → runtime_manager_test）

Step 16: 编译验证 + 全量测试

Step 17: [清理] 删除 EventManager 死代码（见 6.16 节）
         [删除] event_manager.h, event_manager.cpp, event_manager_test.cpp
         [修改] data_mining_service_impl.h/.cpp 移除 eventManager_ 引用
```

---

## 10. 验证

```bash
cd cmake-build-debug && ../ninja.exe -j16

./bin/DataMiningCoreTest
./bin/DataMiningEtlTest
./bin/DataMiningRuntimeTest
./bin/DataMiningComponentTest
```

### 验收标准

- [ ] 终止事件（SUCCESS/FAILURE/INTERRUPT）正确发出
- [ ] triggerMode 从 DDMS 正确传播到事件回调
- [ ] 进度事件含有效百分比（finishCount/totalCount）
- [ ] Source 批次循环正确工作：GetRemainDataCount() > 0 时继续 Trigger，= 0 时停止
- [ ] 每批完成后 ProgressCallback 被调用，finishCount 累加
- [ ] 全部批次完成后 onAsyncComplete 只触发一次
- [ ] 循环中 IsStopping() 为 true 时跳出循环
- [ ] GetRemainDataCount() 默认返回 0 时行为不变（无批次循环）
- [ ] 多 observer 独立过滤正常工作（各 observer 的 EventOptions 独立生效）
- [ ] SubscribeEvent/UnsubscribeEvent 正确管理 observer 生命周期
- [ ] **客户端侧重复订阅检测正常工作**：同 scene + 同 observer 对象不能重复订阅
- [ ] **同 scene 多 observer 独立回调正常工作**：不同 observer 各自收到独立回调
- [ ] **observerId 通过 IPC MessageParcel 正确回传**：客户端能根据 observerId 路由到正确的 DataMiningEventObserver
- [ ] **DataMiningEventObserver 基类正确使用**：shared_ptr 管理生命周期，子类实现 OnEvent()
- [ ] RecalcSubscriptionCache 聚合结果正确
- [ ] sceneToTokens_ 索引正确维护
- [ ] Client 死亡时 observer 被正确清理
- [ ] Stop 发出 INTERRUPT 事件后立即清理 TaskEntry 和 runtime，下次触发可创建新实例
- [ ] Dispatch 拒绝 kind=2/3/4
- [ ] ETL SA 通过回调 stub 上报事件，不依赖 ETLClient
- [ ] RegisterEventCallback 正确注册 stub 到 ETL SA
- [ ] 独立 IPC 方法（StopPipeline/RegisterEventCallback/UpdateSubscription）正常工作
- [ ] 测试不直接访问私有成员
- [ ] Demo 插件端到端验证通过
- [ ] 所有新测试通过，无回归

---

## 11. 风险和注意事项

1. **dlopen 在 mock 环境**：demo 插件通过 constructor 自动注册到 PluginRegistry，mock dlopen 返回 sentinel handle 使 Acquire 流程完整。
2. **异步执行**：Dispatch 使用 ExecutorPool 异步执行，测试中需同步等待。可通过 `executors_` 为 nullptr 时走同步路径简化。
3. **SAMGR 注册**：client_test 依赖 SAMGR 注册 SA，需确保 mock 环境下 `Publish()` 和 `GetSystemAbilityManager()` 正常工作。
4. **OnIdle 测试**：异步 Dispatch 后立即调用 OnIdle 可能存在时序问题。
5. **Demo 插件链接**：demo 插件 .cpp 文件需编译进测试可执行文件以触发 constructor 注册。
6. **Sentinel handle 安全性**：`PluginLoader::Acquire` 只调用 dlopen + GetModule，不调用 dlsym，sentinel handle 安全。
7. **runtime_manager_test 重构工作量最大**（60KB+），建议分批进行。
8. **多 observer 场景下的 IPC 开销**：同一 Client 进程的所有 observer 共享一个 remote，每次事件到达 DDMS 时会为每个匹配的 observer 独立调用 `OnEvent()`，即独立发送 IPC。如果同一 Client 在同一 scene 下有大量 observer，可能产生多次 IPC。当前设计认为 observer 数量有限（通常每个 Client 每场景不超过个位数），暂不优化为聚合发送。
9. **DeathRecipient 与 remote 生命周期**：同一 Client 下所有 observer 共享一个 remote，首次注册时添加 DeathRecipient。需确保在最后一个 observer 被移除时正确处理（不注销 DeathRecipient，因为 remote 对象的引用计数由 sptr 管理，observer 析构时自动释放）。
10. **客户端侧重复订阅检测**：重复订阅判定基于 observer 对象指针（`shared_ptr::get()`），不是 observerId。这意味着即使使用不同的 observerId，如果是同一个 observer 对象，仍然会被拒绝。
11. **批次循环与异步 Source**：当前批次循环仅适用于同步 Source（Trigger 内部同步调用 Notify）。异步 Source 的 `resultReady` 为 false，不进入循环。如果后续需要支持异步 Source 的批次模式，需要额外设计等待机制。
12. **批次循环中的内存使用**：每轮循环创建新的 `TriggerDispatchState` 和 `SourceDispatchNotifier`，但由于同步模式下 Trigger 返回后这些对象即可释放，不会累积。

---

## 12. UML 时序图

PlantUML 源码位于 `puml/` 目录。

### 12.1 SubscribeEvent 时序图

![SubscribeEvent](puml/12_1_subscribe_event.png)

> 源码：[puml/12_1_subscribe_event.puml](puml/12_1_subscribe_event.puml)

### 12.2 UnsubscribeEvent 时序图

![UnsubscribeEvent](puml/12_2_unsubscribe_event.png)

> 源码：[puml/12_2_unsubscribe_event.puml](puml/12_2_unsubscribe_event.puml)

### 12.3 事件分发时序图（含 observerId 回传）

![EventDispatch](puml/12_3_event_dispatch.png)

> 源码：[puml/12_3_event_dispatch.puml](puml/12_3_event_dispatch.puml)

### 12.4 多 Observer 订阅场景时序图

![MultiObserver](puml/12_4_multi_observer.png)

> 源码：[puml/12_4_multi_observer.puml](puml/12_4_multi_observer.puml)

### 12.5 完整生命周期时序图

![FullLifecycle](puml/12_5_full_lifecycle.png)

> 源码：[puml/12_5_full_lifecycle.puml](puml/12_5_full_lifecycle.puml)

### 12.6 Source 批次处理时序图

![BatchProcessing](puml/12_6_batch_processing.png)

> 源码：[puml/12_6_batch_processing.puml](puml/12_6_batch_processing.puml)
