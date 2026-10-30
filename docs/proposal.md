# MoonDiag项目申报书

账号：**btlqql**；项目：MoonDiag；版本：**0.3.0**；日期：2026-10-30；团队：单人；主要语言：MoonBit；许可：Apache-2.0。

## 一、项目名称与摘要

**MoonDiag：支持多接口隔离、诊断状态跟踪与下载一致性检查的UDS会话审计库。**

项目接收录制的CAN日志或带方向的UDS净荷，恢复消息后关联请求与响应，跟踪诊断会话、安全访问与下载过程，检查单条报文解码无法直接发现的跨步骤问题。输出包括可复用的结构化审计结果，以及带消息号、问题代码和原因的文本报告。

核心协议处理和状态判断由MoonBit实现，不依赖真实CAN适配器。CAN日志读取只是一个入口；`analyze_uds_exchange`可以直接接收由软件客户端或其他传输适配器提供的有向UDS净荷。Node负责CLI文件读取，Python及udsoncan仅用于开发验证。

## 二、实际问题与使用场景

基础ISO-TP、UDS与DTC解析已有可复用实现，因此本项目不将“能显示服务号、负响应码或故障码”作为主要独立贡献。关注的问题是：**每条报文都合法，组合后的诊断过程是否仍然一致**。

已经能够复现的使用场景包括：

1. **诊断客户端回归。** 软件客户端升级后，检查请求是否收到对应服务和标识符的响应，pending是否最终结束，安全访问是否真正得到成功确认，而不是发送key后就把状态标为解锁。
2. **下载脚本核对。** 从RequestDownload读取目标大小，从ECU响应读取允许块长度，再累计已确认的TransferData有效数据，检查块计数、重复发送、遗漏与提前退出。
3. **多接口／多ECU日志排错。** 同一采集文件里存在多个CAN接口或多个ECU时，分别维护ISO-TP重组、待响应请求和安全状态，避免相同CAN ID在不同接口之间串配。

这些任务可以在软件联调、台架回归或离线问题复现中使用。项目已经完成真实软件客户端与模拟ECU的集成，但没有将其描述为真实车辆、生产台架或硬件刷写验证。

## 三、已实现的功能与处理链

处理链分为两个入口，共用同一会话审计核心：

- **CAN入口：** candump文本 → 按接口分离 → 按CAN ID执行ISO-TP重组 → 默认物理寻址关联 → 会话审计。
- **净荷入口：** 有向UDS净荷数组／`>>`与`<<`文本 → 请求响应关联 → 会话审计。

| 能力 | 当前处理内容 | 输出 |
|---|---|---|
| CAN／ISO-TP | candump格式解析、单帧／多帧重组与切分、序列与长度错误检查 | 完整UDS净荷或明确错误 |
| 基础诊断 | 常用UDS请求与响应、NRC、OBD-II及DTC解析 | 字段、故障信息及基础报告 |
| 请求关联 | 待响应队列、服务回显、单DID回显、孤立与缺失响应 | 会话问题列表 |
| 安全与会话 | seed／key顺序、成功响应确认、子功能回显、会话切换状态 | 观察到的会话和安全级别 |
| 下载审计 | 格式、目标大小、协商块长度、块计数、重复发送及退出 | 已确认字节数和一致性判定 |
| 工程入口 | 类型化API、CAN日志CLI、UDS净荷CLI | `pass`／`review`／`fail`及退出状态 |

基础`report`命令保留文本／JSON／CSV输出；会话层通过类型化报告和文本渲染提供审计结果，不将所有报告格式混同为同一接口。

## 四、核心处理机制

### 1. 按接口及ECU隔离状态

CAN日志先根据接口名称分组，再执行各自的ISO-TP重组和请求关联。因此，`can0`与`can1`上相同的0x7E0／0x7E8不能共享一条待响应队列或一个安全访问上下文。

默认物理寻址将0x7E0至0x7E7请求对应到请求ID加8的响应；每个ECU单独保留请求、会话和权限状态。其余ID按同ID规则关联，尚未形成可配置OEM映射或功能寻址广播模型。

### 2. 请求、pending与最终响应

正响应服务号应对应请求服务号加0x40；负响应中的原服务号也参与匹配。`7F xx 78`表示请求仍在等待，不关闭待响应项，后续最终响应继续匹配。非pending负响应结束该次请求，并保留NRC说明。

`3E 80`抑制正响应TesterPresent不要求正响应。没有匹配请求的响应、缺少最终响应和服务回显不符分别报告，不把它们混为一个“解码失败”。出现pending或负响应时保留`review`信息，即使后续流程继续完成，也不静默消除这些观察。

### 3. 安全访问由成功响应确认

请求seed本身不代表已经获得seed，发送key也不代表已经解锁。核心维护已确认的seed级别，检查后续key子功能是否匹配；只有观察到匹配的成功key响应，才记录相应安全级别。

失败key响应不会新建解锁状态；成功切换诊断会话会清除旧安全上下文。该状态描述的是日志中观察到的协议结果，不代表本项目计算或验证了OEM密钥算法。

### 4. 下载过程的跨报文约束

成功的RequestDownload交互建立下载上下文，读取地址／大小字段格式、memorySize与协商的最大块长度。TransferData在该上下文中核对块计数及其响应回显，数据长度受ECU协商值约束。

计数器按一字节规则从FF回绕到00；相同已确认块的完全相同重传不重复累计字节。块计数跳跃、同一计数但数据变化、响应回显错误、超长块分别形成可定位问题。只有得到成功确认的有效数据才计入传输量。

RequestTransferExit时将累计字节数与memorySize比较。即使每条请求和响应都能单独解析，漏传或提前结束仍会形成`TRANSFER_SIZE_MISMATCH`。捕获结束而没有成功传输退出则报告`DOWNLOAD_INCOMPLETE`。

### 5. 错误与不支持情况可见

无法解析的非空CAN日志行形成`MALFORMED_CAPTURE`，不会直接丢弃后再给出清洁报告。ISO-TP在捕获结束时仍不完整会被拒绝。未纳入实现的UDS服务产生`review`，而不是因为没有对应检查逻辑就默认通过。

CLI的`fail`返回退出码1；`review`返回0但保留问题明细。自动化调用者必须读取判定和问题列表，不能仅凭退出码0断言没有待复核内容。

## 五、相对基础协议库的增量

| 单条协议解析的结果 | 当前会话审计新增的判断 |
|---|---|
| 收到一个0x62正响应 | 单DID请求与响应是否属于同一标识符 |
| 0x27请求中存在key数据 | 此前是否收到匹配seed，ECU是否成功确认key |
| 0x76响应格式有效 | 是否回显当前块计数，该块是否超长或重复 |
| RequestTransferExit得到0x77 | 已确认数据总量是否满足申请的memorySize |
| 两个接口各有合法报文 | 相同ID的状态是否被隔离，是否出现跨接口错误关联 |

这种跨报文状态与计量核对，是本项目相对基础解码层的实际新增。净荷API进一步将同一核心用于CAN日志和软件客户端导出的交互，避免将CAN文件格式本身作为唯一复用边界。它并未自动实现DoIP、串口或任意其他传输协议。

## 六、完整客户端集成与故障案例

### 案例一：真实软件客户端完成下载

`scripts/client_replay.py`运行真实`udsoncan 1.26.1 Client`，其对端为本项目编写的确定性软件ECU。客户端实际发出请求并按udsoncan规则验证响应，完成以下7次交互：

| 步骤 | 请求与响应 | 审计作用 |
|---|---|---|
| 1 | `10 03` → `50 03 ...` | 确认扩展会话 |
| 2 | `27 01` → `67 01 11 22` | 确认seed结果 |
| 3 | `27 02 33 44` → `67 02` | 记录安全级别1 |
| 4 | `34 00 12 10 00 08` → `74 10 06` | 目标8字节、块请求总长上限6字节 |
| 5 | `36 01 01 02 03 04` → `76 01` | 确认第一块4字节 |
| 6 | `36 02 05 06 07 08` → `76 02` | 确认第二块4字节 |
| 7 | `37` → `77` | 传输退出，总量核对为8字节 |

导出的有向净荷日志经MoonDiag审计后输出`pass`、安全级别1、确认传输8字节。这里的“真实”指使用真实软件客户端库，不指实车或真实ECU硬件。

### 案例二：局部报文合法，整体下载大小不符

仅将案例一RequestDownload的memorySize从8改为9，其余请求、数据和响应保持不变。单条服务与块响应仍可解析，但成功确认的数据只有8字节，传输退出时输出`TRANSFER_SIZE_MISMATCH`并退出1。

这一反例直接展示跨报文审计相对字段解码的新增作用，不依赖错误校验和或随机破坏报文才能制造失败。

### 案例三：状态隔离与边界

回归测试还覆盖：一个ECU取得seed而另一个直接发送key、不同CAN接口使用相同ID、负key响应、单DID回显错误、块计数跳跃、FF至00回绕、完全相同块重传去重、协商块长超限及空／畸形捕获。

```sh
moon run cmd/main --target js -- conversation examples/client/udsoncan-download.log
moon run cmd/main --target js -- conversation examples/client/download-size-mismatch.log
moon run cmd/main --target js -- session examples/uds-sessions/cross-ecu-security.log
```

## 七、接口、验证流程与安装

公共接口包括：

- `analyze_uds_exchange(Array[DirectedUdsPayload])`：审计调用者提供的单段有向会话；传输与分组由调用者负责。
- `analyze_uds_payload_log(String)`：读取`>>`请求／`<<`响应净荷日志。
- `analyze_uds_network(String)`：按CAN接口及ECU返回报告。
- `analyze_uds_session(String)`：生成整体审计报告。
- `render_uds_session`：输出判定、会话、安全级别、确认字节数和问题明细。

当前核心测试**40项**。代码基线在Windows本地JS、wasm、wasm-gc完成check／build／test，对应GitHub Actions的JS、wasm、wasm-gc、native四后端任务通过。udsoncan软件客户端集成实际执行并生成成功与失败日志，相关请求与预期结果保留为可移植回归夹具。

独立工程从公共注册表安装`btlqql/moon_diag@0.3.0`，通过公开净荷API检查会话；与另外两个包共同执行3项公共API用例，在JS、wasm、wasm-gc通过。注册表安装的`session_analysis.mbt`与本地核心源码SHA-256一致。跨后端执行不重复计算独立用例数量。

```sh
moon test --target js
moon test --target wasm
moon test --target wasm-gc
moon add btlqql/moon_diag@0.3.0
```

需要重新生成软件客户端交互时，在独立开发环境安装udsoncan 1.26.1后运行`python scripts/client_replay.py`。该依赖不是MoonBit核心或普通CLI运行依赖。

## 八、当前适用范围与边界

项目是离线诊断与软件回归工具，不连接真实CAN适配器，不执行真实刷写或OEM安全算法。默认CAN地址关联仅覆盖已说明的物理ID规则，不包含可配置OEM映射、功能寻址广播或完整寻址矩阵。

没有实现CAN FD的ISO-TP扩展、DoIP解析、全部UDS服务、P2／P2*超时证明或真实STmin／流控时序。下载审计支持未压缩、未加密的DFI=0；不将传输字节总量一致视为固件签名正确、固件可启动或刷写授权成功。

软件ECU由作者构造，不能替代真实车辆验证；尚未给出大规模日志性能、模糊测试或生产部署证据。已有基础协议能力与新增会话审计分别说明，不声称生态首创或不存在职责交叉。

## 九、公开交付与验证证据

- [公开仓库](https://github.com/btlqql/moon-diag)；[GitHub Release v0.3.0](https://github.com/btlqql/moon-diag/releases/tag/v0.3.0)。
- 公共模块：[btlqql/moon_diag@0.3.0](https://mooncakes.io/docs/btlqql/moon_diag@0.3.0)，发布返回`Server status: 200 OK`，全新工程安装及调用验证通过。
- 已验证核心代码基线：`229a61ebef9a395ac77389e9a8f16e716e92eb58`；[该基线四后端CI](https://github.com/btlqql/moon-diag/actions/runs/41064301952)。申报文档扩充不计作功能增加。
- [软件客户端复现脚本](https://github.com/btlqql/moon-diag/blob/main/scripts/client_replay.py)；[成功日志与来源信息](https://github.com/btlqql/moon-diag/tree/main/examples/client)；[实现与验证说明](https://github.com/btlqql/moon-diag/blob/main/docs/final-review-20261030.md)。

本项目使用AI辅助开发，参赛者负责理解与核实目标、实现和质量。本材料只列已实现、验证和发布的事实，不将软件模拟结果冒称硬件验证或官方审核通过。
