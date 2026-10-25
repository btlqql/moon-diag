# MoonDiag

离线汽车诊断工具包：把录制的 CAN 日志还原成 ISO-TP 传输，再解码 UDS 与 OBD-II 报文。

- 仓库：https://github.com/btlqql/moon-diag
- 版本：0.1.0
- 许可证：Apache-2.0

## 为什么单独做这一层

MoonCakes 上已有 CAN 2.0 / CAN-FD 帧编解码与过滤器实现，例如
[myc1234567/moonbit-canbus](https://mooncakes.io/docs/myc1234567/moonbit-canbus) 和
[fuyun-2026/moonbit-canbus](https://mooncakes.io/docs/fuyun-2026/moonbit-canbus)。
它们停在帧与总线上。MoonDiag 从帧之上开始：

1. **ISO-TP (ISO 15765-2)**：单帧、首帧、连续帧、流控帧识别，多帧重组与发送切分。
2. **UDS (ISO 14229)**：常用服务和子功能请求构造，正/负响应解析，NRC 解释。
3. **OBD-II (SAE J1979)**：Mode 01 常用 PID 换算，Mode 03/07/0A 故障码读取。
4. **DTC (SAE J2012)**：P/C/B/U 代码与状态位解码。
5. **会话报告**：把一份 candump 日志按 CAN ID 分组、重组、分类，输出可核对的文本报告。

面向的任务是：台架测试人员拿到一段录制日志，想知道“这条 0x7E8 的响应到底说了什么、为什么被拒、有哪些故障码”，而不是重新实现一个 CAN 驱动。

2026-10-24 在 MoonCakes 搜索 `uds`、`isotp`、`obd2`、`doip`、`dtc` 未发现同层实现；搜索未命中不等于绝对不存在，私有仓库、未发布代码和不同命名仍是盲区。

## 快速开始

要求 MoonBit 工具链（本版本在 `moon 0.1.20260904` 验证）。CLI 以 JS 为目标，文件读取只使用 Node 内置模块。

```bash
moon test
moon run cmd/main --target js -- report examples/session.log
moon run cmd/main --target js -- report examples/session.log --json
```

`examples/session.log` 的输出：

```text
frames: 7
messages: 5
negative responses: 1
DTCs: 1
CAN 0x7E8 UDS Negative 0x22 NRC 0x31 requestOutOfRange
CAN 0x7E8 UDS ReadDataByIdentifier DID 0xF190 = "1234567890ABCDEFG" [...]
CAN 0x7E8 UDS ReadDTCInformation DTCs: P0301-2F
CAN 0x7E0 OBD PID 0x0C Engine speed = 1726 rpm
CAN 0x7E0 OBD PID 0x05 Coolant temperature = 83 C
```

## CLI

```text
moondiag report <candump.log> [--json] decode a recorded session
moondiag uds <hex>                     parse a UDS response
moondiag obd <hex>                     decode an OBD-II response
moondiag dtc <hex>                     decode DTC triples (high low status)
moondiag segment <hex>                 segment a payload into ISO-TP frames
moondiag request read-did <hex>        build ReadDataByIdentifier
moondiag request session <hex|name>    default|programming|extended|safety
moondiag request clear-dtc <hex>       build ClearDiagnosticInformation
moondiag request tester-present        build TesterPresent
```

示例：

```bash
moon run cmd/main --target js -- uds "7F 22 31"
moon run cmd/main --target js -- obd "41 0C 1A F8"
moon run cmd/main --target js -- request read-did F190
moon run cmd/main --target js -- segment "62 F1 90 31 32 33 34 35 36 37 38 39 30 41 42 43 44 45 46 47"
```

## 输入格式

支持两种 candump 文本：

```text
can0 7E8 [8] 02 10 03 00 00 00 00 00
(1690000000.123) vcan0 18DAF110#0210030000000000
```

扩展帧 ID 超过 3 位十六进制，报告按 8 位输出。空行和无法解析的行会被跳过。

## 测试

`moon test` 共 12 项：

- 十六进制编解码与分隔符、非法半字节。
- candump 经典格式、`candump -L` 格式、扩展帧。
- ISO-TP 单帧/多帧往返；序列号错误；长度不足。
- DTC 代码与状态位。
- UDS 请求构造（会话、DID、安全访问、TesterPresent、清码、下载）。
- UDS 正响应、负响应、DID、DTC 解析。
- OBD-II RPM、水温、车速、油位、Mode 03 故障码、Mode 09 VIN。
- 会话报告分组、计数、VIN 提取；未完成传输报告。
- JSON 报告：计数、事件类型、UDS/NRC、DTC 与 OBD 读数。

GitHub Actions 在 wasm、wasm-gc、js、native 四个后端执行 check/build/test。

## 外部对照

- [can-isotp 2.0.7 + udsoncan 1.26.1 对照](docs/reference-comparison.md)：ISO-TP 多帧重组、UDS 负响应、DID 正响应、DTC 记录均一致；对照中发现并修复了 UDS DTC 记录长度错误。
- 复现：`python scripts/reference_compare.py`（参考库装在 `D:/Codex/tools/pyrefs`，不是运行时依赖）。
- 输入是构造的合法帧，不是真实车辆日志；未覆盖流控时序、全部 UDS 服务和 CAN FD。

## 明确不做

- 不打开真实 CAN 适配器，不实现 CAN 驱动、波特率、总线仲裁或 ELM327 串口协议。
- 不实现 OEM 安全访问算法；只构造 seed/key 帧并解释 NRC。
- 不实现 DoIP、J1939、SOME/IP、CAN FD 的 ISO-TP 扩展。
- 不是完整的 UDS 服务矩阵：未覆盖 0x23、0x24、0x2A、0x2C、0x2F、0x38 等。
- 报告是文本格式，不含图形界面或数据库。

## 后续

优先补：ISO-TP CAN FD 长度、流控参数与超时模型、更多 UDS 服务、OBD Mode 06/09、按 CAN ID 的请求/响应配对、JSON 报告。每项都要有真实日志样本和失败样例，再谈发布。
