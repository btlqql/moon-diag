# MoonDiag 0.3.0

面向台架回归的离线诊断日志审计：逐ECU隔离会话与安全状态，检查单DID回显，以及0x34/0x36/0x37下载中的块大小、计数、重传与确认字节数。

2026-10-30修订。Apache-2.0。纯MoonBit核心提供独立于CAN传输的有向UDS净荷审计API；可嵌入软件客户端、台架回归和离线分析。

## 运行

需要MoonBit工具链与Node.js。核心库不依赖Node，CLI使用Node读取文件。

```sh
moon test --target js
moon run cmd/main --target js -- session examples/uds-sessions/download-ok.log
moon run cmd/main --target js -- conversation examples/client/udsoncan-download.log
moon run cmd/main --target js -- conversation examples/client/download-size-mismatch.log
```

session命令发现fail时返回1；review输出供人工复核，退出码为0。

## 当前能力与验证

新版功能和验证见[本轮复核](docs/final-review-20261030.md)。真实udsoncan 1.26.1 Client已与软件ECU完成7次交互；`scripts/client_replay.py`可重新生成成功下载日志和仅修改memorySize的反例。Windows本地验证JS、wasm、wasm-gc及独立消费工程。客户端依赖仅用于开发验证，运行核心不需要Python。

CAN日志按接口及ECU隔离重组和状态，无法解析的非空行报告失败，未完成的ISO-TP消息拒绝。`analyze_uds_exchange`接受有向净荷数组；`analyze_uds_payload_log`接受每行`>>`请求／`<<`响应。

不是刷写器；不运行OEM安全算法，不支持完整UDS/CAN FD/DoIP、真实时序或功能寻址。示例为构造日志；下载审计限未压缩、未加密数据。
