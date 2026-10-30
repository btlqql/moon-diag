# MoonDiag：可嵌入诊断客户端的UDS会话审计库

账号：btlqql｜单人项目｜版本：0.3.0｜主要语言：MoonBit｜许可：Apache-2.0

## 解决的问题

诊断下载中，各条报文可被正确解码，仍可能发生错误解锁、响应串配、漏传块或提前结束。MoonDiag面向诊断客户端与台架回归，将请求／响应、权限及传输总量作为同一过程检查，而非只展示ISO-TP、UDS或DTC字段。

## 核心实现

提供独立于CAN的有向UDS净荷审计API和CLI；CAN适配按接口及ECU隔离重组与状态。跟踪pending／最终响应、服务和单DID回显、安全访问seed／key及成功确认。下载检查协商块长、计数FF到00回绕、相同已确认块重传去重、确认字节总量和退出条件；坏日志及未完成传输不会静默通过。

## 可复现任务

真实udsoncan 1.26.1 Client与软件ECU完成会话切换、seed／key、申请下载、两个数据块、传输退出，共7次交互。MoonDiag审计其导出净荷，输出pass和确认8字节；仅将请求memorySize从8改为9，其余响应不变，检出TRANSFER_SIZE_MISMATCH并退出1。脚本、成功日志及反例随代码提供。

## 相对已有能力的增量

认可现有基础协议库；独立贡献是跨报文的会话、安全状态和下载一致性审计。相同核心既可接CAN录制日志，也可由其他传输或软件客户端提供有向净荷，不要求重新实现一个CAN驱动。

## 验证与范围

40项测试及独立消费工程通过，公开CI完成四后端check／build／test。集成为真实软件客户端与模拟ECU，不冒称实车验证。未实现OEM密钥算法、真实刷写、DoIP解析、CAN FD、完整UDS服务或时序证明；下载审计限未压缩、未加密DFI=0。

## 项目信息

源码：https://github.com/btlqql/moon-diag；固定提交：229a61ebef9a。AI辅助开发，参赛者对目标、技术路径和质量负责。

验证记录：https://github.com/btlqql/moon-diag/actions/runs/41064301952

公共包：https://mooncakes.io/docs/btlqql/moon_diag@0.3.0（独立工程注册表安装验证通过）

正式发布：[GitHub Release v0.3.0](https://github.com/btlqql/moon-diag/releases/tag/v0.3.0)
