# UDS 会话语义分析（2026-10-25）

`session_analysis.mbt` 在 ISO-TP/UDS 解码之上做请求/响应配对和状态判断。它不满足于“把一条响应解出来”，而是回答：这条响应属于哪个请求、是否缺失、是否被抑制、是否 pending、服务/会话是否回显、安全访问顺序是否正确。

## 判断项

| 代码 | 级别 | 判断 |
|---|---|---|
| `MISSING_RESPONSE` | fail | 请求没有最终响应 |
| `ORPHAN_RESPONSE` | fail | 响应找不到匹配请求 |
| `SERVICE_MISMATCH` | fail | 响应的服务号与请求不匹配 |
| `SESSION_ECHO_MISMATCH` | fail | 0x10 请求的会话与 0x50 回显不一致 |
| `SECURITY_SEQUENCE` | fail | 0x27 密钥发送没有对应 seed 请求 |
| `NEGATIVE_RESPONSE` | review | 非 0x78 的负响应，附 NRC 说明 |
| `PENDING_RESPONSE` | review | 0x78 response pending，请求继续等待最终响应 |

## 配对规则

- 物理寻址下，请求 CAN ID 0x7E0–0x7E7 的响应 ID 为请求 ID + 8；其他 ID 原样匹配。
- 正响应 SID 必须等于请求 SID + 0x40；负响应 `7F` 的第二字节必须等于请求 SID。
- `3E 80` 的抑制正响应 TesterPresent 不生成待响应项。
- `7F xx 78` 不关闭请求，后续最终响应继续匹配并关闭。
- 正/负最终响应关闭请求；未关闭的请求在日志末尾报 `MISSING_RESPONSE`。

## 具体日志与结果

`examples/uds-sessions/` 有 8 份日志。

**happy.log**：10 03→50 03、22 F1 90→62 F1 90…、3E 80（无响应）、10 01→50 01。

```text
verdict: pass
requests: 4
responses: 3
session: default
security level: 0
```

**missing.log**：只有 22 F1 90 请求。

```text
verdict: fail
issue step=1 fail MISSING_RESPONSE: request 0x22 has no response
```

**orphan.log**：只有 62 F1 90… 响应。

```text
verdict: fail
issue step=1 fail ORPHAN_RESPONSE: response 0x62 has no matching request
```

**service-mismatch.log**：10 03 请求，返回 62 F1 90…。

```text
verdict: fail
issue step=2 fail SERVICE_MISMATCH: response 0x62 does not match request 0x10
```

**negative.log**：22 F1 90→7F 22 31。

```text
verdict: review
issue step=2 review NEGATIVE_RESPONSE: request 0x22 rejected: NRC 0x31 requestOutOfRange
```

**pending.log**：22 F1 90→7F 22 78→62 F1 90…。

```text
verdict: review
responses: 2
issue step=2 review PENDING_RESPONSE: request 0x22 is pending (NRC 0x78)
```

**security.log**：直接发送 27 02 key，没有 27 01 seed。

```text
verdict: fail
issue step=1 fail SECURITY_SEQUENCE: key send 0x02 without matching seed request
```

**session-echo.log**：请求 10 03，ECU 回 50 01。

```text
verdict: fail
issue step=2 fail SESSION_ECHO_MISMATCH: requested session 0x03 but ECU echoed 0x01
```

## 相对于“解码 + 报告”新增的判断

- 维护每个 CAN ID 的待响应请求队列，按物理寻址规则匹配响应。
- 区分抑制正响应、pending 响应和最终响应。
- 校验服务号回显、会话回显和安全访问 seed/key 顺序。
- 把缺失、孤儿、服务不符、会话不符、安全顺序错误汇总为 pass/review/fail，带步骤号和原因。

## 边界

- 只分析日志中出现的报文，不生成或补全请求。
- 不模拟真实超时、STmin、块大小或总线时序；pending 只按日志顺序处理。
- 不实现 OEM 的“某服务只能在某会话执行”矩阵；会话状态只用于回显和报告。
- 不打开 CAN 适配器；测试日志是作者构造的合法样例，尚未用真实车辆日志验证。

## 复现

```bash
moon test
moon run cmd/main --target js -- session examples/uds-sessions/happy.log
moon run cmd/main --target js -- session examples/uds-sessions/security.log
```

测试文件：`uds_session_test.mbt`（8 项），总计 25 项测试。
