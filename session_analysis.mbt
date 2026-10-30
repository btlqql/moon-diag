// Stateful UDS session analysis over a recorded candump log.
// This is above ISO-TP/UDS decoding: it correlates tester requests with ECU
// responses, handles suppressed positives and pending responses, checks the
// service/session echo and the security-access seed/key order.

pub(all) struct UdsSessionIssue {
  step : Int
  code : String
  severity : String
  detail : String
}

pub(all) struct UdsSessionReport {
  verdict : String
  requests : Int
  responses : Int
  session : String
  security_level : Int
  transferred_bytes : Int
  issues : Array[UdsSessionIssue]
}

fn session_issue(
  issues : Array[UdsSessionIssue],
  step : Int,
  code : String,
  severity : String,
  detail : String,
) -> Unit {
  issues.push({ step, code, severity, detail })
}

fn remove_pending(
  slot : Int,
  pending_step : Array[Int],
  pending_can : Array[Int],
  pending_sid : Array[Int],
  pending_sub : Array[Int],
) -> Unit {
  for i in slot..<(pending_can.length() - 1) {
    pending_step[i] = pending_step[i + 1]
    pending_can[i] = pending_can[i + 1]
    pending_sid[i] = pending_sid[i + 1]
    pending_sub[i] = pending_sub[i + 1]
  }
  ignore(pending_step.pop())
  ignore(pending_can.pop())
  ignore(pending_sid.pop())
  ignore(pending_sub.pop())
}

fn expected_response_id(request_id : Int) -> Int {
  if request_id >= 0x7e0 && request_id <= 0x7e7 {
    request_id + 8
  } else {
    request_id
  }
}

fn payloads_in_order(text : String) -> Array[(Int, Int, Array[Int])] raise IsotpError {
  let frames = parse_candump(text)
  let ids : Array[Int] = Array::new()
  for frame in frames {
    let mut seen = false
    for id in ids {
      if id == frame.id {
        seen = true
      }
    }
    if !seen {
      ids.push(frame.id)
    }
  }
  let messages : Array[(Int, Int, Array[Int])] = Array::new()
  for id in ids {
    let reasm = IsotpReassembler::new()
    for i in 0..<frames.length() {
      if frames[i].id == id {
        match reasm.push(frames[i].data) {
          Some(payload) => messages.push((i, id, payload))
          None => ()
        }
      }
    }
    if reasm.is_active() { raise Incomplete(reasm.expected, reasm.payload.length()) }
  }
  messages.sort_by(fn(a, b) { a.0 - b.0 })
  messages
}

fn analyze_uds_messages(messages : Array[(Int, Int, Array[Int])]) -> UdsSessionReport {
  let issues : Array[UdsSessionIssue] = Array::new()
  let pending_step : Array[Int] = Array::new()
  let pending_can : Array[Int] = Array::new()
  let pending_sid : Array[Int] = Array::new()
  let pending_sub : Array[Int] = Array::new()
  let mut requests = 0
  let mut responses = 0
  let mut current_session = "default"
  let mut security_level = 0
  let mut security_seed_level = -1
  let mut download_active = false
  let mut transferred_bytes = 0
  let mut expected_bytes = 0
  let mut max_block = 0
  let mut last_block = 0
  let mut last_data : Array[Int] = []
  let mut message_no = 0
  for message in messages {
    message_no = message_no + 1
    let can_id = message.1
    let payload = message.2
    if payload.length() == 0 {
      continue
    }
    let sid = payload[0]
    if sid >= 0x10 && sid <= 0x3e {
      requests = requests + 1
      let sub = if payload.length() > 1 { payload[1] & 0x7f } else { 0 }
      if sid == 0x3e && payload.length() > 1 && (payload[1] & 0x80) != 0 {
        // Suppress-positive TesterPresent: no response is expected.
        continue
      }
      if sid == 0x27 {
        if (sub & 1) == 0 && security_seed_level != sub - 1 {
          session_issue(
            issues,
            message_no,
            "SECURITY_SEQUENCE",
            "fail",
            "key send 0x" + hex_int(sub, 2) + " without matching seed request",
          )
        }
      }
      if sid == 0x36 && !download_active {
        session_issue(issues, message_no, "TRANSFER_BEFORE_DOWNLOAD", "fail", "TransferData has no accepted RequestDownload")
      }
      pending_step.push(message_no)
      pending_can.push(can_id)
      pending_sid.push(sid)
      pending_sub.push(sub)
    } else if sid == 0x7f || (sid >= 0x40 && sid <= 0x7e) {
      responses = responses + 1
      let mut slot = -1
      let mut id_slot = -1
      for i in 0..<pending_can.length() {
        let sid_matches = if sid == 0x7f {
          payload.length() > 1 && payload[1] == pending_sid[i]
        } else {
          sid - 0x40 == pending_sid[i]
        }
        let id_matches = if pending_can[i] >= 0x7e0 && pending_can[i] <= 0x7e7 {
          pending_can[i] + 8 == can_id
        } else {
          pending_can[i] == can_id
        }
        if id_matches {
          id_slot = i
          if sid_matches {
            slot = i
            break
          }
        }
      }
      if slot < 0 && id_slot >= 0 {
        session_issue(
          issues,
          message_no,
          "SERVICE_MISMATCH",
          "fail",
          "response 0x" + hex_int(sid, 2) + " does not match request 0x" +
          hex_int(pending_sid[id_slot], 2),
        )
        remove_pending(id_slot, pending_step, pending_can, pending_sid, pending_sub)
      } else if slot < 0 {
        session_issue(
          issues,
          message_no,
          "ORPHAN_RESPONSE",
          "fail",
          "response 0x" + hex_int(sid, 2) + " has no matching request",
        )
      } else {
        let req_sid = pending_sid[slot]
        let req_sub = pending_sub[slot]
        let request_data = messages[pending_step[slot] - 1].2
        if sid == 0x7f {
          let nrc = if payload.length() > 2 { payload[2] } else { 0 }
          if nrc == 0x78 {
            session_issue(
              issues,
              message_no,
              "PENDING_RESPONSE",
              "review",
              "request 0x" + hex_int(req_sid, 2) + " is pending (NRC 0x78)",
            )
          } else {
            if req_sid == 0x27 {
              security_seed_level = -1
            }
            session_issue(
              issues,
              message_no,
              "NEGATIVE_RESPONSE",
              "review",
              "request 0x" + hex_int(req_sid, 2) + " rejected: NRC 0x" +
              hex_int(nrc, 2) + " " + nrc_description(nrc),
            )
            // Remove the request: a negative response is final.
            remove_pending(slot, pending_step, pending_can, pending_sid, pending_sub)
          }
        } else {
          if req_sid == 0x22 {
            if request_data.length() == 3 && (payload.length() < 3 || payload[1] != request_data[1] || payload[2] != request_data[2]) {
              session_issue(issues, message_no, "DID_ECHO_MISMATCH", "fail", "ReadDataByIdentifier response belongs to a different DID")
            }
          }
          if req_sid == 0x34 {
            if request_data.length() < 3 || payload.length() < 3 {
              session_issue(issues, message_no, "DOWNLOAD_FORMAT", "fail", "download request or response is truncated")
            } else {
              let address_len = request_data[2] & 15
              let size_len = request_data[2] >> 4
              let block_len = payload[1] >> 4
              if request_data[1] != 0 {
                session_issue(issues, message_no, "UNSUPPORTED_DOWNLOAD_FORMAT", "fail", "compressed or encrypted downloads are outside this auditor")
              } else if address_len == 0 || size_len == 0 || size_len > 4 || request_data.length() != 3 + address_len + size_len || block_len == 0 || block_len > 4 || payload.length() != 2 + block_len {
                session_issue(issues, message_no, "DOWNLOAD_FORMAT", "fail", "invalid download address/size or block-length fields")
              } else {
                let mut total = 0L
                let mut limit = 0L
                for k in (3 + address_len)..<request_data.length() { total = total * 256L + request_data[k].to_int64() }
                for k in 2..<payload.length() { limit = limit * 256L + payload[k].to_int64() }
                if total <= 0L || total > 2147483647L || limit < 3L || limit > 2147483647L {
                  session_issue(issues, message_no, "DOWNLOAD_SIZE", "fail", "download size or block limit is outside the offline auditor range")
                } else {
                  download_active = true
                  transferred_bytes = 0
                  expected_bytes = total.to_int()
                  max_block = limit.to_int()
                  last_block = 0
                  last_data = []
                }
              }
            }
          } else if req_sid == 0x36 && download_active {
            if request_data.length() < 3 || payload.length() != 2 || payload[1] != request_data[1] {
              session_issue(issues, message_no, "BLOCK_ECHO_MISMATCH", "fail", "TransferData response must echo its block counter")
            } else if request_data.length() > max_block {
              session_issue(issues, message_no, "BLOCK_TOO_LARGE", "fail", "TransferData exceeds the ECU negotiated block length")
            } else {
              let block = request_data[1]
              if block == last_block && last_data == request_data {
                // An acknowledged exact retransmission is not counted twice.
                ()
              } else if block != ((last_block + 1) & 255) {
                session_issue(issues, message_no, "BLOCK_SEQUENCE", "fail", "TransferData counter skipped, changed on retry, or arrived out of order")
              } else {
                last_block = block
                last_data = request_data
                transferred_bytes = transferred_bytes + request_data.length() - 2
                if transferred_bytes > expected_bytes {
                  session_issue(issues, message_no, "TRANSFER_SIZE_EXCEEDED", "fail", "acknowledged transfer exceeds RequestDownload memorySize")
                }
              }
            }
          } else if req_sid == 0x37 {
            if !download_active {
              session_issue(issues, message_no, "EXIT_BEFORE_DOWNLOAD", "fail", "transfer exit without an accepted download")
            } else if transferred_bytes != expected_bytes {
              session_issue(issues, message_no, "TRANSFER_SIZE_MISMATCH", "fail", "acknowledged bytes do not match RequestDownload memorySize")
            }
            download_active = false
          }
          if req_sid == 0x27 {
            if payload.length() < 2 || payload[1] != req_sub {
              session_issue(issues, message_no, "SECURITY_ECHO_MISMATCH", "fail", "security response does not echo the requested subfunction")
              security_seed_level = -1
            } else if (req_sub & 1) == 1 {
              if payload.length() < 3 {
                session_issue(issues, message_no, "MISSING_SEED", "fail", "successful seed response has no seed bytes")
              } else {
                security_seed_level = req_sub
              }
            } else if security_seed_level == req_sub - 1 {
              security_level = req_sub - 1
              security_seed_level = -1
            }
          }
          if req_sid == 0x10 {
            if payload.length() < 2 || payload[1] != req_sub {
              session_issue(
                issues,
                message_no,
                "SESSION_ECHO_MISMATCH",
                "fail",
                "requested session 0x" + hex_int(req_sub, 2) +
                " but ECU returned a missing or different session echo",
              )
            } else {
              current_session = session_name(req_sub)
              security_level = 0
              security_seed_level = -1
            }
          }
          // Positive response is final.
          remove_pending(slot, pending_step, pending_can, pending_sid, pending_sub)
        }
      }
    } else {
      session_issue(issues,message_no,"UNSUPPORTED_SERVICE","review","payload is outside the implemented UDS service range")
    }
  }
  for i in 0..<pending_can.length() {
    session_issue(
      issues,
      pending_step[i],
      "MISSING_RESPONSE",
      "fail",
      "request 0x" + hex_int(pending_sid[i], 2) + " has no response",
    )
  }
  if download_active {
    session_issue(issues, message_no, "DOWNLOAD_INCOMPLETE", "review", "capture ends before a successful RequestTransferExit")
  }
  let mut fail = false
  let mut review = false
  for item in issues {
    if item.severity == "fail" {
      fail = true
    } else {
      review = true
    }
  }
  {
    verdict: if fail { "fail" } else if review { "review" } else { "pass" },
    requests,
    responses,
    session: current_session,
    security_level,
    transferred_bytes,
    issues,
  }
}

pub(all) struct UdsEcuReport {
  channel : String
  request_id : Int
  report : UdsSessionReport
}

// Each physical ECU owns its own pending queue, session and security state.
fn analyze_uds_channel(text : String, channel : String) -> Array[UdsEcuReport] raise IsotpError {
  let messages = payloads_in_order(text)
  let ids : Array[Int] = []
  for message in messages {
    let id = if message.1 >= 0x7e8 && message.1 <= 0x7ef { message.1 - 8 } else { message.1 }
    if !ids.contains(id) { ids.push(id) }
  }
  let out : Array[UdsEcuReport] = []
  for id in ids {
    let group : Array[(Int, Int, Array[Int])] = []
    for message in messages {
      if message.1 == id || message.1 == expected_response_id(id) {
        group.push(message)
      }
    }
    out.push({ channel, request_id: id, report: analyze_uds_messages(group) })
  }
  out
}

// Reassembly and session state must never mix identical IDs from different buses.
pub fn analyze_uds_network(text : String) -> Array[UdsEcuReport] raise IsotpError {
  let channels : Array[String] = []
  let logs : Array[StringBuilder] = []
  let mut invalid = 0
  for raw in text.split("\n") {
    let line = raw.trim_space().to_string()
    if line.length() == 0 || line.has_prefix("#") { continue }
    match parse_candump_line(line) {
      None => invalid = invalid + 1
      Some(frame) => {
        let mut index = -1
        for i in 0..<channels.length() { if channels[i] == frame.channel { index = i } }
        if index < 0 { index = channels.length(); channels.push(frame.channel); logs.push(StringBuilder()) }
        logs[index].write_string(line + "\n")
      }
    }
  }
  let out : Array[UdsEcuReport] = []
  for i in 0..<channels.length() {
    for report in analyze_uds_channel(logs[i].to_string(),channels[i]) { out.push(report) }
  }
  if invalid > 0 {
    out.push({ channel: "<parse-errors>", request_id: -1, report: {
      verdict: "fail", requests: 0, responses: 0, session: "unknown", security_level: 0, transferred_bytes: 0,
      issues: [{ step: 0, code: "MALFORMED_CAPTURE", severity: "fail", detail: invalid.to_string() + " lines cannot be parsed" }],
    } })
  }
  out
}

pub fn analyze_uds_session(text : String) -> UdsSessionReport raise IsotpError {
  let ecus = analyze_uds_network(text)
  if ecus.length() == 1 { return ecus[0].report }
  let issues : Array[UdsSessionIssue] = []
  let mut requests = 0
  let mut responses = 0
  let mut verdict = "review"
  for ecu in ecus {
    requests = requests + ecu.report.requests
    responses = responses + ecu.report.responses
    for item in ecu.report.issues { issues.push(item) }
    if ecu.report.verdict == "fail" { verdict = "fail" }
  }
  if ecus.length() == 0 {
    session_issue(issues, 0, "EMPTY_CAPTURE", "review", "no diagnostic messages decoded")
  } else if verdict != "fail" {
    verdict = "pass"
    for ecu in ecus { if ecu.report.verdict == "review" { verdict = "review" } }
  }
  { verdict, requests, responses, session: "multiple/none; inspect per-ECU reports", security_level: 0, transferred_bytes: 0, issues }
}

// Transport-independent UDS payload audit; usable with CAN, DoIP, queues or
// software clients after the transport supplies direction and payload bytes.
pub(all) struct DirectedUdsPayload {
  is_request : Bool
  payload : Array[Int]
}

pub fn analyze_uds_exchange(messages : Array[DirectedUdsPayload]) -> UdsSessionReport {
  let items : Array[(Int, Int, Array[Int])] = []
  for i in 0..<messages.length() {
    items.push((i, if messages[i].is_request { 0x7e0 } else { 0x7e8 }, messages[i].payload))
  }
  let report = analyze_uds_messages(items)
  if messages.length() == 0 {
    { ..report, verdict: "review", issues: [{ step: 0, code: "EMPTY_CAPTURE", severity: "review", detail: "no UDS payloads provided" }] }
  } else { report }
}

pub fn analyze_uds_payload_log(text : String) -> UdsSessionReport raise IsotpError {
  let messages : Array[DirectedUdsPayload] = []
  for raw in text.split("\n") {
    let line = raw.trim_space().to_string()
    if line.length() == 0 || line.has_prefix("#") { continue }
    if !line.has_prefix(">>") && !line.has_prefix("<<") { raise InvalidLength(-1) }
    let payload = match hex_decode(line.substring(start=2)) {
      Some(bytes) => bytes
      None => raise InvalidLength(-1)
    }
    if payload.length() == 0 { raise EmptyPayload }
    messages.push({ is_request: line.has_prefix(">>"), payload })
  }
  analyze_uds_exchange(messages)
}

pub fn render_uds_session(report : UdsSessionReport) -> String {
  let out = StringBuilder()
  out.write_string("verdict: " + report.verdict + "\n")
  out.write_string("requests: " + report.requests.to_string() + "\n")
  out.write_string("responses: " + report.responses.to_string() + "\n")
  out.write_string("session: " + report.session + "\n")
  out.write_string("security level: " + report.security_level.to_string() + "\n")
  out.write_string("acknowledged transfer bytes: " + report.transferred_bytes.to_string() + "\n")
  for item in report.issues {
    out.write_string(
      "issue step=" + item.step.to_string() + " " + item.severity + " " +
      item.code + ": " + item.detail + "\n",
    )
  }
  out.to_string()
}
