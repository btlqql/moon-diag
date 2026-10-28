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
  }
  messages.sort_by(fn(a, b) { a.0 - b.0 })
  messages
}

pub fn analyze_uds_session(text : String) -> UdsSessionReport raise IsotpError {
  let messages = payloads_in_order(text)
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
        if (sub & 1) == 1 {
          security_seed_level = sub
        } else if security_seed_level != sub - 1 {
          session_issue(
            issues,
            message_no,
            "SECURITY_SEQUENCE",
            "fail",
            "key send 0x" + hex_int(sub, 2) + " without matching seed request",
          )
        } else {
          security_level = sub - 1
          security_seed_level = -1
        }
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
          if req_sid == 0x10 {
            if payload.length() > 1 && payload[1] != req_sub {
              session_issue(
                issues,
                message_no,
                "SESSION_ECHO_MISMATCH",
                "fail",
                "requested session 0x" + hex_int(req_sub, 2) +
                " but ECU echoed 0x" + hex_int(payload[1], 2),
              )
            } else {
              current_session = session_name(req_sub)
            }
          }
          // Positive response is final.
          remove_pending(slot, pending_step, pending_can, pending_sid, pending_sub)
        }
      }
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
    issues,
  }
}

pub fn render_uds_session(report : UdsSessionReport) -> String {
  let out = StringBuilder()
  out.write_string("verdict: " + report.verdict + "\n")
  out.write_string("requests: " + report.requests.to_string() + "\n")
  out.write_string("responses: " + report.responses.to_string() + "\n")
  out.write_string("session: " + report.session + "\n")
  out.write_string("security level: " + report.security_level.to_string() + "\n")
  for item in report.issues {
    out.write_string(
      "issue step=" + item.step.to_string() + " " + item.severity + " " +
      item.code + ": " + item.detail + "\n",
    )
  }
  out.to_string()
}
