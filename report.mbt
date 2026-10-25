// Session report: candump text -> ISO-TP -> UDS/OBD decoding.

pub(all) enum DiagEvent {
  UdsEvent(Int, UdsMessage)
  ObdEvent(Int, ObdMessage)
  RawEvent(Int, Array[Int])
}

pub(all) struct DiagReport {
  frame_count : Int
  events : Array[DiagEvent]
  errors : Array[String]
  incomplete_ids : Array[Int]
  negative_count : Int
  dtc_count : Int
}

fn slice(bytes : Array[Int], start : Int, end : Int) -> Array[Int] {
  let out : Array[Int] = Array::new()
  for i in start..<end {
    out.push(bytes[i])
  }
  out
}

pub fn ascii(bytes : Array[Int]) -> String {
  let out = StringBuilder()
  for b in bytes {
    if b >= 32 && b <= 126 {
      out.write_char(Char::from_int(b))
    } else {
      out.write_char('.')
    }
  }
  out.to_string()
}

fn describe_isotp_error(err : IsotpError) -> String {
  match err {
    EmptyFrame => "empty frame"
    EmptyPayload => "empty payload"
    InvalidFrameSize(n) => "invalid frame size " + n.to_string()
    InvalidLength(n) => "invalid length " + n.to_string()
    TooLarge(n) => "payload too large " + n.to_string()
    UnexpectedFirstFrame => "unexpected first frame"
    UnexpectedConsecutiveFrame => "unexpected consecutive frame"
    UnexpectedSingleFrame => "unexpected single frame"
    BadSequence(got, want) =>
      "bad sequence " + got.to_string() + ", expected " + want.to_string()
    Incomplete(got, want) =>
      "incomplete " + got.to_string() + " of " + want.to_string()
  }
}

fn classify(can_id : Int, payload : Array[Int]) -> DiagEvent {
  if payload.length() == 0 {
    return RawEvent(can_id, payload)
  }
  let sid = payload[0]
  if sid == 0x41 || sid == 0x43 || sid == 0x47 || sid == 0x4a {
    ObdEvent(can_id, parse_obd_message(payload))
  } else if sid == 0x7f || (sid >= 0x40 && sid <= 0x7e) {
    UdsEvent(can_id, parse_uds_message(payload))
  } else {
    RawEvent(can_id, payload)
  }
}

pub fn analyze_log(text : String) -> DiagReport {
  let frames = parse_candump(text)
  let events : Array[DiagEvent] = Array::new()
  let errors : Array[String] = Array::new()
  let incomplete : Array[Int] = Array::new()
  let ids : Array[Int] = Array::new()
  for frame in frames {
    let mut known = false
    for id in ids {
      if id == frame.id {
        known = true
        break
      }
    }
    if !known {
      ids.push(frame.id)
    }
  }
  for id in ids {
    let mut reasm = IsotpReassembler::new()
    for frame in frames {
      if frame.id == id {
        let result = try {
          reasm.push(frame.data)
        } catch {
          err => {
            errors.push(
              "CAN 0x" + hex_can_id(id) + ": " + describe_isotp_error(err),
            )
            reasm = IsotpReassembler::new()
            None
          }
        }
        match result {
          Some(payload) => events.push(classify(id, payload))
          None => ()
        }
      }
    }
    if reasm.is_active() {
      incomplete.push(id)
    }
  }
  let mut negative = 0
  let mut dtcs = 0
  for event in events {
    match event {
      UdsEvent(_, message) =>
        match message {
          Negative(_, _, _) => negative = negative + 1
          Positive(sid, data) =>
            if sid == 0x59 && data.length() >= 2 {
              let full : Array[Int] = [0x59]
              for b in data {
                full.push(b)
              }
              match parse_dtc_response(full) {
                Some(list) => dtcs = dtcs + list.length()
                None => ()
              }
            }
          Malformed(_) => ()
        }
      ObdEvent(_, message) =>
        match message {
          DtcResponse(_, list) => dtcs = dtcs + list.length()
          _ => ()
        }
      RawEvent(_, _) => ()
    }
  }
  {
    frame_count: frames.length(),
    events,
    errors,
    incomplete_ids: incomplete,
    negative_count: negative,
    dtc_count: dtcs,
  }
}

fn describe_uds(can_id : Int, message : UdsMessage) -> String {
  let head = "CAN 0x" + hex_can_id(can_id) + " UDS "
  match message {
    Positive(sid, data) => {
      let service = sid - 0x40
      let name = uds_service_name(service)
      if service == 0x22 && data.length() >= 2 {
        let full : Array[Int] = [sid]
        for b in data {
          full.push(b)
        }
        match parse_did_response(full) {
          Some((did, value)) =>
            head + name + " DID 0x" + hex_int(did, 4) + " = \"" + ascii(value) +
            "\" [" + hex_encode(value) + "]"
          None => head + name
        }
      } else if service == 0x19 {
        let full : Array[Int] = [sid]
        for b in data {
          full.push(b)
        }
        match parse_dtc_response(full) {
          Some(list) => {
            let out = StringBuilder()
            out.write_string(head + name + " DTCs:")
            for d in list {
              out.write_string(" " + d.code)
            }
            out.to_string()
          }
          None => head + name + " (" + data.length().to_string() + " bytes)"
        }
      } else {
        head + name + " [" + hex_encode(data) + "]"
      }
    }
    Negative(service, nrc, reason) =>
      head + "Negative 0x" + hex_int(service, 2) + " NRC 0x" + hex_int(nrc, 2) +
      " " + reason
    Malformed(reason) => head + "Malformed: " + reason
  }
}

fn describe_obd(can_id : Int, message : ObdMessage) -> String {
  let head = "CAN 0x" + hex_can_id(can_id) + " OBD "
  match message {
    Mode01(pid, bytes) =>
      match decode_obd_pid(pid, slice(bytes, 2, bytes.length())) {
        Some(r) =>
          head + "PID 0x" + hex_int(pid, 2) + " " + r.label + " = " + r.value +
          (if r.unit.length() > 0 { " " + r.unit } else { "" })
        None => head + "PID 0x" + hex_int(pid, 2) + " unsupported"
      }
    DtcResponse(mode, dtcs) => {
      let out = StringBuilder()
      out.write_string(head + "mode 0x" + hex_int(mode, 2) + " DTCs:")
      for d in dtcs {
        out.write_string(" " + d.code)
      }
      out.to_string()
    }
    Unknown(bytes) => head + "unrecognized [" + hex_encode(bytes) + "]"
  }
}

pub fn render_report(report : DiagReport) -> String {
  let out = StringBuilder()
  out.write_string("frames: " + report.frame_count.to_string() + "\n")
  out.write_string("messages: " + report.events.length().to_string() + "\n")
  out.write_string("negative responses: " + report.negative_count.to_string() + "\n")
  out.write_string("DTCs: " + report.dtc_count.to_string() + "\n")
  if report.incomplete_ids.length() > 0 {
    out.write_string("incomplete ISO-TP ids:")
    for id in report.incomplete_ids {
      out.write_string(" 0x" + hex_can_id(id))
    }
    out.write_string("\n")
  }
  for event in report.events {
    match event {
      UdsEvent(id, message) => out.write_string(describe_uds(id, message) + "\n")
      ObdEvent(id, message) => out.write_string(describe_obd(id, message) + "\n")
      RawEvent(id, payload) =>
        out.write_string(
          "CAN 0x" + hex_can_id(id) + " raw [" + hex_encode(payload) + "]\n",
        )
    }
  }
  for error in report.errors {
    out.write_string("error: " + error + "\n")
  }
  out.to_string()
}

fn json_escape(text : String) -> String {
  let out = StringBuilder()
  for i in 0..<text.length() {
    let c = text[i].to_int()
    if c == 34 {
      out.write_string("\\\"")
    } else if c == 92 {
      out.write_string("\\\\")
    } else if c == 10 {
      out.write_string("\\n")
    } else if c == 13 {
      out.write_string("\\r")
    } else if c == 9 {
      out.write_string("\\t")
    } else if c < 32 {
      out.write_string("\\u00")
      out.write_char(hex_nibble_char(c >> 4))
      out.write_char(hex_nibble_char(c))
    } else {
      out.write_char(Char::from_int(c))
    }
  }
  out.to_string()
}

fn json_string(text : String) -> String {
  "\"" + json_escape(text) + "\""
}

fn quoted_array(items : Array[String]) -> String {
  "[" + items.join(",") + "]"
}

fn dtc_json(list : Array[Dtc]) -> String {
  let items : Array[String] = Array::new()
  for d in list {
    items.push(
      "{\"code\":" + json_string(d.code) + ",\"failureType\":" +
      json_string("0x" + hex_int(d.failure_type, 2)) + ",\"status\":" +
      json_string("0x" + hex_int(d.status, 2)) + "}",
    )
  }
  quoted_array(items)
}

fn uds_event_json(can_id : Int, message : UdsMessage) -> String {
  let can = json_string("0x" + hex_can_id(can_id))
  match message {
    Positive(sid, data) => {
      let service = sid - 0x40
      let fields : Array[String] = [
        "\"canId\":" + can,
        "\"kind\":\"uds\"",
        "\"positive\":true",
        "\"service\":" + json_string("0x" + hex_int(service, 2)),
        "\"serviceName\":" + json_string(uds_service_name(service)),
        "\"data\":" + json_string(hex_encode(data)),
      ]
      if service == 0x22 && data.length() >= 2 {
        let full : Array[Int] = [sid]
        for b in data {
          full.push(b)
        }
        match parse_did_response(full) {
          Some((did, value)) => {
            fields.push("\"did\":" + json_string("0x" + hex_int(did, 4)))
            fields.push("\"value\":" + json_string(hex_encode(value)))
            fields.push("\"ascii\":" + json_string(ascii(value)))
          }
          None => ()
        }
      } else if service == 0x19 {
        let full : Array[Int] = [sid]
        for b in data {
          full.push(b)
        }
        match parse_dtc_response(full) {
          Some(list) => fields.push("\"dtcs\":" + dtc_json(list))
          None => ()
        }
      }
      "{" + fields.join(",") + "}"
    }
    Negative(service, nrc, reason) => {
      let fields : Array[String] = [
        "\"canId\":" + can,
        "\"kind\":\"uds\"",
        "\"positive\":false",
        "\"service\":" + json_string("0x" + hex_int(service, 2)),
        "\"nrc\":" + json_string("0x" + hex_int(nrc, 2)),
        "\"reason\":" + json_string(reason),
      ]
      "{" + fields.join(",") + "}"
    }
    Malformed(reason) =>
      "{\"canId\":" + can + ",\"kind\":\"uds\",\"malformed\":" +
      json_string(reason) + "}"
  }
}

fn obd_event_json(can_id : Int, message : ObdMessage) -> String {
  let can = json_string("0x" + hex_can_id(can_id))
  match message {
    Mode01(pid, bytes) => {
      let data = slice(bytes, 2, bytes.length())
      match decode_obd_pid(pid, data) {
        Some(r) =>
          "{\"canId\":" + can + ",\"kind\":\"obd\",\"mode\":\"0x41\"," +
          "\"pid\":" + json_string("0x" + hex_int(pid, 2)) + ",\"label\":" +
          json_string(r.label) + ",\"value\":" + json_string(r.value) +
          ",\"unit\":" + json_string(r.unit) + "}"
        None =>
          "{\"canId\":" + can + ",\"kind\":\"obd\",\"mode\":\"0x41\"," +
          "\"pid\":" + json_string("0x" + hex_int(pid, 2)) +
          ",\"supported\":false}"
      }
    }
    DtcResponse(mode, dtcs) =>
      "{\"canId\":" + can + ",\"kind\":\"obd\",\"mode\":" +
      json_string("0x" + hex_int(mode, 2)) + ",\"dtcs\":" + dtc_json(dtcs) +
      "}"
    Unknown(bytes) =>
      "{\"canId\":" + can + ",\"kind\":\"obd\",\"unknown\":" +
      json_string(hex_encode(bytes)) + "}"
  }
}

pub fn render_json(report : DiagReport) -> String {
  let events : Array[String] = Array::new()
  for event in report.events {
    match event {
      UdsEvent(id, message) => events.push(uds_event_json(id, message))
      ObdEvent(id, message) => events.push(obd_event_json(id, message))
      RawEvent(id, payload) =>
        events.push(
          "{\"canId\":" + json_string("0x" + hex_can_id(id)) +
          ",\"kind\":\"raw\",\"payload\":" + json_string(hex_encode(payload)) +
          "}",
        )
    }
  }
  let incomplete : Array[String] = Array::new()
  for id in report.incomplete_ids {
    incomplete.push(json_string("0x" + hex_can_id(id)))
  }
  let errors : Array[String] = Array::new()
  for error in report.errors {
    errors.push(json_string(error))
  }
  "{\"frames\":" + report.frame_count.to_string() + ",\"messages\":" +
  report.events.length().to_string() + ",\"negativeResponses\":" +
  report.negative_count.to_string() + ",\"dtcs\":" +
  report.dtc_count.to_string() + ",\"incompleteIsoTpIds\":" +
  quoted_array(incomplete) + ",\"events\":[" + events.join(",") +
  "],\"errors\":" + quoted_array(errors) + "}"
}

fn csv_field(text : String) -> String {
  let out = StringBuilder()
  out.write_char('"')
  for i in 0..<text.length() {
    let c = text[i].to_int()
    if c == 34 {
      out.write_string("\"\"")
    } else {
      out.write_char(Char::from_int(c))
    }
  }
  out.write_char('"')
  out.to_string()
}

pub fn render_csv(report : DiagReport) -> String {
  let out = StringBuilder()
  out.write_string("can_id,kind,detail\n")
  for event in report.events {
    match event {
      UdsEvent(id, message) =>
        out.write_string(
          "0x" + hex_can_id(id) + ",uds," +
          csv_field(describe_uds(id, message)) + "\n",
        )
      ObdEvent(id, message) =>
        out.write_string(
          "0x" + hex_can_id(id) + ",obd," +
          csv_field(describe_obd(id, message)) + "\n",
        )
      RawEvent(id, payload) =>
        out.write_string(
          "0x" + hex_can_id(id) + ",raw," + csv_field(hex_encode(payload)) +
          "\n",
        )
    }
  }
  out.to_string()
}

pub(all) struct IdSummary {
  can_id : Int
  messages : Int
  negatives : Int
}

pub fn summarize_by_id(report : DiagReport) -> Array[IdSummary] {
  let ids : Array[Int] = Array::new()
  let counts : Array[Int] = Array::new()
  let negatives : Array[Int] = Array::new()
  for event in report.events {
    let id = match event {
      UdsEvent(id, _) => id
      ObdEvent(id, _) => id
      RawEvent(id, _) => id
    }
    let mut slot = -1
    for i in 0..<ids.length() {
      if ids[i] == id {
        slot = i
        break
      }
    }
    if slot < 0 {
      ids.push(id)
      counts.push(0)
      negatives.push(0)
      slot = ids.length() - 1
    }
    counts[slot] = counts[slot] + 1
    match event {
      UdsEvent(_, Negative(_, _, _)) =>
        negatives[slot] = negatives[slot] + 1
      _ => ()
    }
  }
  let out : Array[IdSummary] = Array::new()
  for i in 0..<ids.length() {
    out.push({ can_id: ids[i], messages: counts[i], negatives: negatives[i] })
  }
  out
}
