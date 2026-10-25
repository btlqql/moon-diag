// Core checks for the diagnostic toolkit.

fn h(text : String) -> Array[Int] raise Failure {
  match hex_decode(text) {
    Some(bytes) => bytes
    None => fail("invalid test hex: " + text)
  }
}

fn arrays_equal(a : Array[Int], b : Array[Int]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i in 0..<a.length() {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

fn frame(line : String) -> CanFrame raise Failure {
  match parse_candump_line(line) {
    Some(f) => f
    None => fail("invalid candump line: " + line)
  }
}

fn payload_of(frames : Array[Array[Int]]) -> Array[Int] raise IsotpError {
  let reasm = IsotpReassembler::new()
  let mut out : Array[Int] = Array::new()
  for f in frames {
    match reasm.push(f) {
      Some(p) => out = p
      None => ()
    }
  }
  out
}

///|
test "hex codec accepts separators and rejects odd nibbles" {
  assert_eq(hex_encode(h("01 02 aB")), "01 02 AB")
  assert_eq(h("01:02-AB").length(), 3)
  assert_true(hex_decode("0") is None)
  assert_true(hex_decode("zz") is None)
}

///|
test "candump classic and log formats parse" {
  let a = frame("can0 7E8 [8] 02 10 03 00 00 00 00 00")
  assert_eq(a.id, 0x7e8)
  assert_eq(a.extended, false)
  assert_eq(a.data.length(), 8)
  let b = frame("(1690000000.123) vcan0 18DAF110#0210030000000000")
  assert_eq(b.id, 0x18daf110)
  assert_eq(b.extended, true)
  assert_eq(b.channel, "vcan0")
  assert_eq(b.data.length(), 8)
  assert_true(parse_candump_line("garbage") is None)
}

///|
test "ISO-TP single frame and segmented payloads round-trip" {
  let small = h("01 02 03")
  let frames = segment(small)
  assert_eq(frames.length(), 1)
  assert_true(arrays_equal(payload_of(frames), small))
  let big = h("62 F1 90 31 32 33 34 35 36 37 38 39 30 41 42 43 44 45 46 47")
  let parts = segment(big)
  assert_eq(parts.length(), 3)
  assert_true(arrays_equal(payload_of(parts), big))
}

///|
test "ISO-TP rejects sequence and length errors" {
  let reasm = IsotpReassembler::new()
  assert_true(reasm.push(h("10 0A 01 02 03 04 05 06")) is None)
  let bad = try {
    ignore(reasm.push(h("22 07 08 09 0A 0B 0C 0D")))
    false
  } catch {
    _ => true
  }
  assert_true(bad)
  let short = try {
    ignore(IsotpReassembler::new().push(h("05 01 02")))
    false
  } catch {
    _ => true
  }
  assert_true(short)
}

///|
test "DTC decode and status bits" {
  let d = decode_dtc(0x03, 0x01, status=0x2f)
  assert_eq(d.code, "P0301")
  assert_eq(d.system, "Powertrain")
  assert_true(d.status_bits.length() == 5)
  let u = decode_dtc(0xC1, 0x23)
  assert_eq(u.code, "U0123")
  assert_eq(u.system, "Network")
}

///|
test "UDS request builders" {
  assert_eq(hex_encode(request_session_control(0x03)), "10 03")
  assert_eq(hex_encode(request_read_did(0xF190)), "22 F1 90")
  assert_eq(hex_encode(request_write_did(0xF190, h("41 42"))), "2E F1 90 41 42")
  assert_eq(hex_encode(request_security_access(0x01)), "27 01")
  assert_eq(hex_encode(request_security_access(0x01, key=h("AA BB"))), "27 02 AA BB")
  assert_eq(hex_encode(request_tester_present()), "3E 80")
  assert_eq(hex_encode(request_read_dtc_by_status(0xFF)), "19 02 FF")
  assert_eq(hex_encode(request_clear_dtc(0xFFFFFF)), "14 FF FF FF")
}

///|
test "UDS responses decode positive, negative and DTC payloads" {
  match parse_uds_message(h("7F 22 31")) {
    Negative(service, nrc, reason) => {
      assert_eq(service, 0x22)
      assert_eq(nrc, 0x31)
      assert_eq(reason, "requestOutOfRange")
    }
    _ => fail("expected a negative response")
  }
  match parse_uds_message(h("62 F1 90 31 32 33")) {
    Positive(sid, data) => {
      assert_eq(sid, 0x62)
      let full : Array[Int] = [sid]
      for b in data {
        full.push(b)
      }
      match parse_did_response(full) {
        Some((did, value)) => {
          assert_eq(did, 0xF190)
          assert_eq(ascii(value), "123")
        }
        None => fail("DID response should parse")
      }
    }
    _ => fail("expected a positive response")
  }
  match parse_dtc_response(h("59 02 FF 03 01 2F 00 00 00")) {
    Some(list) => {
      assert_eq(list.length(), 1)
      assert_eq(list[0].code, "P0301-2F")
      assert_eq(list[0].failure_type, 0x2f)
      assert_eq(list[0].status, 0)
    }
    None => fail("DTC response should parse")
  }
}

///|
test "OBD-II PID decoding" {
  match decode_obd_pid(0x0C, h("1A F8")) {
    Some(r) => {
      assert_eq(r.value, "1726")
      assert_eq(r.unit, "rpm")
    }
    None => fail("RPM PID should decode")
  }
  match decode_obd_pid(0x05, h("7B")) {
    Some(r) => assert_eq(r.value, "83")
    None => fail("coolant PID should decode")
  }
  match decode_obd_pid(0x0D, h("50")) {
    Some(r) => assert_eq(r.value, "80")
    None => fail("speed PID should decode")
  }
  match decode_obd_pid(0x2F, h("80")) {
    Some(r) => assert_eq(r.value, "50.2")
    None => fail("fuel level PID should decode")
  }
  match parse_obd_message(h("43 01 03 01 00 00")) {
    DtcResponse(_, dtcs) => {
      assert_eq(dtcs.length(), 1)
      assert_eq(dtcs[0].code, "P0301")
    }
    _ => fail("mode 03 response should decode")
  }
}

///|
test "session report groups frames and keeps counts" {
  let log = [
    "can0 7E8 [8] 03 7F 22 31 00 00 00 00",
    "can0 7E8 [8] 10 14 62 F1 90 31 32 33",
    "can0 7E8 [8] 21 34 35 36 37 38 39 30",
    "can0 7E8 [8] 22 41 42 43 44 45 46 47",
    "can0 7E0 [8] 06 41 0C 1A F8 00 00 00",
  ].join("\n")
  let report = analyze_log(log)
  assert_eq(report.frame_count, 5)
  assert_eq(report.events.length(), 3)
  assert_eq(report.negative_count, 1)
  assert_eq(report.dtc_count, 0)
  let text = render_report(report)
  assert_true(text.contains("P0301") == false)
  assert_true(text.contains("1726"))
  assert_true(text.contains("1234567890ABCDEFG"))
}

///|
test "incomplete ISO-TP transfer is reported" {
  let report = analyze_log("can0 7E8 [8] 10 14 62 F1 90 31 32 33")
  assert_eq(report.incomplete_ids.length(), 1)
  assert_eq(report.events.length(), 0)
}

///|
test "JSON report carries counts and event kinds" {
  let log = [
    "can0 7E8 [8] 03 7F 22 31 00 00 00 00",
    "can0 7E0 [8] 06 41 0C 1A F8 00 00 00",
  ].join("\n")
  let json = render_json(analyze_log(log))
  assert_true(json.contains("\"frames\":2"))
  assert_true(json.contains("\"negativeResponses\":1"))
  assert_true(json.contains("\"kind\":\"uds\""))
  assert_true(json.contains("\"kind\":\"obd\""))
  assert_true(json.contains("\"reason\":\"requestOutOfRange\""))
}

///|
test "OBD mode 09 VIN extraction" {
  let vin_bytes = h("31 32 33 34 35 36 37 38 39 30 41 42 43 44 45 46 47")
  let payload : Array[Int] = [0x49, 0x02, 0x01]
  for b in vin_bytes {
    payload.push(b)
  }
  assert_eq(parse_obd_vin(payload), Some("1234567890ABCDEFG"))
  assert_true(parse_obd_vin(h("49 02")) is None)
}

///|
test "OBD mode 06 monitor result" {
  match parse_obd_mode06(h("46 01 01 01 12 34 00 00")) {
    Some(r) => {
      assert_eq(r.mid, 1)
      assert_eq(r.tid, 1)
      assert_eq(r.unit, 1)
      assert_eq(r.value, 0x1234)
    }
    None => fail("mode 06 response should decode")
  }
  assert_true(parse_obd_mode06(h("46 01")) is None)
}

///|
test "CSV report includes one row per message" {
  let log = [
    "can0 7E8 [8] 03 7F 22 31 00 00 00 00",
    "can0 7E0 [8] 06 41 0C 1A F8 00 00 00",
  ].join("\n")
  let csv = render_csv(analyze_log(log))
  assert_true(csv.has_prefix("can_id,kind,detail\n"))
  assert_true(csv.contains("0x7E8,uds,"))
  assert_true(csv.contains("0x7E0,obd,"))
  assert_true(csv.contains("requestOutOfRange"))
}

///|
test "summary groups messages by CAN id" {
  let log = [
    "can0 7E8 [8] 03 7F 22 31 00 00 00 00",
    "can0 7E8 [8] 02 10 03 00 00 00 00 00",
    "can0 7E0 [8] 06 41 0C 1A F8 00 00 00",
  ].join("\n")
  let summary = summarize_by_id(analyze_log(log))
  assert_eq(summary.length(), 2)
  assert_eq(summary[0].can_id, 0x7e8)
  assert_eq(summary[0].negatives, 1)
  assert_eq(summary[1].can_id, 0x7e0)
}

///|
test "DTC status filter keeps matching records" {
  let list : Array[Dtc] = [
    decode_uds_dtc(0x03, 0x01, 0x2f, 0x2f),
    decode_uds_dtc(0x03, 0x02, 0x00, 0x01),
  ]
  let confirmed = filter_dtcs_by_status(list, 0x08)
  assert_eq(confirmed.length(), 1)
  assert_eq(confirmed[0].code, "P0301-2F")
}

///|
test "flow-control frames are counted and ignored" {
  let reasm = IsotpReassembler::new()
  assert_true(reasm.push(h("30 00 00 00 00 00 00 00")) is None)
  assert_eq(reasm.flow_control_count(), 1)
  assert_true(!reasm.is_active())
}
