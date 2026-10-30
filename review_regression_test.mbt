test "negative key response cannot unlock security" {
  let r = analyze_uds_session("can0 7E0 [3] 02 27 01\ncan0 7E8 [4] 03 67 01 11\ncan0 7E0 [4] 03 27 02 22\ncan0 7E8 [4] 03 7F 27 35")
  assert_eq(r.security_level, 0)
  assert_eq(r.verdict, "review")
}

test "only acknowledged key unlocks security" {
  let r = analyze_uds_session("can0 7E0 [3] 02 27 01\ncan0 7E8 [4] 03 67 01 11\ncan0 7E0 [4] 03 27 02 22\ncan0 7E8 [3] 02 67 02")
  assert_eq(r.security_level, 1)
  assert_eq(r.verdict, "pass")
}

test "seed from one ECU cannot authorize another ECU" {
  let r = analyze_uds_network("can0 7E0 [3] 02 27 01\ncan0 7E8 [4] 03 67 01 11\ncan0 7E1 [4] 03 27 02 22\ncan0 7E9 [3] 02 67 02")
  assert_eq(r.length(), 2)
  assert_eq(r[0].report.verdict, "pass")
  assert_eq(r[1].report.verdict, "fail")
  assert_eq(r[1].report.security_level, 0)
}

test "Read DID detects a matching service with wrong identifier" {
  let r = analyze_uds_session("can0 7E0 [4] 03 22 F1 90\ncan0 7E8 [5] 04 62 F1 91 00")
  assert_true(r.issues.any(fn(x) { x.code == "DID_ECHO_MISMATCH" }))
}

fn download_log() -> String {
  "can0 7E0 [7] 06 34 00 12 10 00 04\ncan0 7E8 [4] 03 74 10 06\ncan0 7E0 [7] 06 36 01 11 22 33 44\ncan0 7E8 [3] 02 76 01\ncan0 7E0 [2] 01 37\ncan0 7E8 [2] 01 77"
}

test "download verifies acknowledged bytes and exit size" {
  let r = analyze_uds_session(download_log())
  assert_eq(r.verdict, "pass")
  assert_eq(r.transferred_bytes, 4)
  let bad = analyze_uds_session(download_log().replace(old="10 00 04", new="10 00 05"))
  assert_true(bad.issues.any(fn(x) { x.code == "TRANSFER_SIZE_MISMATCH" }))
}

test "download rejects a skipped block counter" {
  let r = analyze_uds_session(download_log().replace(old="36 01", new="36 02").replace(old="76 01", new="76 02"))
  assert_true(r.issues.any(fn(x) { x.code == "BLOCK_SEQUENCE" }))
}

test "empty diagnostic capture is review" {
  assert_eq(analyze_uds_session("").verdict, "review")
}

test "exact acknowledged retransmission is not counted twice" {
  let log = download_log().replace(old="can0 7E0 [2] 01 37", new="can0 7E0 [7] 06 36 01 11 22 33 44\ncan0 7E8 [3] 02 76 01\ncan0 7E0 [2] 01 37")
  let r = analyze_uds_session(log)
  assert_eq(r.verdict, "pass")
  assert_eq(r.transferred_bytes, 4)
}

test "negotiated block size is enforced" {
  let r = analyze_uds_session(download_log().replace(old="74 10 06", new="74 10 05"))
  assert_true(r.issues.any(fn(x) { x.code == "BLOCK_TOO_LARGE" }))
}

test "compressed downloads are rejected rather than size-audited as plaintext" {
  let r = analyze_uds_session(download_log().replace(old="34 00", new="34 10"))
  assert_true(r.issues.any(fn(x) { x.code == "UNSUPPORTED_DOWNLOAD_FORMAT" }))
}

test "identical IDs on different interfaces never share session security or reassembly" {
  let r = analyze_uds_network("can0 7E0 [3] 02 27 01\ncan0 7E8 [4] 03 67 01 11\ncan1 7E0 [4] 03 27 02 22\ncan1 7E8 [3] 02 67 02")
  assert_eq(r.length(),2)
  assert_eq(r[0].channel,"can0")
  assert_eq(r[1].channel,"can1")
  assert_eq(r[1].report.security_level,0)
  assert_eq(r[1].report.verdict,"fail")
}

test "malformed lines cannot disappear from a successful audit" {
  assert_eq(analyze_uds_session("this is not a CAN frame").verdict,"fail")
}

test "block counter wraps from FF to 00" {
  let header = "can0 7E0 [8] 07 34 00 22 10 00 01 00\ncan0 7E8 [4] 03 74 10 03\n"
  let body = StringBuilder()
  body.write_string(header)
  for i in 1..<257 {
    let block = hex_int(i & 255, 2)
    body.write_string("can0 7E0 [4] 03 36 " + block + " 11\ncan0 7E8 [3] 02 76 " + block + "\n")
  }
  body.write_string("can0 7E0 [2] 01 37\ncan0 7E8 [2] 01 77")
  let r = analyze_uds_session(body.to_string())
  assert_eq(r.verdict, "pass")
  assert_eq(r.transferred_bytes, 256)
}
