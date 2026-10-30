// Requests emitted and responses verified by the real udsoncan Client.
test "udsoncan client download is audited from transport-independent payloads" {
  let r = analyze_uds_payload_log(">> 10 03\n<< 50 03 00 32 01 F4\n>> 27 01\n<< 67 01 11 22\n>> 27 02 33 44\n<< 67 02\n>> 34 00 12 10 00 08\n<< 74 10 06\n>> 36 01 01 02 03 04\n<< 76 01\n>> 36 02 05 06 07 08\n<< 76 02\n>> 37\n<< 77\n")
  assert_eq(r.verdict,"pass")
  assert_eq(r.transferred_bytes,8)
  assert_eq(r.security_level,1)
}
test "mutating client memorySize is detected despite locally valid responses" {
  let r = analyze_uds_payload_log(">> 10 03\n<< 50 03 00 32 01 F4\n>> 27 01\n<< 67 01 11 22\n>> 27 02 33 44\n<< 67 02\n>> 34 00 12 10 00 09\n<< 74 10 06\n>> 36 01 01 02 03 04\n<< 76 01\n>> 36 02 05 06 07 08\n<< 76 02\n>> 37\n<< 77\n")
  assert_eq(r.verdict,"fail")
  assert_true(r.issues.any(fn(x) { x.code == "TRANSFER_SIZE_MISMATCH" }))
}
