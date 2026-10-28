// Generated UDS session fixtures.

fn uds_happy() -> String { "can0 7E0 [8] 02 10 03 00 00 00 00 00\ncan0 7E8 [8] 06 50 03 00 32 01 F4 00\ncan0 7E0 [8] 03 22 F1 90 00 00 00 00\ncan0 7E8 [8] 06 62 F1 90 31 32 33 00\ncan0 7E0 [8] 02 3E 80 00 00 00 00 00\ncan0 7E0 [8] 02 10 01 00 00 00 00 00\ncan0 7E8 [8] 06 50 01 00 32 01 F4 00" }
fn uds_missing() -> String { "can0 7E0 [8] 03 22 F1 90 00 00 00 00" }
fn uds_orphan() -> String { "can0 7E8 [8] 06 62 F1 90 31 32 33 00" }
fn uds_service() -> String { "can0 7E0 [8] 02 10 03 00 00 00 00 00\ncan0 7E8 [8] 06 62 F1 90 31 32 33 00" }
fn uds_negative() -> String { "can0 7E0 [8] 03 22 F1 90 00 00 00 00\ncan0 7E8 [8] 03 7F 22 31 00 00 00 00" }
fn uds_pending() -> String { "can0 7E0 [8] 03 22 F1 90 00 00 00 00\ncan0 7E8 [8] 03 7F 22 78 00 00 00 00\ncan0 7E8 [8] 06 62 F1 90 31 32 33 00" }
fn uds_security() -> String { "can0 7E0 [8] 04 27 02 AA BB 00 00 00\ncan0 7E8 [8] 04 67 02 AA BB 00 00 00" }
fn uds_echo() -> String { "can0 7E0 [8] 02 10 03 00 00 00 00 00\ncan0 7E8 [8] 06 50 01 00 32 01 F4 00" }

///|
test "UDS session happy path passes" {
  let report = analyze_uds_session(uds_happy())
  assert_eq(report.verdict, "pass")
  assert_eq(report.requests, 4)
  assert_eq(report.responses, 3)
  assert_eq(report.session, "default")
  assert_eq(report.issues.length(), 0)
}

///|
test "UDS session detects missing response" {
  let report = analyze_uds_session(uds_missing())
  assert_eq(report.verdict, "fail")
  let mut found = false
  for issue in report.issues {
    if issue.code == "MISSING_RESPONSE" { found = true }
  }
  assert_true(found)
}

///|
test "UDS session detects orphan response" {
  let report = analyze_uds_session(uds_orphan())
  assert_eq(report.verdict, "fail")
  let mut found = false
  for issue in report.issues {
    if issue.code == "ORPHAN_RESPONSE" { found = true }
  }
  assert_true(found)
}

///|
test "UDS session detects service mismatch" {
  let report = analyze_uds_session(uds_service())
  assert_eq(report.verdict, "fail")
  let mut found = false
  for issue in report.issues {
    if issue.code == "SERVICE_MISMATCH" { found = true }
  }
  assert_true(found)
}

///|
test "UDS session reports negative response as review" {
  let report = analyze_uds_session(uds_negative())
  assert_eq(report.verdict, "review")
  let mut found = false
  for issue in report.issues {
    if issue.code == "NEGATIVE_RESPONSE" { found = true }
  }
  assert_true(found)
}

///|
test "UDS session keeps a pending request until the final response" {
  let report = analyze_uds_session(uds_pending())
  assert_eq(report.verdict, "review")
  assert_eq(report.responses, 2)
  let mut found = false
  for issue in report.issues {
    if issue.code == "PENDING_RESPONSE" { found = true }
  }
  assert_true(found)
}

///|
test "UDS session rejects key send without seed" {
  let report = analyze_uds_session(uds_security())
  assert_eq(report.verdict, "fail")
  let mut found = false
  for issue in report.issues {
    if issue.code == "SECURITY_SEQUENCE" { found = true }
  }
  assert_true(found)
}

///|
test "UDS session checks the session echo" {
  let report = analyze_uds_session(uds_echo())
  assert_eq(report.verdict, "fail")
  let mut found = false
  for issue in report.issues {
    if issue.code == "SESSION_ECHO_MISMATCH" { found = true }
  }
  assert_true(found)
}
