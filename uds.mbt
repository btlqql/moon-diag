// UDS (ISO 14229) request builders and response decoding.
// Security-access algorithms are intentionally out of scope; the toolkit builds
// seed/key frames and reports NRCs, it does not implement OEM secrets.

pub(all) enum UdsMessage {
  Positive(Int, Array[Int])
  Negative(Int, Int, String)
  Malformed(String)
}

pub fn uds_service_name(service : Int) -> String {
  if service == 0x10 {
    "DiagnosticSessionControl"
  } else if service == 0x11 {
    "ECUReset"
  } else if service == 0x14 {
    "ClearDiagnosticInformation"
  } else if service == 0x19 {
    "ReadDTCInformation"
  } else if service == 0x22 {
    "ReadDataByIdentifier"
  } else if service == 0x27 {
    "SecurityAccess"
  } else if service == 0x28 {
    "CommunicationControl"
  } else if service == 0x2E {
    "WriteDataByIdentifier"
  } else if service == 0x31 {
    "RoutineControl"
  } else if service == 0x34 {
    "RequestDownload"
  } else if service == 0x36 {
    "TransferData"
  } else if service == 0x37 {
    "RequestTransferExit"
  } else if service == 0x3E {
    "TesterPresent"
  } else if service == 0x85 {
    "ControlDTCSetting"
  } else {
    "Unknown"
  }
}

pub fn nrc_description(nrc : Int) -> String {
  if nrc == 0x10 {
    "generalReject"
  } else if nrc == 0x11 {
    "serviceNotSupported"
  } else if nrc == 0x12 {
    "subFunctionNotSupported"
  } else if nrc == 0x13 {
    "incorrectMessageLengthOrInvalidFormat"
  } else if nrc == 0x14 {
    "responseTooLong"
  } else if nrc == 0x21 {
    "busyRepeatRequest"
  } else if nrc == 0x22 {
    "conditionsNotCorrect"
  } else if nrc == 0x24 {
    "requestSequenceError"
  } else if nrc == 0x25 {
    "noResponseFromSubnetComponent"
  } else if nrc == 0x26 {
    "failurePreventsExecutionOfRequestedAction"
  } else if nrc == 0x31 {
    "requestOutOfRange"
  } else if nrc == 0x33 {
    "securityAccessDenied"
  } else if nrc == 0x34 {
    "authenticationRequired"
  } else if nrc == 0x35 {
    "invalidKey"
  } else if nrc == 0x36 {
    "exceedNumberOfAttempts"
  } else if nrc == 0x37 {
    "requiredTimeDelayNotExpired"
  } else if nrc == 0x70 {
    "uploadDownloadNotAccepted"
  } else if nrc == 0x71 {
    "transferDataSuspended"
  } else if nrc == 0x72 {
    "generalProgrammingFailure"
  } else if nrc == 0x73 {
    "wrongBlockSequenceCounter"
  } else if nrc == 0x78 {
    "requestCorrectlyReceivedResponsePending"
  } else if nrc == 0x7e {
    "subFunctionNotSupportedInActiveSession"
  } else if nrc == 0x7f {
    "serviceNotSupportedInActiveSession"
  } else {
    "unknownNrc"
  }
}

pub fn session_name(session : Int) -> String {
  if session == 0x01 {
    "default"
  } else if session == 0x02 {
    "programming"
  } else if session == 0x03 {
    "extendedDiagnostic"
  } else if session == 0x04 {
    "safetySystemDiagnostic"
  } else {
    "unknownSession"
  }
}

fn u16_bytes(value : Int) -> Array[Int] {
  [((value >> 8) & 0xff), value & 0xff]
}

pub fn request_session_control(
  session : Int,
  suppress_positive? : Bool = false,
) -> Array[Int] {
  [0x10, session | (if suppress_positive { 0x80 } else { 0 })]
}

pub fn request_ecu_reset(reset_type : Int) -> Array[Int] {
  [0x11, reset_type]
}

pub fn request_clear_dtc(group : Int) -> Array[Int] {
  [0x14, (group >> 16) & 0xff, (group >> 8) & 0xff, group & 0xff]
}

pub fn request_read_dtc_by_status(mask : Int) -> Array[Int] {
  [0x19, 0x02, mask]
}

pub fn request_read_dtc_supported() -> Array[Int] {
  [0x19, 0x0a]
}

pub fn request_read_did(did : Int) -> Array[Int] {
  let out : Array[Int] = [0x22]
  let bytes = u16_bytes(did)
  out.push(bytes[0])
  out.push(bytes[1])
  out
}

pub fn request_write_did(did : Int, data : Array[Int]) -> Array[Int] {
  let out = request_read_did(did)
  out[0] = 0x2e
  for b in data {
    out.push(b)
  }
  out
}

pub fn request_security_access(level : Int, key? : Array[Int]) -> Array[Int] {
  let out : Array[Int] = [0x27]
  match key {
    None => out.push(level)
    Some(bytes) => {
      out.push(level + 1)
      for b in bytes {
        out.push(b)
      }
    }
  }
  out
}

pub fn request_tester_present(suppress_positive? : Bool = true) -> Array[Int] {
  [0x3e, if suppress_positive { 0x80 } else { 0x00 }]
}

pub fn request_routine_control(
  control_type : Int,
  routine_id : Int,
  data? : Array[Int],
) -> Array[Int] {
  let out : Array[Int] = [0x31, control_type]
  let bytes = u16_bytes(routine_id)
  out.push(bytes[0])
  out.push(bytes[1])
  match data {
    Some(values) =>
      for b in values {
        out.push(b)
      }
    None => ()
  }
  out
}

pub fn request_download(address : Int, size : Int) -> Array[Int] {
  let out : Array[Int] = [0x34, 0x00, 0x44]
  for shift in [24, 16, 8, 0] {
    out.push((address >> shift) & 0xff)
  }
  for shift in [24, 16, 8, 0] {
    out.push((size >> shift) & 0xff)
  }
  out
}

pub fn request_transfer_data(block_sequence : Int, data : Array[Int]) -> Array[Int] {
  let out : Array[Int] = [0x36, block_sequence & 0xff]
  for b in data {
    out.push(b)
  }
  out
}

pub fn request_transfer_exit() -> Array[Int] {
  [0x37]
}

pub fn parse_uds_message(bytes : Array[Int]) -> UdsMessage {
  if bytes.length() == 0 {
    return Malformed("empty message")
  }
  if bytes[0] == 0x7f {
    if bytes.length() < 3 {
      return Malformed("negative response shorter than 3 bytes")
    }
    Negative(bytes[1], bytes[2], nrc_description(bytes[2]))
  } else if bytes[0] >= 0x40 && bytes[0] <= 0x7e {
    let data : Array[Int] = Array::new()
    for i in 1..<bytes.length() {
      data.push(bytes[i])
    }
    Positive(bytes[0], data)
  } else {
    Malformed("request or unknown service id")
  }
}

pub fn parse_did_response(bytes : Array[Int]) -> (Int, Array[Int])? {
  if bytes.length() < 3 || bytes[0] != 0x62 {
    return None
  }
  let did = (bytes[1] << 8) | bytes[2]
  let data : Array[Int] = Array::new()
  for i in 3..<bytes.length() {
    data.push(bytes[i])
  }
  Some((did, data))
}

pub fn parse_dtc_response(bytes : Array[Int]) -> Array[Dtc]? {
  if bytes.length() < 3 || bytes[0] != 0x59 {
    return None
  }
  let out : Array[Dtc] = Array::new()
  let mut i = 3
  while i + 2 < bytes.length() {
    let high = bytes[i]
    let low = bytes[i + 1]
    let status = bytes[i + 2]
    if is_present_dtc(high, low) {
      out.push(decode_dtc(high, low, status=status))
    }
    i = i + 3
  }
  Some(out)
}

pub fn parse_security_seed(bytes : Array[Int]) -> (Int, Array[Int])? {
  if bytes.length() < 2 || bytes[0] != 0x67 {
    return None
  }
  let data : Array[Int] = Array::new()
  for i in 2..<bytes.length() {
    data.push(bytes[i])
  }
  Some((bytes[1], data))
}
