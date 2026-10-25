// Node is used only for file IO. All protocol work runs in MoonBit.

extern "js" fn read_text(path : String) -> String? =
  #| (path) => {
  #|   try {
  #|     const fs = process.getBuiltinModule('node:fs');
  #|     const text = fs.readFileSync(path, 'utf8');
  #|     return text.length > 4194304 ? undefined : text;
  #|   } catch { return undefined; }
  #| }

extern "js" fn stderr(text : String) -> Unit =
  #| (text) => { process.stderr.write(text + '\n'); }

extern "js" fn exit_code(code : Int) -> Unit =
  #| (code) => { process.exitCode = code; }

fn usage() -> Unit {
  println(
    "MoonDiag 0.1.0\n" +
    "Usage:\n" +
    "  moondiag report <candump.log>          decode a recorded session\n" +
    "  moondiag uds <hex>                     parse a UDS response\n" +
    "  moondiag obd <hex>                     decode an OBD-II response\n" +
    "  moondiag dtc <hex>                     decode DTC pairs\n" +
    "  moondiag segment <hex>                 segment a payload into ISO-TP frames\n" +
    "  moondiag request read-did <hex>        build a UDS request\n" +
    "  moondiag request session <hex|name>    default|programming|extended|safety\n" +
    "  moondiag request clear-dtc <hex>       build ClearDiagnosticInformation\n" +
    "  moondiag request tester-present        build TesterPresent\n" +
    "Inputs are offline logs or hex strings; no CAN adapter is opened.",
  )
}

fn need_hex(text : String) -> Array[Int]? {
  match @diag.hex_decode(text) {
    Some(bytes) => Some(bytes)
    None => {
      stderr("ERROR: invalid hex string")
      None
    }
  }
}

fn print_uds(bytes : Array[Int]) -> Unit {
  match @diag.parse_uds_message(bytes) {
    @diag.Positive(sid, data) => {
      let service = sid - 0x40
      println(
        "positive service=0x" + @diag.hex_int(service, 2) + " (" +
        @diag.uds_service_name(service) + ") data=" + @diag.hex_encode(data),
      )
    }
    @diag.Negative(service, nrc, reason) =>
      println(
        "negative service=0x" + @diag.hex_int(service, 2) + " nrc=0x" +
        @diag.hex_int(nrc, 2) + " (" + reason + ")",
      )
    @diag.Malformed(reason) => {
      stderr("ERROR: " + reason)
      exit_code(1)
    }
  }
}

fn print_obd(bytes : Array[Int]) -> Unit {
  match @diag.parse_obd_message(bytes) {
    @diag.Mode01(pid, raw) => {
      let data : Array[Int] = Array::new()
      for i in 2..<raw.length() {
        data.push(raw[i])
      }
      match @diag.decode_obd_pid(pid, data) {
        Some(r) =>
          println(
            "PID 0x" + @diag.hex_int(pid, 2) + " " + r.label + "=" + r.value +
            (if r.unit.length() > 0 { r.unit } else { "" }),
          )
        None => println("PID 0x" + @diag.hex_int(pid, 2) + " unsupported")
      }
    }
    @diag.DtcResponse(mode, dtcs) => {
      println("mode=0x" + @diag.hex_int(mode, 2) + " dtcs=" + dtcs.length().to_string())
      for d in dtcs {
        println(d.code + " " + d.system + " status=" + @diag.hex_encode([d.status]))
      }
    }
    @diag.Unknown(_) => {
      stderr("ERROR: not an OBD-II response")
      exit_code(1)
    }
  }
}

fn run() -> Unit {
  let args = @env.args()
  if args.length() < 3 {
    usage()
    return
  }
  let command = args[2]
  if command == "--help" || command == "help" {
    usage()
  } else if command == "report" {
    let mut json = false
    let mut path = ""
    if args.length() == 4 {
      path = args[3]
    } else if args.length() == 5 && args[3] == "--json" {
      json = true
      path = args[4]
    } else if args.length() == 5 && args[4] == "--json" {
      json = true
      path = args[3]
    } else {
      usage()
      exit_code(2)
      return
    }
    match read_text(path) {
      Some(text) => {
        let report = @diag.analyze_log(text)
        println(if json {
          @diag.render_json(report)
        } else {
          @diag.render_report(report)
        })
      }
      None => {
        stderr("ERROR: cannot read input file")
        exit_code(2)
      }
    }
  } else if command == "uds" {
    if args.length() != 4 {
      usage()
      exit_code(2)
      return
    }
    match need_hex(args[3]) {
      Some(bytes) => print_uds(bytes)
      None => exit_code(2)
    }
  } else if command == "obd" {
    if args.length() != 4 {
      usage()
      exit_code(2)
      return
    }
    match need_hex(args[3]) {
      Some(bytes) => print_obd(bytes)
      None => exit_code(2)
    }
  } else if command == "dtc" {
    if args.length() != 4 {
      usage()
      exit_code(2)
      return
    }
    match need_hex(args[3]) {
      Some(bytes) => {
        if bytes.length() % 3 != 0 {
          stderr("ERROR: DTC input must be triples of high, low, status")
          exit_code(2)
          return
        }
        let mut i = 0
        while i + 2 < bytes.length() {
          let d = @diag.decode_dtc(bytes[i], bytes[i + 1], status=bytes[i + 2])
          println(
            d.code + " " + d.system + " status=" + @diag.hex_encode([d.status]),
          )
          i = i + 3
        }
      }
      None => exit_code(2)
    }
  } else if command == "segment" {
    if args.length() != 4 {
      usage()
      exit_code(2)
      return
    }
    match need_hex(args[3]) {
      Some(bytes) =>
        try {
          let frames = @diag.segment(bytes)
          for i in 0..<frames.length() {
            println(i.to_string() + ": " + @diag.hex_encode(frames[i]))
          }
        } catch {
          _ => {
            stderr("ERROR: payload cannot be segmented")
            exit_code(2)
          }
        }
      None => exit_code(2)
    }
  } else if command == "request" {
    if args.length() < 4 {
      usage()
      exit_code(2)
      return
    }
    let kind = args[3]
    if kind == "tester-present" {
      println(@diag.hex_encode(@diag.request_tester_present()))
    } else if kind == "read-did" && args.length() == 5 {
      match need_hex(args[4]) {
        Some(bytes) =>
          if bytes.length() == 2 {
            println(
              @diag.hex_encode(@diag.request_read_did((bytes[0] << 8) | bytes[1])),
            )
          } else {
            stderr("ERROR: DID must be two bytes")
            exit_code(2)
          }
        None => exit_code(2)
      }
    } else if kind == "session" && args.length() == 5 {
      let session = if args[4] == "default" {
        0x01
      } else if args[4] == "programming" {
        0x02
      } else if args[4] == "extended" {
        0x03
      } else if args[4] == "safety" {
        0x04
      } else {
        match need_hex(args[4]) {
          Some(bytes) =>
            if bytes.length() == 1 {
              bytes[0]
            } else {
              stderr("ERROR: invalid session")
              exit_code(2)
              0
            }
          None => {
            exit_code(2)
            0
          }
        }
      }
      if session != 0 {
        println(@diag.hex_encode(@diag.request_session_control(session)))
      }
    } else if kind == "clear-dtc" && args.length() == 5 {
      match need_hex(args[4]) {
        Some(bytes) =>
          if bytes.length() == 3 {
            println(
              @diag.hex_encode(
                @diag.request_clear_dtc(
                  (bytes[0] << 16) | (bytes[1] << 8) | bytes[2],
                ),
              ),
            )
          } else {
            stderr("ERROR: group must be three bytes")
            exit_code(2)
          }
        None => exit_code(2)
      }
    } else {
      usage()
      exit_code(2)
    }
  } else {
    usage()
    exit_code(2)
  }
}

///|
fn main {
  run()
}
