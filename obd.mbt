// OBD-II (SAE J1979) mode 01/03/07/0A decoding.

pub(all) enum ObdMessage {
  Mode01(Int, Array[Int])
  DtcResponse(Int, Array[Dtc])
  Unknown(Array[Int])
}

pub(all) struct ObdReading {
  pid : Int
  label : String
  value : String
  unit : String
  raw : Array[Int]
}

fn fmt_1(value : Double) -> String {
  let negative = value < 0.0
  let scaled = (value.abs() * 10.0).round().to_int()
  let whole = scaled / 10
  let frac = scaled % 10
  (if negative { "-" } else { "" }) + whole.to_string() + "." + frac.to_string()
}

fn fmt_2(value : Double) -> String {
  let negative = value < 0.0
  let scaled = (value.abs() * 100.0).round().to_int()
  let whole = scaled / 100
  let frac = scaled % 100
  let body = if frac < 10 {
    whole.to_string() + ".0" + frac.to_string()
  } else {
    whole.to_string() + "." + frac.to_string()
  }
  (if negative { "-" } else { "" }) + body
}

fn byte_at(data : Array[Int], index : Int) -> Int {
  if index >= 0 && index < data.length() {
    data[index]
  } else {
    0
  }
}

fn supported_pids(data : Array[Int]) -> String {
  let out = StringBuilder()
  for i in 0..<4 {
    let byte = byte_at(data, i)
    for bit in 0..<8 {
      if ((byte >> (7 - bit)) & 1) == 1 {
        let pid = i * 8 + bit + 1
        if out.to_string().length() > 0 {
          out.write_char(' ')
        }
        out.write_string("0x" + pid.to_string())
      }
    }
  }
  out.to_string()
}

fn fuel_type(code : Int) -> String {
  if code == 1 {
    "Gasoline"
  } else if code == 2 {
    "Methanol"
  } else if code == 4 {
    "Ethanol"
  } else if code == 8 {
    "Diesel"
  } else if code == 16 {
    "LPG"
  } else if code == 32 {
    "CNG"
  } else if code == 64 {
    "Electric"
  } else {
    "Unknown(" + code.to_string() + ")"
  }
}

fn monitor_bits(byte : Int, names : Array[String]) -> String {
  let out = StringBuilder()
  for i in 0..<8 {
    if ((byte >> i) & 1) == 1 {
      if out.to_string().length() > 0 {
        out.write_char(',')
      }
      out.write_string(names[i])
    }
  }
  out.to_string()
}

pub fn decode_obd_pid(pid : Int, data : Array[Int]) -> ObdReading? {
  let a = byte_at(data, 0)
  let b = byte_at(data, 1)
  let reading = if pid == 0x00 || pid == 0x20 || pid == 0x40 || pid == 0x60 {
    Some({
      pid,
      label: "Supported PIDs",
      value: supported_pids(data),
      unit: "",
      raw: data,
    })
  } else if pid == 0x01 {
    let mil = (a & 0x80) != 0
    let count = a & 0x7f
    Some({
      pid,
      label: "Monitor status",
      value: "MIL=" + mil.to_string() + " DTCs=" + count.to_string(),
      unit: "",
      raw: data,
    })
  } else if pid == 0x03 {
    Some({
      pid,
      label: "Fuel system status",
      value: "0x" + a.to_string() + " 0x" + b.to_string(),
      unit: "",
      raw: data,
    })
  } else if pid == 0x04 {
    Some({ pid, label: "Calculated engine load", value: fmt_1(a.to_double() * 100.0 / 255.0), unit: "%", raw: data })
  } else if pid == 0x05 {
    Some({ pid, label: "Coolant temperature", value: (a - 40).to_string(), unit: "C", raw: data })
  } else if pid == 0x06 || pid == 0x07 || pid == 0x08 || pid == 0x09 {
    let label = if pid == 0x06 {
      "Short term fuel trim bank 1"
    } else if pid == 0x07 {
      "Long term fuel trim bank 1"
    } else if pid == 0x08 {
      "Short term fuel trim bank 2"
    } else {
      "Long term fuel trim bank 2"
    }
    Some({ pid, label, value: fmt_1((a.to_double() - 128.0) * 100.0 / 128.0), unit: "%", raw: data })
  } else if pid == 0x0a {
    Some({ pid, label: "Fuel pressure", value: (a * 3).to_string(), unit: "kPa", raw: data })
  } else if pid == 0x0b {
    Some({ pid, label: "Intake manifold pressure", value: a.to_string(), unit: "kPa", raw: data })
  } else if pid == 0x0c {
    Some({ pid, label: "Engine speed", value: ((a * 256 + b) / 4).to_string(), unit: "rpm", raw: data })
  } else if pid == 0x0d {
    Some({ pid, label: "Vehicle speed", value: a.to_string(), unit: "km/h", raw: data })
  } else if pid == 0x0e {
    Some({ pid, label: "Timing advance", value: fmt_1(a.to_double() / 2.0 - 64.0), unit: "deg", raw: data })
  } else if pid == 0x0f {
    Some({ pid, label: "Intake air temperature", value: (a - 40).to_string(), unit: "C", raw: data })
  } else if pid == 0x10 {
    Some({ pid, label: "MAF air flow", value: fmt_2((a * 256 + b).to_double() / 100.0), unit: "g/s", raw: data })
  } else if pid == 0x11 {
    Some({ pid, label: "Throttle position", value: fmt_1(a.to_double() * 100.0 / 255.0), unit: "%", raw: data })
  } else if pid == 0x1f {
    Some({ pid, label: "Run time since start", value: (a * 256 + b).to_string(), unit: "s", raw: data })
  } else if pid == 0x21 {
    Some({ pid, label: "Distance with MIL on", value: (a * 256 + b).to_string(), unit: "km", raw: data })
  } else if pid == 0x2f {
    Some({ pid, label: "Fuel level", value: fmt_1(a.to_double() * 100.0 / 255.0), unit: "%", raw: data })
  } else if pid == 0x31 {
    Some({ pid, label: "Distance since codes cleared", value: (a * 256 + b).to_string(), unit: "km", raw: data })
  } else if pid == 0x33 {
    Some({ pid, label: "Barometric pressure", value: a.to_string(), unit: "kPa", raw: data })
  } else if pid == 0x42 {
    Some({ pid, label: "Control module voltage", value: fmt_2((a * 256 + b).to_double() / 1000.0), unit: "V", raw: data })
  } else if pid == 0x46 {
    Some({ pid, label: "Ambient air temperature", value: (a - 40).to_string(), unit: "C", raw: data })
  } else if pid == 0x51 {
    Some({ pid, label: "Fuel type", value: fuel_type(a), unit: "", raw: data })
  } else if pid == 0x5c {
    Some({ pid, label: "Engine oil temperature", value: (a - 40).to_string(), unit: "C", raw: data })
  } else {
    None
  }
  reading
}

pub fn readiness_summary(data : Array[Int]) -> String {
  let a = byte_at(data, 0)
  let b = byte_at(data, 1)
  let c = byte_at(data, 2)
  let d = byte_at(data, 3)
  let since = monitor_bits(b, [
    "misfire", "fuelSystem", "components", "catalyst", "heatedCatalyst",
    "evaporativeSystem", "secondaryAir", "acRefrigerant",
  ])
  let available = monitor_bits(d, [
    "oxygenSensor", "oxygenSensorHeater", "egr", "reserved4", "reserved5",
    "reserved6", "reserved7", "reserved8",
  ])
  "MIL=" + ((a & 0x80) != 0).to_string() + " dtcCount=" +
  (a & 0x7f).to_string() + " incomplete=" + since + " available=" + available +
  " encoded=0x" + c.to_string() + "0x" + d.to_string()
}

pub fn parse_obd_message(bytes : Array[Int]) -> ObdMessage {
  if bytes.length() < 2 {
    return Unknown(bytes)
  }
  if bytes[0] == 0x41 {
    Mode01(bytes[1], bytes)
  } else if bytes[0] == 0x43 || bytes[0] == 0x47 || bytes[0] == 0x4a {
    let dtcs : Array[Dtc] = Array::new()
    let mut i = 2
    while i + 1 < bytes.length() {
      if is_present_dtc(bytes[i], bytes[i + 1]) {
        dtcs.push(decode_dtc(bytes[i], bytes[i + 1]))
      }
      i = i + 2
    }
    DtcResponse(bytes[0], dtcs)
  } else {
    Unknown(bytes)
  }
}

// OBD mode 09 PID 02 returns the VIN. Some ECUs prefix a frame counter, so
// take the final 17 printable ASCII bytes after the mode/PID header.
pub fn parse_obd_vin(bytes : Array[Int]) -> String? {
  if bytes.length() < 19 || bytes[0] != 0x49 || bytes[1] != 0x02 {
    return None
  }
  let start = bytes.length() - 17
  let vin = StringBuilder()
  for i in start..<bytes.length() {
    let b = bytes[i]
    if b < 32 || b > 126 {
      return None
    }
    vin.write_char(Char::from_int(b))
  }
  Some(vin.to_string())
}

pub(all) struct MonitorResult {
  mid : Int
  tid : Int
  unit : Int
  value : Int
}

// Mode 06: 46 MID TID UAS TestValue(2) Min(2) Max(2) ...
pub fn parse_obd_mode06(bytes : Array[Int]) -> MonitorResult? {
  if bytes.length() < 8 || bytes[0] != 0x46 {
    return None
  }
  Some({
    mid: bytes[1],
    tid: bytes[2],
    unit: bytes[3],
    value: (bytes[4] << 8) | bytes[5],
  })
}
