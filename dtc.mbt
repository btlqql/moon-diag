// SAE J2012 / ISO 15031-6 diagnostic trouble codes.

pub(all) struct Dtc {
  code : String
  system : String
  description : String
  status : Int
  status_bits : Array[String]
}

fn hex3(value : Int) -> String {
  let out = StringBuilder()
  out.write_char(hex_nibble_char(value >> 8))
  out.write_char(hex_nibble_char(value >> 4))
  out.write_char(hex_nibble_char(value))
  out.to_string()
}

pub fn decode_dtc_status(status : Int) -> Array[String] {
  let out : Array[String] = Array::new()
  let names = [
    "testFailed",
    "testFailedThisCycle",
    "pending",
    "confirmed",
    "notCompletedSinceClear",
    "failedSinceClear",
    "notCompletedThisCycle",
    "warningIndicator",
  ]
  for i in 0..<8 {
    if ((status >> i) & 1) == 1 {
      out.push(names[i])
    }
  }
  out
}

pub fn decode_dtc(high : Int, low : Int, status? : Int = 0) -> Dtc {
  let system_index = (high >> 6) & 0x3
  let systems = ["Powertrain", "Chassis", "Body", "Network"]
  let letters = ["P", "C", "B", "U"]
  let first = (high >> 4) & 0x3
  let rest = ((high & 0x0f) << 8) | low
  let code = letters[system_index] + first.to_string() + hex3(rest)
  {
    code,
    system: systems[system_index],
    description: "",
    status,
    status_bits: decode_dtc_status(status),
  }
}

pub fn is_present_dtc(high : Int, low : Int) -> Bool {
  high != 0 || low != 0
}
