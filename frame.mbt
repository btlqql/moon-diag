// CAN frame transport and candle/candump text parsing.
// The toolkit is offline: it reads recorded frames, it does not open a bus.

pub(all) struct CanFrame {
  channel : String
  id : Int
  extended : Bool
  data : Array[Int]
}

pub fn CanFrame::new(
  channel : String,
  id : Int,
  extended : Bool,
  data : Array[Int],
) -> CanFrame {
  { channel, id, extended, data }
}

fn hex_digit(c : Int) -> Int? {
  if c >= 48 && c <= 57 {
    Some(c - 48)
  } else if c >= 65 && c <= 70 {
    Some(c - 55)
  } else if c >= 97 && c <= 102 {
    Some(c - 87)
  } else {
    None
  }
}

pub fn hex_nibble_char(value : Int) -> Char {
  let digits = "0123456789ABCDEF"
  match digits.get_char(value & 0xf) {
    Some(c) => c
    None => '?'
  }
}

pub fn hex_int(value : Int, width : Int) -> String {
  let out = StringBuilder()
  for i in 0..<width {
    let shift = (width - 1 - i) * 4
    out.write_char(hex_nibble_char(value >> shift))
  }
  out.to_string()
}

pub fn hex_can_id(id : Int) -> String {
  hex_int(id, if id > 0x7ff { 8 } else { 3 })
}

pub fn hex_encode(bytes : Array[Int]) -> String {
  let out = StringBuilder()
  for i in 0..<bytes.length() {
    if i > 0 {
      out.write_char(' ')
    }
    let v = bytes[i]
    out.write_char(hex_nibble_char(v >> 4))
    out.write_char(hex_nibble_char(v))
  }
  out.to_string()
}

pub fn hex_decode(text : String) -> Array[Int]? {
  let out : Array[Int] = Array::new()
  let mut high = -1
  for i in 0..<text.length() {
    let c = text[i].to_int()
    if c == 32 || c == 9 || c == 10 || c == 13 || c == 58 || c == 45 || c == 44 {
      continue
    }
    match hex_digit(c) {
      Some(v) =>
        if high < 0 {
          high = v
        } else {
          out.push((high << 4) | v)
          high = -1
        }
      None => return None
    }
  }
  if high >= 0 {
    None
  } else {
    Some(out)
  }
}

fn parse_hex_int(text : String) -> Int? {
  let mut value = 0
  if text.length() == 0 {
    return None
  }
  for i in 0..<text.length() {
    match hex_digit(text[i].to_int()) {
      Some(v) => value = value * 16 + v
      None => return None
    }
  }
  Some(value)
}

fn split_ws(text : String) -> Array[String] {
  let out : Array[String] = Array::new()
  let mut start = 0
  let mut i = 0
  while i <= text.length() {
    let at_end = i == text.length()
    let c = if at_end { 0 } else { text[i].to_int() }
    let is_space = !at_end && (c == 32 || c == 9 || c == 13)
    if at_end || is_space {
      if i > start {
        out.push(text.substring(start=start, end=i))
      }
      start = i + 1
    }
    i = i + 1
  }
  out
}

// Accepts classic candump (`can0 7E8 [8] 02 10 03 ...`) and
// candump -L (`(1690000000.123) can0 7E8#0210030000000000`).
pub fn parse_candump_line(line : String) -> CanFrame? {
  let mut body = line.trim_space().to_string()
  if body.length() == 0 || body.has_prefix("#") {
    return None
  }
  if body.has_prefix("(") {
    match body.find(")") {
      Some(close) => body = body.substring(start=close + 1).trim_space().to_string()
      None => return None
    }
  }
  match body.find("#") {
    Some(hash) => {
      let left = body.substring(start=0, end=hash).trim_space().to_string()
      let payload_hex = body.substring(start=hash + 1).trim_space().to_string()
      let parts = split_ws(left)
      if parts.length() != 2 {
        return None
      }
      let id = match parse_hex_int(parts[1]) {
        Some(v) => v
        None => return None
      }
      match hex_decode(payload_hex) {
        Some(data) =>
          Some({ channel: parts[0], id, extended: parts[1].length() > 3, data })
        None => None
      }
    }
    None => {
      let parts = split_ws(body)
      if parts.length() < 4 {
        return None
      }
      let channel = parts[0]
      let id = match parse_hex_int(parts[1]) {
        Some(v) => v
        None => return None
      }
      let len_text = parts[2]
      if !len_text.has_prefix("[") || !len_text.has_suffix("]") {
        return None
      }
      let declared = match parse_hex_int(
        len_text.substring(start=1, end=len_text.length() - 1),
      ) {
        Some(v) => v
        None => return None
      }
      let data : Array[Int] = Array::new()
      let mut i = 3
      while i < parts.length() {
        match hex_decode(parts[i]) {
          Some(chunk) => {
            for b in chunk {
              data.push(b)
            }
          }
          None => return None
        }
        i = i + 1
      }
      if declared < 0 || declared > 64 || data.length() < declared {
        return None
      }
      while data.length() > declared {
        ignore(data.pop())
      }
      Some({ channel, id, extended: parts[1].length() > 3, data })
    }
  }
}

pub fn parse_candump(text : String) -> Array[CanFrame] {
  let frames : Array[CanFrame] = Array::new()
  for line in text.split("\n").to_array() {
    match parse_candump_line(line.to_string()) {
      Some(frame) => frames.push(frame)
      None => ()
    }
  }
  frames
}

pub fn CanFrame::to_candump(self : CanFrame) -> String {
  let id_text = if self.extended {
    let out = StringBuilder()
    for shift in [28, 24, 20, 16, 12, 8, 4, 0] {
      out.write_char(hex_nibble_char(self.id >> shift))
    }
    out.to_string()
  } else {
    let out = StringBuilder()
    for shift in [8, 4, 0] {
      out.write_char(hex_nibble_char(self.id >> shift))
    }
    out.to_string()
  }
  self.channel + " " + id_text + " [" + self.data.length().to_string() + "] " +
  hex_encode(self.data)
}
