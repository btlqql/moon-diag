// ISO 15765-2 (ISO-TP) reassembly and segmentation for classic CAN.
// Flow-control frames are recognised but this offline toolkit does not simulate
// a live transport; segmentation emits the data frames only.

pub(all) suberror IsotpError {
  EmptyFrame
  EmptyPayload
  InvalidFrameSize(Int)
  InvalidLength(Int)
  TooLarge(Int)
  UnexpectedFirstFrame
  UnexpectedConsecutiveFrame
  UnexpectedSingleFrame
  BadSequence(Int, Int)
  Incomplete(Int, Int)
}

pub(all) struct IsotpReassembler {
  max_len : Int
  mut expected : Int
  mut payload : Array[Int]
  mut next_seq : Int
  mut active : Bool
  mut flow_control : Int
}

pub fn IsotpReassembler::new(max_len? : Int = 4095) -> IsotpReassembler {
  {
    max_len,
    expected: 0,
    payload: Array::new(),
    next_seq: 0,
    active: false,
    flow_control: 0,
  }
}

pub fn IsotpReassembler::is_active(self : IsotpReassembler) -> Bool {
  self.active
}

pub fn IsotpReassembler::flow_control_count(self : IsotpReassembler) -> Int {
  self.flow_control
}

fn take_payload(self : IsotpReassembler) -> Array[Int] {
  let out = self.payload
  self.payload = Array::new()
  self.expected = 0
  self.next_seq = 0
  self.active = false
  out
}

pub fn IsotpReassembler::push(
  self : IsotpReassembler,
  frame : Array[Int],
) -> Array[Int]? raise IsotpError {
  if frame.length() == 0 {
    raise EmptyFrame
  }
  let kind = (frame[0] >> 4) & 0x0f
  if kind == 0 {
    // Single frame.
    if self.active {
      raise UnexpectedSingleFrame
    }
    let mut len = frame[0] & 0x0f
    let mut offset = 1
    if len == 0 {
      if frame.length() < 2 {
        raise InvalidLength(0)
      }
      len = frame[1]
      offset = 2
    }
    if len < 0 || len > self.max_len {
      raise TooLarge(len)
    }
    if frame.length() < offset + len {
      raise Incomplete(frame.length() - offset, len)
    }
    let out : Array[Int] = Array::new()
    for i in 0..<len {
      out.push(frame[offset + i])
    }
    Some(out)
  } else if kind == 1 {
    // First frame.
    if self.active {
      raise UnexpectedFirstFrame
    }
    if frame.length() < 2 {
      raise InvalidLength(frame.length())
    }
    let len = ((frame[0] & 0x0f) << 8) | frame[1]
    if len <= 7 {
      raise InvalidLength(len)
    }
    if len > self.max_len {
      raise TooLarge(len)
    }
    self.expected = len
    self.payload = Array::new()
    self.next_seq = 1
    self.active = true
    for i in 2..<frame.length() {
      if self.payload.length() < self.expected {
        self.payload.push(frame[i])
      }
    }
    if self.payload.length() == self.expected {
      Some(self.take_payload())
    } else {
      None
    }
  } else if kind == 2 {
    // Consecutive frame.
    if !self.active {
      raise UnexpectedConsecutiveFrame
    }
    let seq = frame[0] & 0x0f
    if seq != self.next_seq {
      raise BadSequence(seq, self.next_seq)
    }
    for i in 1..<frame.length() {
      if self.payload.length() < self.expected {
        self.payload.push(frame[i])
      }
    }
    self.next_seq = (self.next_seq + 1) & 0x0f
    if self.next_seq == 0 {
      self.next_seq = 1
    }
    if self.payload.length() == self.expected {
      Some(self.take_payload())
    } else {
      None
    }
  } else if kind == 3 {
    // Flow control: valid on the wire, counted but not part of the payload.
    self.flow_control = self.flow_control + 1
    None
  } else {
    raise InvalidLength(kind)
  }
}

pub fn IsotpReassembler::finish(self : IsotpReassembler) -> Unit raise IsotpError {
  if self.active {
    let got = self.payload.length()
    let want = self.expected
    ignore(self.take_payload())
    raise Incomplete(got, want)
  }
}

pub fn segment(
  payload : Array[Int],
  frame_size? : Int = 8,
) -> Array[Array[Int]] raise IsotpError {
  if frame_size < 2 || frame_size > 64 {
    raise InvalidFrameSize(frame_size)
  }
  if payload.length() == 0 {
    raise EmptyPayload
  }
  if payload.length() > 4095 {
    raise TooLarge(payload.length())
  }
  let frames : Array[Array[Int]] = Array::new()
  if payload.length() <= frame_size - 1 {
    let frame : Array[Int] = Array::new()
    frame.push(payload.length())
    for b in payload {
      frame.push(b)
    }
    while frame.length() < frame_size {
      frame.push(0)
    }
    frames.push(frame)
    return frames
  }
  let first : Array[Int] = Array::new()
  first.push(0x10 | ((payload.length() >> 8) & 0x0f))
  first.push(payload.length() & 0xff)
  let mut pos = 0
  while pos < payload.length() && first.length() < frame_size {
    first.push(payload[pos])
    pos = pos + 1
  }
  while first.length() < frame_size {
    first.push(0)
  }
  frames.push(first)
  let mut seq = 1
  while pos < payload.length() {
    let frame : Array[Int] = Array::new()
    frame.push(0x20 | seq)
    while pos < payload.length() && frame.length() < frame_size {
      frame.push(payload[pos])
      pos = pos + 1
    }
    while frame.length() < frame_size {
      frame.push(0)
    }
    frames.push(frame)
    seq = seq + 1
    if seq > 15 {
      seq = 1
    }
  }
  frames
}
