// import { PagedArena as Memory } from "../lib/PagedArena"
import { Memory } from "../utils/Memory"

/**
 * Poly1305 MAC - Optimized for Extreme Speed (64-bit / No-GC / Manual Memory)
 */
@final
@unmanaged
export class Poly1305 {
  // Internal state (5 limbs of 26-bits)
  private h0!: u64
  private h1!: u64
  private h2!: u64
  private h3!: u64
  private h4!: u64
  private r0!: u64
  private r1!: u64
  private r2!: u64
  private r3!: u64
  private r4!: u64
  private s1!: u64
  private s2!: u64
  private s3!: u64
  private s4!: u64
  private pad0!: u64
  private pad1!: u64

  // Static buffer for alignment (Manually managed)
  private bufferPtr!: usize
  private pos!: u32
  private finished!: bool

  @inline
  private processBlocks(ptr: usize, len: u32): void {
    let h0 = this.h0
    let h1 = this.h1
    let h2 = this.h2
    let h3 = this.h3
    let h4 = this.h4
    let r0 = this.r0
    let r1 = this.r1
    let r2 = this.r2
    let r3 = this.r3
    let r4 = this.r4
    let s1 = this.s1
    let s2 = this.s2
    let s3 = this.s3
    let s4 = this.s4
    let end = ptr + len

    while (ptr < end) {
      let M0 = load<u64>(ptr)
      let M1 = load<u64>(ptr + 8)
      ptr += 16

      h0 += M0 & 0x3ffffff
      h1 += (M0 >> 26) & 0x3ffffff
      h2 += ((M0 >> 52) | (M1 << 12)) & 0x3ffffff
      h3 += (M1 >> 14) & 0x3ffffff
      h4 += (M1 >> 40) + ((1 as u64) << 24) // Add 2^128 to every block

      let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
      let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
      let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
      let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
      let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

      let c = d0 >> 26
      h0 = d0 & 0x3ffffff
      d1 += c
      c = d1 >> 26
      h1 = d1 & 0x3ffffff
      d2 += c
      c = d2 >> 26
      h2 = d2 & 0x3ffffff
      d3 += c
      c = d3 >> 26
      h3 = d3 & 0x3ffffff
      d4 += c
      c = d4 >> 26
      h4 = d4 & 0x3ffffff
      h0 += c * 5
      c = h0 >> 26
      h0 &= 0x3ffffff
      h1 += c
    }
    this.h0 = h0
    this.h1 = h1
    this.h2 = h2
    this.h3 = h3
    this.h4 = h4
  }

  @inline
  private processPartial(ptr: usize): void {
    let M0 = load<u64>(ptr)
    let M1 = load<u64>(ptr + 8)

    let h0 = this.h0 + (M0 & 0x3ffffff)
    let h1 = this.h1 + ((M0 >> 26) & 0x3ffffff)
    let h2 = this.h2 + (((M0 >> 52) | (M1 << 12)) & 0x3ffffff)
    let h3 = this.h3 + ((M1 >> 14) & 0x3ffffff)
    let h4 = this.h4 + (M1 >> 40)

    let d0 = h0 * this.r0 + h1 * this.s4 + h2 * this.s3 + h3 * this.s2 + h4 * this.s1
    let d1 = h0 * this.r1 + h1 * this.r0 + h2 * this.s4 + h3 * this.s3 + h4 * this.s2
    let d2 = h0 * this.r2 + h1 * this.r1 + h2 * this.r0 + h3 * this.s4 + h4 * this.s3
    let d3 = h0 * this.r3 + h1 * this.r2 + h2 * this.r1 + h3 * this.r0 + h4 * this.s4
    let d4 = h0 * this.r4 + h1 * this.r3 + h2 * this.r2 + h3 * this.r1 + h4 * this.r0

    let c = d0 >> 26
    h0 = d0 & 0x3ffffff
    d1 += c
    c = d1 >> 26
    h1 = d1 & 0x3ffffff
    d2 += c
    c = d2 >> 26
    h2 = d2 & 0x3ffffff
    d3 += c
    c = d3 >> 26
    h3 = d3 & 0x3ffffff
    d4 += c
    c = d4 >> 26
    h4 = d4 & 0x3ffffff
    h0 += c * 5
    c = h0 >> 26
    h0 &= 0x3ffffff
    h1 += c

    this.h0 = h0
    this.h1 = h1
    this.h2 = h2
    this.h3 = h3
    this.h4 = h4
  }

  update(data: Uint8Array): void {
    if (this.finished) throw new Error("Poly1305: already finished")
    let len = <u32>data.length
    if (len == 0) return

    let ptr = data.dataStart
    let pos = this.pos
    let bPtr = this.bufferPtr

    if (pos > 0) {
      let take = (16 as u32) - pos
      if (len < take) take = len
      memory.copy(bPtr + pos, ptr, <usize>take)
      this.pos += take
      ptr += take
      len -= take

      if (this.pos == 16) {
        this.processBlocks(bPtr, 16)
        this.pos = 0
      } else {
        return
      }
    }

    let blocksLen = len & ~15
    if (blocksLen > 0) {
      this.processBlocks(ptr, blocksLen)
      ptr += blocksLen
      len -= blocksLen
    }

    if (len > 0) {
      memory.copy(bPtr, ptr, <usize>len)
      this.pos = len
    }
  }

  digest(out: Uint8Array): void {
    if (this.finished) throw new Error("Poly1305: already finished")
    if (<u32>out.length < 16) throw new Error("Poly1305: output buffer too small")

    this.finished = true
    let pos = this.pos

    if (pos > 0) {
      let bPtr = this.bufferPtr
      store<u8>(bPtr + pos, 1)
      memory.fill(bPtr + pos + 1, 0, <usize>((15 as u32) - pos))
      this.processPartial(bPtr)
    }

    let h0 = this.h0
    let h1 = this.h1
    let h2 = this.h2
    let h3 = this.h3
    let h4 = this.h4

    let c = h0 >> 26
    h0 &= 0x3ffffff
    h1 += c
    c = h1 >> 26
    h1 &= 0x3ffffff
    h2 += c
    c = h2 >> 26
    h2 &= 0x3ffffff
    h3 += c
    c = h3 >> 26
    h3 &= 0x3ffffff
    h4 += c
    c = h4 >> 26
    h4 &= 0x3ffffff
    h0 += c * 5
    c = h0 >> 26
    h0 &= 0x3ffffff
    h1 += c

    c = h1 >> 26
    h1 &= 0x3ffffff
    h2 += c
    c = h2 >> 26
    h2 &= 0x3ffffff
    h3 += c
    c = h3 >> 26
    h3 &= 0x3ffffff
    h4 += c
    c = h4 >> 26
    h4 &= 0x3ffffff
    h0 += c * 5
    c = h0 >> 26
    h0 &= 0x3ffffff
    h1 += c

    let g0 = h0 + 5
    c = g0 >> 26
    g0 &= 0x3ffffff
    let g1 = h1 + c
    c = g1 >> 26
    g1 &= 0x3ffffff
    let g2 = h2 + c
    c = g2 >> 26
    g2 &= 0x3ffffff
    let g3 = h3 + c
    c = g3 >> 26
    g3 &= 0x3ffffff
    let g4 = h4 + c - ((1 as u64) << 26)

    let mask = ((g4 as i64) >> 63) as u64
    let nmask = ~mask

    h0 = (h0 & mask) | (g0 & nmask)
    h1 = (h1 & mask) | (g1 & nmask)
    h2 = (h2 & mask) | (g2 & nmask)
    h3 = (h3 & mask) | (g3 & nmask)
    h4 = (h4 & mask) | (g4 & nmask)

    let H0 = h0 | (h1 << 26) | ((h2 & 0xfff) << 52)
    let H1 = (h2 >> 12) | (h3 << 14) | (h4 << 40)

    let T0 = H0 + this.pad0
    let carry = T0 < H0 ? (1 as u64) : (0 as u64)
    let T1 = H1 + this.pad1 + carry

    let outPtr = out.dataStart
    store<u64>(outPtr, T0)
    store<u64>(outPtr + 8, T1)
  }

  static create(key: Uint8Array): Poly1305 {
    if (key.length != 32) throw new Error("Poly1305: key must be 32 bytes")
    return Poly1305.createFromPtr(key.dataStart)
  }

  static createFromPtr(ptr: usize): Poly1305 {
    let ctxPtr = Memory.alloc(offsetof<Poly1305>())
    let ctx = changetype<Poly1305>(ctxPtr)
    ctx.bufferPtr = Memory.alloc(16)
    ctx.pos = 0
    ctx.finished = false

    // Reset state
    ctx.h0 = 0
    ctx.h1 = 0
    ctx.h2 = 0
    ctx.h3 = 0
    ctx.h4 = 0

    let R0 = load<u64>(ptr)
    let R1 = load<u64>(ptr + 8)

    // Clamp r
    R0 &= 0x0ffffffc0fffffff
    R1 &= 0x0ffffffc0ffffffc

    ctx.r0 = R0 & 0x3ffffff
    ctx.r1 = (R0 >> 26) & 0x3ffffff
    ctx.r2 = ((R0 >> 52) | (R1 << 12)) & 0x3ffffff
    ctx.r3 = (R1 >> 14) & 0x3ffffff
    ctx.r4 = (R1 >> 40) & 0x3ffffff

    ctx.s1 = ctx.r1 * 5
    ctx.s2 = ctx.r2 * 5
    ctx.s3 = ctx.r3 * 5
    ctx.s4 = ctx.r4 * 5

    ctx.pad0 = load<u64>(ptr + 16)
    ctx.pad1 = load<u64>(ptr + 24)

    return ctx
  }

  static mac(msg: Uint8Array, key: Uint8Array, out: Uint8Array): void {
    let marker = Memory.save()
    let p = Poly1305.create(key)
    p.update(msg)
    p.digest(out)
    Memory.restore(marker)
  }
}

export function Poly1305_mac(msg: Uint8Array, key: Uint8Array, out: Uint8Array): void {
  Poly1305.mac(msg, key, out)
}
