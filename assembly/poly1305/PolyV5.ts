/**
 * ==============================================================================
 * Poly1305 V5
 * ==============================================================================
 * Combina la armonía matemática de los registros de V1 con la arquitectura
 * Zero-Allocation pura de V3.
 *
 * EL SECRETO:
 * - V8 TurboFan ama las clases locales (Escape Analysis).
 * - En `processPartial`, usamos `this.r0` en lugar de variables locales
 *   para evitar exceder los 16 registros de la CPU (Register Spilling).
 * ==============================================================================
 */

// 1. MEMORIA ESTÁTICA NATIVA: Reemplaza a Memory.ts. Cero coste de allocation.
const CTX_PTR: usize = memory.data(offsetof<Poly1305>())
const BUF_PTR: usize = memory.data(16)
@final
@unmanaged
export class Poly1305 {
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
  private pos!: u32
  private finished!: bool

  /**
   * EXACTAMENTE TU V1: En bucles, V8 saca las variables locales de la memoria
   * y las mantiene en registros permanentemente.
   */
  @inline
  private processBlocks(ptr: usize, len: u32): void {
    let h0 = this.h0,
      h1 = this.h1,
      h2 = this.h2,
      h3 = this.h3,
      h4 = this.h4
    let r0 = this.r0,
      r1 = this.r1,
      r2 = this.r2,
      r3 = this.r3,
      r4 = this.r4
    let s1 = this.s1,
      s2 = this.s2,
      s3 = this.s3,
      s4 = this.s4
    let end = ptr + len

    while (ptr < end) {
      let M0 = load<u64>(ptr)
      let M1 = load<u64>(ptr + 8)
      ptr += 16

      h0 += M0 & 0x3ffffff
      h1 += (M0 >> 26) & 0x3ffffff
      h2 += ((M0 >> 52) | (M1 << 12)) & 0x3ffffff
      h3 += (M1 >> 14) & 0x3ffffff
      h4 += (M1 >> 40) + ((1 as u64) << 24)

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

  /**
   * EXACTAMENTE TU V1 (El secreto del éxito): Al NO asignar r0-r4 a locales aquí,
   * evitamos el "Register Spilling" en x86-64. V8 lo inyecta como operandos de memoria.
   */
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

  // Se modificó para recibir punteros crudos y devorar bytes sin compasión
  update(ptr: usize, len: u32): void {
    if (this.finished) throw new Error("Poly1305: already finished")
    if (len == 0) return

    let pos = this.pos
    if (pos > 0) {
      let take = (16 as u32) - pos
      if (len < take) take = len
      memory.copy(BUF_PTR + pos, ptr, <usize>take)
      this.pos += take
      ptr += take
      len -= take

      if (this.pos == 16) {
        this.processBlocks(BUF_PTR, 16)
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
      memory.copy(BUF_PTR, ptr, <usize>len)
      this.pos = len
    }
  }

  digest(outPtr: usize): void {
    if (this.finished) throw new Error("Poly1305: already finished")
    this.finished = true

    let pos = this.pos
    if (pos > 0) {
      store<u8>(BUF_PTR + pos, 1)
      memory.fill(BUF_PTR + pos + 1, 0, <usize>((15 as u32) - pos))
      this.processPartial(BUF_PTR)
    }

    let h0 = this.h0,
      h1 = this.h1,
      h2 = this.h2,
      h3 = this.h3,
      h4 = this.h4

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

    store<u64>(outPtr, T0)
    store<u64>(outPtr + 8, T1)
  }

  @inline
  static createFromPtr(ptr: usize): Poly1305 {
    // Tomamos el control de la memoria estática
    let ctx = changetype<Poly1305>(CTX_PTR)
    ctx.pos = 0
    ctx.finished = false
    ctx.h0 = 0
    ctx.h1 = 0
    ctx.h2 = 0
    ctx.h3 = 0
    ctx.h4 = 0

    let R0 = load<u64>(ptr)
    let R1 = load<u64>(ptr + 8)

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

  // @inline
  static mac_ptr(msgPtr: usize, msgLen: u32, keyPtr: usize, outPtr: usize): void {
    const p = Poly1305.createFromPtr(keyPtr)
    p.update(msgPtr, msgLen)
    p.digest(outPtr)
  }

  // @inline
  static mac(msg: Uint8Array, key: Uint8Array, out: Uint8Array): void {
    if (key.length != 32) throw new Error("Poly1305: key must be 32 bytes")
    if (out.length < 16) throw new Error("Poly1305: output buffer too small")

    Poly1305.mac_ptr(msg.dataStart, <u32>msg.length, key.dataStart, out.dataStart)
  }
}

// ==============================================================================
// 🚀 WRAPPERS FINALES
// ==============================================================================
export function Poly1305_mac_ptr(msgPtr: usize, msgLen: u32, keyPtr: usize, outPtr: usize): void {
  Poly1305.mac_ptr(msgPtr, msgLen, keyPtr, outPtr)
}

export function Poly1305_mac(msg: Uint8Array, key: Uint8Array, out: Uint8Array): void {
  Poly1305.mac(msg, key, out)
}
