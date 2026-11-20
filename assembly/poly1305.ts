/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  poly1305.ts — Poly1305 (Message Authentication Code, RFC 8439)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Poly1305 es un MAC de 16 bytes diseñado por Daniel J. Bernstein. Aquí se
 * implementa con aritmética radix-2⁶ en `u64` (5 limbs de 26 bits), la forma
 * más rápida en WebAssembly escalar (sin SIMD).
 *
 * 100% ZERO-ALLOC / SOLO PUNTEROS:
 *  • Sin Uint8Array ni objetos intermedios — toda la API opera sobre punteros
 *    crudos (usize) y longitudes (u32).
 *  • El contexto y su buffer de 16 bytes se reservan en la arena `Arena`
 *    (struct sobre puntero vía changetype), sin `new` en el heap.
 *  • Cada `createFromPtr` obtiene su propio contexto → reentrante.
 *
 * SIN `throw` (runtime stub): `update`/`digest` sobre un contexto ya sellado
 * (`finished`) son un no-op seguro (`return`), consistente con chacha/aead.
 *
 * ── STREAMING (autenticación de archivos grandes en tiempo real) ──────────
 * Poly1305 es incremental: alimenta los datos en chunks arbitrarios (archivos
 * de GB o flujos de red) sin acumular nada en memoria.
 *
 *   const p = Poly1305.createFromPtr(keyPtr)   // 1) init (clave de 32 B)
 *   p.update(chunk1Ptr, chunk1Len)             // 2) update (chunk a chunk)
 *   p.update(chunkNPtr, chunkNLen)
 *   p.digest(tagPtr)                           // 3) digest → tag de 16 B
 *
 * El estado interno (acumulador h, buffer parcial) vive en el contexto de la
 * arena; entre `update` y `update` no se reserva memoria nueva. Memoria plana.
 *
 * ── ONE-SHOT (mensajes pequeños) ──────────────────────────────────────────
 * `mac_ptr(msgPtr, msgLen, keyPtr, outPtr)` hace init+update+digest en una
 * llamada, con `Arena.save()/restore()` (libera el contexto) y `wipe()`
 * (limpia el material sensible) → uso standalone seguro y sin leaks.
 *
 * Claves de rendimiento (validadas):
 *  • `processBlocks` carga r0–r4 en variables locales → el JIT las mantiene
 *    en registros permanentemente (escape analysis).
 *  • `processPartial` usa `this.r0` directamente (operandos de memoria) para NO
 *    exceder los 16 registros x86-64 (evita register spilling en el bloque final).
 */
import { Arena } from "./arena"

@final
@unmanaged
export class Poly1305 {
  // ── Acumulador (5 limbs radix-2⁶) ──
  private h0!: u64
  private h1!: u64
  private h2!: u64
  private h3!: u64
  private h4!: u64
  // ── Clave "r" clampeada (5 limbs) ──
  private r0!: u64
  private r1!: u64
  private r2!: u64
  private r3!: u64
  private r4!: u64
  // ── Precomputados s_i = r_i * 5 (para la reducción mod 2¹³⁰−5) ──
  private s1!: u64
  private s2!: u64
  private s3!: u64
  private s4!: u64
  // ── Padding "s" (últimos 16 bytes de la clave de 32 bytes) ──
  private pad0!: u64
  private pad1!: u64
  // ── Estado de streaming ──
  private pos!: u32 // bytes pendientes en el buffer parcial (0..15)
  private finished!: bool
  // ── Buffer de bloque parcial (16 bytes, en la arena) ──
  private bufPtr!: usize

  // ═════════════════════════════════════════════════════════════════════════
  // 🏭 FÁBRICA (init del streaming)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * [STREAMING · INIT] Crea un contexto Poly1305 desde un puntero a la clave
   * de 32 bytes — zero-alloc vía arena (sin `new`).
   *
   * Reserva el contexto y su buffer de 16 bytes en `Arena`, clampea "r"
   * (RFC 8439 §2.5), precomputa s_i = r_i·5 y carga el padding "s".
   * Punto de entrada del flujo streaming: createFromPtr → update × N → digest.
   *
   * @param keyPtr Puntero a la clave de 32 bytes (r ‖ s).
   */
  @inline
  static createFromPtr(keyPtr: usize): Poly1305 {
    let ctxPtr = Arena.alloc(offsetof<Poly1305>())
    let ctx = changetype<Poly1305>(ctxPtr)
    ctx.bufPtr = Arena.alloc(16)

    ctx.pos = 0
    ctx.finished = false
    ctx.h0 = 0
    ctx.h1 = 0
    ctx.h2 = 0
    ctx.h3 = 0
    ctx.h4 = 0

    // Clampeo de "r" (RFC 8439 §2.5): ciertos bits deben ser 0
    let R0 = load<u64>(keyPtr)
    let R1 = load<u64>(keyPtr + 8)
    R0 &= 0x0ffffffc0fffffff
    R1 &= 0x0ffffffc0ffffffc

    // "r" en radix-2⁶ (5 limbs de 26 bits)
    ctx.r0 = R0 & 0x3ffffff
    ctx.r1 = (R0 >> 26) & 0x3ffffff
    ctx.r2 = ((R0 >> 52) | (R1 << 12)) & 0x3ffffff
    ctx.r3 = (R1 >> 14) & 0x3ffffff
    ctx.r4 = (R1 >> 40) & 0x3ffffff

    // s_i = r_i * 5 (precomputados para la reducción)
    ctx.s1 = ctx.r1 * 5
    ctx.s2 = ctx.r2 * 5
    ctx.s3 = ctx.r3 * 5
    ctx.s4 = ctx.r4 * 5

    // Padding "s" (últimos 16 bytes de la clave)
    ctx.pad0 = load<u64>(keyPtr + 16)
    ctx.pad1 = load<u64>(keyPtr + 24)

    return ctx
  }

  // ═════════════════════════════════════════════════════════════════════════
  // 🔄 API DE STREAMING (init → update × N → digest)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * [STREAMING · UPDATE] Alimentar bytes al MAC.
   *
   * Acepta chunks de cualquier tamaño (1 byte, 4 KB, 1 MB…) y los acumula
   * internamente: los bloques completos de 16 B se procesan al vuelo y el
   * residuo (< 16 B) se guarda en el buffer parcial. No reserva memoria nueva
   * entre llamadas → apto para archivos de GB y flujos en tiempo real.
   *
   * No-op seguro si el contexto ya está sellado (`finished`).
   *
   * @param ptr Puntero a los datos del chunk.
   * @param len Longitud del chunk en bytes.
   */
  update(ptr: usize, len: u32): void {
    if (this.finished || len == 0) return

    let pos = this.pos
    if (pos > 0) {
      // Completa el buffer parcial previo hasta 16 bytes
      let take = <u32>16 - pos
      if (len < take) take = len
      memory.copy(this.bufPtr + pos, ptr, <usize>take)
      this.pos += take
      ptr += take
      len -= take

      if (this.pos == 16) {
        this.processBlocks(this.bufPtr, 16)
        this.pos = 0
      } else {
        return // aún no hay bloque completo
      }
    }

    // Procesa bloques completos directamente desde la entrada (sin copiar)
    let blocksLen = len & ~15
    if (blocksLen > 0) {
      this.processBlocks(ptr, blocksLen)
      ptr += blocksLen
      len -= blocksLen
    }

    // Guarda el residuo (< 16 B) como bloque parcial
    if (len > 0) {
      memory.copy(this.bufPtr, ptr, <usize>len)
      this.pos = len
    }
  }

  /**
   * [STREAMING · DIGEST] Finaliza y escribe el tag de 16 bytes en outPtr.
   *
   * Aplica el padding final (byte 0x01 + ceros), la carry chain completa, la
   * reducción mod 2¹³⁰−5 con selección constant-time (máscara) y suma el
   * padding "s". Tras llamar a `digest`, el contexto queda sellado (no admite
   * más `update`). No-op seguro si ya está sellado.
   *
   * @param outPtr Puntero al buffer de salida del tag (16 bytes).
   */
  digest(outPtr: usize): void {
    if (this.finished) return
    this.finished = true

    let pos = this.pos
    if (pos > 0) {
      // Padding del bloque final: 0x01 seguido de ceros
      store<u8>(this.bufPtr + pos, 1)
      memory.fill(this.bufPtr + pos + 1, 0, <usize>(<u32>15 - pos))
      this.processPartial(this.bufPtr)
    }

    let h0 = this.h0,
      h1 = this.h1,
      h2 = this.h2,
      h3 = this.h3,
      h4 = this.h4

    // Carry chain completa (1ª pasada)
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

    // Carry chain completa (2ª pasada)
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

    // g = h + 5; si g >= 2¹³⁰ → g -= 2¹³⁰ (reducción final)
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
    let g4 = h4 + c - ((<u64>1) << 26)

    // Selección constant-time: mask = (g4 < 0) ? 0 : ~0
    let mask = <u64>((<i64>g4) >> 63)
    let nmask = ~mask

    h0 = (h0 & mask) | (g0 & nmask)
    h1 = (h1 & mask) | (g1 & nmask)
    h2 = (h2 & mask) | (g2 & nmask)
    h3 = (h3 & mask) | (g3 & nmask)
    h4 = (h4 & mask) | (g4 & nmask)

    // Reensamblar a 128 bits (little-endian)
    let H0 = h0 | (h1 << 26) | ((h2 & 0xfff) << 52)
    let H1 = (h2 >> 12) | (h3 << 14) | (h4 << 40)

    // tag = (h + s) mod 2¹²⁸
    let T0 = H0 + this.pad0
    let carry = T0 < H0 ? <u64>1 : <u64>0
    let T1 = H1 + this.pad1 + carry

    store<u64>(outPtr, T0)
    store<u64>(outPtr + 8, T1)
  }

  // ═════════════════════════════════════════════════════════════════════════
  // ⚡ API ONE-SHOT (mensajes completos en memoria)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * [ONE-SHOT] Calcula el tag Poly1305 de msg[0..msgLen) con clave de 32 bytes
   * y lo escribe en outPtr (16 B). Equivale a createFromPtr + update + digest,
   * pero con `Arena.save()/restore()` (libera el contexto de la arena) y
   * `wipe()` (limpia el material sensible) → uso standalone seguro y sin leaks.
   *
   * @param msgPtr Puntero al mensaje.
   * @param msgLen Longitud del mensaje en bytes.
   * @param keyPtr Puntero a la clave de 32 bytes (r ‖ s).
   * @param outPtr Puntero al buffer de salida del tag (16 bytes).
   */
  static mac_ptr(msgPtr: usize, msgLen: u32, keyPtr: usize, outPtr: usize): void {
    const marker = Arena.save()
    const p = Poly1305.createFromPtr(keyPtr)
    p.update(msgPtr, msgLen)
    p.digest(outPtr)
    p.wipe() // limpiar material sensible (clave r, acumulador h, buffer parcial)
    Arena.restore(marker) // liberar el contexto de la arena
  }

  // ═════════════════════════════════════════════════════════════════════════
  // 🧹 SEGURIDAD (limpieza de material sensible)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * Limpia TODO el material sensible: el buffer de bloque parcial (16 B) y el
   * contexto completo (acumulador h, clave r clampeada, precomputados s,
   * padding s). Lo llama `AeadStream.wipeAll()` y `mac_ptr` antes de liberar.
   */
  // @ts-ignore
  @inline
  wipe(): void {
    memory.fill(this.bufPtr, 0, 16) // buffer de bloque parcial
    memory.fill(changetype<usize>(this), 0, offsetof<Poly1305>()) // h, r, s, pad, pos…
  }

  // ═════════════════════════════════════════════════════════════════════════
  // 🔒 NÚCLEO MATEMÁTICO (privado, validado y optimizado)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * Procesa bloques completos de 16 bytes (hot path).
   * r0–r4 en locales → el JIT los mantiene en registros (máximo rendimiento).
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

      // h += m (con el bit de "high" en h4)
      h0 += M0 & 0x3ffffff
      h1 += (M0 >> 26) & 0x3ffffff
      h2 += ((M0 >> 52) | (M1 << 12)) & 0x3ffffff
      h3 += (M1 >> 14) & 0x3ffffff
      h4 += (M1 >> 40) + ((<u64>1) << 24)

      // h = h * r  (multiplicación radix-2⁶ con reducción parcial)
      let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
      let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
      let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
      let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
      let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

      // Carry chain (reduce cada limb a 26 bits)
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
      h0 += c * 5 // reducción mod 2¹³⁰−5
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
   * Procesa el último bloque parcial (< 16 bytes, ya con el byte 0x01 de padding).
   * Usa `this.r0` directamente (operandos de memoria) para no exceder los 16
   * registros x86-64 (evita register spilling en el bloque final).
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
}

// ═══════════════════════════════════════════════════════════════════════════
// 🚀 WRAPPER EXPORTADO (solo punteros)
// ═══════════════════════════════════════════════════════════════════════════

/** One-shot: tag Poly1305 de msg[0..msgLen) con clave de 32 B → out (16 B). */
export function poly1305_mac_ptr(msgPtr: usize, msgLen: u32, keyPtr: usize, outPtr: usize): void {
  Poly1305.mac_ptr(msgPtr, msgLen, keyPtr, outPtr)
}
