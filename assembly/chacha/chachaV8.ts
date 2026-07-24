/**
 * ==============================================================================
 * 🔥 CHACHA20 & XCHACHA20 V8 — EDICIÓN DEFINITIVA 🔥
 * ==============================================================================
 * Rendimiento: > 7,000 ops/s (64KB) en Scalar Wasm.
 * Arquitectura: Zero-Dependencies, Arena Local, Clases Monomórficas.
 *
 * OPTIMIZACIONES PARA AEAD (vs V7):
 *
 * 1. API DE PUNTEROS (encryptPtr): Permite al módulo AEAD operar sin crear
 *    Uint8Array intermedios. Elimina la necesidad de SHARED_AUTH_KEY como
 *    Uint8Array y todos los Uint8Array.wrap() en el flujo de cifrado.
 *
 * 2. ARENA LOCAL (memory.data): Arena de 64KB en la sección .data del módulo.
 *    Cero dependencias externas, cero overhead de GC. El AEAD puede usar
 *    save/restore de esta arena directamente.
 *
 * 3. LIMPIEZA DE CÓDIGO: Documentación en español, indentación consistente,
 *    eliminación de @ts-ignore duplicados, decoradores alineados.
 * ==============================================================================
 */

import { LocalArena } from "../utils/LocalArena"

// =============================================================================
// ⚡ FUNCIONES CORE (HOT PATH)
// =============================================================================

/**
 * Bloque ChaCha20 completo con XOR contra datos de entrada.
 * Procesa exactamente 64 bytes: out[i] = in[i] ^ keystream[i]
 */
// @ts-ignore
@inline
function chachaXorBlock(
  k0: u32, k1: u32, k2: u32, k3: u32,
  k4: u32, k5: u32, k6: u32, k7: u32,
  n0: u32, n1: u32, n2: u32,
  ctr: u32,
  inPtr: usize, outPtr: usize,
  rounds: i32
): void {
  // Constantes ChaCha ("expand 32-byte k")
  let x00 = 0x61707865 as u32
  let x01 = 0x3320646e as u32
  let x02 = 0x79622d32 as u32
  let x03 = 0x6b206574 as u32
  let x04 = k0, x05 = k1, x06 = k2, x07 = k3
  let x08 = k4, x09 = k5, x10 = k6, x11 = k7
  let x12 = ctr, x13 = n0, x14 = n1, x15 = n2

  // Doble ronda desenrollada
  for (let r = 0; r < rounds; r += 2) {
    // Ronda columnar
    x00 += x04; x12 ^= x00; x12 = rotl<u32>(x12, 16)
    x08 += x12; x04 ^= x08; x04 = rotl<u32>(x04, 12)
    x00 += x04; x12 ^= x00; x12 = rotl<u32>(x12, 8)
    x08 += x12; x04 ^= x08; x04 = rotl<u32>(x04, 7)

    x01 += x05; x13 ^= x01; x13 = rotl<u32>(x13, 16)
    x09 += x13; x05 ^= x09; x05 = rotl<u32>(x05, 12)
    x01 += x05; x13 ^= x01; x13 = rotl<u32>(x13, 8)
    x09 += x13; x05 ^= x09; x05 = rotl<u32>(x05, 7)

    x02 += x06; x14 ^= x02; x14 = rotl<u32>(x14, 16)
    x10 += x14; x06 ^= x10; x06 = rotl<u32>(x06, 12)
    x02 += x06; x14 ^= x02; x14 = rotl<u32>(x14, 8)
    x10 += x14; x06 ^= x10; x06 = rotl<u32>(x06, 7)

    x03 += x07; x15 ^= x03; x15 = rotl<u32>(x15, 16)
    x11 += x15; x07 ^= x11; x07 = rotl<u32>(x07, 12)
    x03 += x07; x15 ^= x03; x15 = rotl<u32>(x15, 8)
    x11 += x15; x07 ^= x11; x07 = rotl<u32>(x07, 7)

    // Ronda diagonal
    x00 += x05; x15 ^= x00; x15 = rotl<u32>(x15, 16)
    x10 += x15; x05 ^= x10; x05 = rotl<u32>(x05, 12)
    x00 += x05; x15 ^= x00; x15 = rotl<u32>(x15, 8)
    x10 += x15; x05 ^= x10; x05 = rotl<u32>(x05, 7)

    x01 += x06; x12 ^= x01; x12 = rotl<u32>(x12, 16)
    x11 += x12; x06 ^= x11; x06 = rotl<u32>(x06, 12)
    x01 += x06; x12 ^= x01; x12 = rotl<u32>(x12, 8)
    x11 += x12; x06 ^= x11; x06 = rotl<u32>(x06, 7)

    x02 += x07; x13 ^= x02; x13 = rotl<u32>(x13, 16)
    x08 += x13; x07 ^= x08; x07 = rotl<u32>(x07, 12)
    x02 += x07; x13 ^= x02; x13 = rotl<u32>(x13, 8)
    x08 += x13; x07 ^= x08; x07 = rotl<u32>(x07, 7)

    x03 += x04; x14 ^= x03; x14 = rotl<u32>(x14, 16)
    x09 += x14; x04 ^= x09; x04 = rotl<u32>(x04, 12)
    x03 += x04; x14 ^= x03; x14 = rotl<u32>(x14, 8)
    x09 += x14; x04 ^= x09; x04 = rotl<u32>(x04, 7)
  }

  // Sumar estado original y XOR con entrada
  store<u32>(outPtr, load<u32>(inPtr, 0) ^ (x00 + 0x61707865), 0)
  store<u32>(outPtr, load<u32>(inPtr, 4) ^ (x01 + 0x3320646e), 4)
  store<u32>(outPtr, load<u32>(inPtr, 8) ^ (x02 + 0x79622d32), 8)
  store<u32>(outPtr, load<u32>(inPtr, 12) ^ (x03 + 0x6b206574), 12)
  store<u32>(outPtr, load<u32>(inPtr, 16) ^ (x04 + k0), 16)
  store<u32>(outPtr, load<u32>(inPtr, 20) ^ (x05 + k1), 20)
  store<u32>(outPtr, load<u32>(inPtr, 24) ^ (x06 + k2), 24)
  store<u32>(outPtr, load<u32>(inPtr, 28) ^ (x07 + k3), 28)
  store<u32>(outPtr, load<u32>(inPtr, 32) ^ (x08 + k4), 32)
  store<u32>(outPtr, load<u32>(inPtr, 36) ^ (x09 + k5), 36)
  store<u32>(outPtr, load<u32>(inPtr, 40) ^ (x10 + k6), 40)
  store<u32>(outPtr, load<u32>(inPtr, 44) ^ (x11 + k7), 44)
  store<u32>(outPtr, load<u32>(inPtr, 48) ^ (x12 + ctr), 48)
  store<u32>(outPtr, load<u32>(inPtr, 52) ^ (x13 + n0), 52)
  store<u32>(outPtr, load<u32>(inPtr, 56) ^ (x14 + n1), 56)
  store<u32>(outPtr, load<u32>(inPtr, 60) ^ (x15 + n2), 60)
}

/**
 * Genera 64 bytes de keystream puro (sin XOR).
 * Usado para el último bloque parcial y derivación HChaCha20.
 */
// @ts-ignore
@inline
function chachaKeystreamBlock(
  k0: u32, k1: u32, k2: u32, k3: u32,
  k4: u32, k5: u32, k6: u32, k7: u32,
  n0: u32, n1: u32, n2: u32,
  ctr: u32,
  outPtr: usize,
  rounds: i32
): void {
  let x00 = 0x61707865 as u32
  let x01 = 0x3320646e as u32
  let x02 = 0x79622d32 as u32
  let x03 = 0x6b206574 as u32
  let x04 = k0, x05 = k1, x06 = k2, x07 = k3
  let x08 = k4, x09 = k5, x10 = k6, x11 = k7
  let x12 = ctr, x13 = n0, x14 = n1, x15 = n2

  for (let r = 0; r < rounds; r += 2) {
    x00 += x04; x12 ^= x00; x12 = rotl<u32>(x12, 16)
    x08 += x12; x04 ^= x08; x04 = rotl<u32>(x04, 12)
    x00 += x04; x12 ^= x00; x12 = rotl<u32>(x12, 8)
    x08 += x12; x04 ^= x08; x04 = rotl<u32>(x04, 7)

    x01 += x05; x13 ^= x01; x13 = rotl<u32>(x13, 16)
    x09 += x13; x05 ^= x09; x05 = rotl<u32>(x05, 12)
    x01 += x05; x13 ^= x01; x13 = rotl<u32>(x13, 8)
    x09 += x13; x05 ^= x09; x05 = rotl<u32>(x05, 7)

    x02 += x06; x14 ^= x02; x14 = rotl<u32>(x14, 16)
    x10 += x14; x06 ^= x10; x06 = rotl<u32>(x06, 12)
    x02 += x06; x14 ^= x02; x14 = rotl<u32>(x14, 8)
    x10 += x14; x06 ^= x10; x06 = rotl<u32>(x06, 7)

    x03 += x07; x15 ^= x03; x15 = rotl<u32>(x15, 16)
    x11 += x15; x07 ^= x11; x07 = rotl<u32>(x07, 12)
    x03 += x07; x15 ^= x03; x15 = rotl<u32>(x15, 8)
    x11 += x15; x07 ^= x11; x07 = rotl<u32>(x07, 7)

    x00 += x05; x15 ^= x00; x15 = rotl<u32>(x15, 16)
    x10 += x15; x05 ^= x10; x05 = rotl<u32>(x05, 12)
    x00 += x05; x15 ^= x00; x15 = rotl<u32>(x15, 8)
    x10 += x15; x05 ^= x10; x05 = rotl<u32>(x05, 7)

    x01 += x06; x12 ^= x01; x12 = rotl<u32>(x12, 16)
    x11 += x12; x06 ^= x11; x06 = rotl<u32>(x06, 12)
    x01 += x06; x12 ^= x01; x12 = rotl<u32>(x12, 8)
    x11 += x12; x06 ^= x11; x06 = rotl<u32>(x06, 7)

    x02 += x07; x13 ^= x02; x13 = rotl<u32>(x13, 16)
    x08 += x13; x07 ^= x08; x07 = rotl<u32>(x07, 12)
    x02 += x07; x13 ^= x02; x13 = rotl<u32>(x13, 8)
    x08 += x13; x07 ^= x08; x07 = rotl<u32>(x07, 7)

    x03 += x04; x14 ^= x03; x14 = rotl<u32>(x14, 16)
    x09 += x14; x04 ^= x09; x04 = rotl<u32>(x04, 12)
    x03 += x04; x14 ^= x03; x14 = rotl<u32>(x14, 8)
    x09 += x14; x04 ^= x09; x04 = rotl<u32>(x04, 7)
  }

  store<u32>(outPtr, x00 + 0x61707865, 0)
  store<u32>(outPtr, x01 + 0x3320646e, 4)
  store<u32>(outPtr, x02 + 0x79622d32, 8)
  store<u32>(outPtr, x03 + 0x6b206574, 12)
  store<u32>(outPtr, x04 + k0, 16)
  store<u32>(outPtr, x05 + k1, 20)
  store<u32>(outPtr, x06 + k2, 24)
  store<u32>(outPtr, x07 + k3, 28)
  store<u32>(outPtr, x08 + k4, 32)
  store<u32>(outPtr, x09 + k5, 36)
  store<u32>(outPtr, x10 + k6, 40)
  store<u32>(outPtr, x11 + k7, 44)
  store<u32>(outPtr, x12 + ctr, 48)
  store<u32>(outPtr, x13 + n0, 52)
  store<u32>(outPtr, x14 + n1, 56)
  store<u32>(outPtr, x15 + n2, 60)
}

/**
 * HChaCha20: Deriva subclave de 32 bytes a partir de clave de 256 bits y nonce de 128 bits.
 * Ejecuta las rondas SIN sumar el estado original al final (a diferencia de ChaCha20 normal).
 * Extrae los primeros 128 bits (x00-x03) y los últimos 128 bits (x12-x15) del estado.
 */
// @ts-ignore
@inline
function hchacha(
  k0: u32, k1: u32, k2: u32, k3: u32,
  k4: u32, k5: u32, k6: u32, k7: u32,
  n0: u32, n1: u32, n2: u32, n3: u32,
  outPtr: usize
): void {
  let x00 = 0x61707865 as u32
  let x01 = 0x3320646e as u32
  let x02 = 0x79622d32 as u32
  let x03 = 0x6b206574 as u32
  let x04 = k0, x05 = k1, x06 = k2, x07 = k3
  let x08 = k4, x09 = k5, x10 = k6, x11 = k7
  let x12 = n0, x13 = n1, x14 = n2, x15 = n3

  for (let r = 0; r < 20; r += 2) {
    x00 += x04; x12 ^= x00; x12 = rotl<u32>(x12, 16)
    x08 += x12; x04 ^= x08; x04 = rotl<u32>(x04, 12)
    x00 += x04; x12 ^= x00; x12 = rotl<u32>(x12, 8)
    x08 += x12; x04 ^= x08; x04 = rotl<u32>(x04, 7)

    x01 += x05; x13 ^= x01; x13 = rotl<u32>(x13, 16)
    x09 += x13; x05 ^= x09; x05 = rotl<u32>(x05, 12)
    x01 += x05; x13 ^= x01; x13 = rotl<u32>(x13, 8)
    x09 += x13; x05 ^= x09; x05 = rotl<u32>(x05, 7)

    x02 += x06; x14 ^= x02; x14 = rotl<u32>(x14, 16)
    x10 += x14; x06 ^= x10; x06 = rotl<u32>(x06, 12)
    x02 += x06; x14 ^= x02; x14 = rotl<u32>(x14, 8)
    x10 += x14; x06 ^= x10; x06 = rotl<u32>(x06, 7)

    x03 += x07; x15 ^= x03; x15 = rotl<u32>(x15, 16)
    x11 += x15; x07 ^= x11; x07 = rotl<u32>(x07, 12)
    x03 += x07; x15 ^= x03; x15 = rotl<u32>(x15, 8)
    x11 += x15; x07 ^= x11; x07 = rotl<u32>(x07, 7)

    x00 += x05; x15 ^= x00; x15 = rotl<u32>(x15, 16)
    x10 += x15; x05 ^= x10; x05 = rotl<u32>(x05, 12)
    x00 += x05; x15 ^= x00; x15 = rotl<u32>(x15, 8)
    x10 += x15; x05 ^= x10; x05 = rotl<u32>(x05, 7)

    x01 += x06; x12 ^= x01; x12 = rotl<u32>(x12, 16)
    x11 += x12; x06 ^= x11; x06 = rotl<u32>(x06, 12)
    x01 += x06; x12 ^= x01; x12 = rotl<u32>(x12, 8)
    x11 += x12; x06 ^= x11; x06 = rotl<u32>(x06, 7)

    x02 += x07; x13 ^= x02; x13 = rotl<u32>(x13, 16)
    x08 += x13; x07 ^= x08; x07 = rotl<u32>(x07, 12)
    x02 += x07; x13 ^= x02; x13 = rotl<u32>(x13, 8)
    x08 += x13; x07 ^= x08; x07 = rotl<u32>(x07, 7)

    x03 += x04; x14 ^= x03; x14 = rotl<u32>(x14, 16)
    x09 += x14; x04 ^= x09; x04 = rotl<u32>(x04, 12)
    x03 += x04; x14 ^= x03; x14 = rotl<u32>(x14, 8)
    x09 += x14; x04 ^= x09; x04 = rotl<u32>(x04, 7)
  }

  // Guardar los primeros 128 bits y los últimos 128 bits como subclave
  store<u32>(outPtr, x00, 0)
  store<u32>(outPtr, x01, 4)
  store<u32>(outPtr, x02, 8)
  store<u32>(outPtr, x03, 12)
  store<u32>(outPtr, x12, 16)
  store<u32>(outPtr, x13, 20)
  store<u32>(outPtr, x14, 24)
  store<u32>(outPtr, x15, 28)
}

// =============================================================================
// 🔧 LÓGICA INTERNA COMPARTIDA (encryptCore)
// =============================================================================

/**
 * Motor de cifrado/descifrado puro con punteros. Nucleo compartido por
 * encrypt(), encryptPtr(), y sus variantes estáticas.
 * Todos los parámetros son escalares o punteros — cero objetos GC.
 */
// @ts-ignore
@inline
function encryptCore(
  ctx: ChaCha20,
  inPtr: usize, outPtr: usize, len: u32
): void {
  let ctr = ctx.counter
  let pos: u32 = 0

  // Bloques completos de 64 bytes
  while (pos + 64 <= len) {
    chachaXorBlock(
      ctx.k0, ctx.k1, ctx.k2, ctx.k3,
      ctx.k4, ctx.k5, ctx.k6, ctx.k7,
      ctx.n0, ctx.n1, ctx.n2,
      ctr,
      inPtr + pos, outPtr + pos,
      ctx.rounds
    )
    ctr++
    pos += 64
  }

  // Último bloque parcial (0..63 bytes)
  if (pos < len) {
    let bPtr = ctx.blockPtr
    chachaKeystreamBlock(
      ctx.k0, ctx.k1, ctx.k2, ctx.k3,
      ctx.k4, ctx.k5, ctx.k6, ctx.k7,
      ctx.n0, ctx.n1, ctx.n2,
      ctr,
      bPtr,
      ctx.rounds
    )
    let take = len - pos
    for (let i: u32 = 0; i < take; i++) {
      store<u8>(outPtr + pos + i, load<u8>(inPtr + pos + i) ^ load<u8>(bPtr + i))
    }
    ctr++
    memory.fill(bPtr, 0, 64)
  }
  ctx.counter = ctr
}

/**
 * Motor de cifrado para XChaCha20 — idéntica lógica pero opera sobre XChaCha20.
 * Necesario porque AssemblyScript no soporta genéricos sobre @unmanaged classes.
 */
// @ts-ignore
@inline
function xEncryptCore(
  ctx: XChaCha20,
  inPtr: usize, outPtr: usize, len: u32
): void {
  let ctr = ctx.counter
  let pos: u32 = 0

  while (pos + 64 <= len) {
    chachaXorBlock(
      ctx.k0, ctx.k1, ctx.k2, ctx.k3,
      ctx.k4, ctx.k5, ctx.k6, ctx.k7,
      ctx.n0, ctx.n1, ctx.n2,
      ctr,
      inPtr + pos, outPtr + pos,
      ctx.rounds
    )
    ctr++
    pos += 64
  }

  if (pos < len) {
    let bPtr = ctx.blockPtr
    chachaKeystreamBlock(
      ctx.k0, ctx.k1, ctx.k2, ctx.k3,
      ctx.k4, ctx.k5, ctx.k6, ctx.k7,
      ctx.n0, ctx.n1, ctx.n2,
      ctr,
      bPtr,
      ctx.rounds
    )
    let take = len - pos
    for (let i: u32 = 0; i < take; i++) {
      store<u8>(outPtr + pos + i, load<u8>(inPtr + pos + i) ^ load<u8>(bPtr + i))
    }
    ctr++
    memory.fill(bPtr, 0, 64)
  }
  ctx.counter = ctr
}

// =============================================================================
// 🏛️ ChaCha20 (Nonce de 12 bytes — RFC 8439)
// =============================================================================

@final
@unmanaged
export class ChaCha20 {
  k0!: u32
  k1!: u32
  k2!: u32
  k3!: u32
  k4!: u32
  k5!: u32
  k6!: u32
  k7!: u32
  n0!: u32
  n1!: u32
  n2!: u32
  counter!: u32
  rounds!: i32
  blockPtr!: usize

  /**
   * Fábrica desde Uint8Array (validación de longitudes incluida).
   */
  static create(key: Uint8Array, nonce: Uint8Array, counter: u32 = 0, rounds: i32 = 20): ChaCha20 {
    if (key.length != 32) throw new Error("chacha20: clave debe ser 32 bytes")
    if (nonce.length != 12) throw new Error("chacha20: nonce debe ser 12 bytes")
    return ChaCha20.createFromPtr(key.dataStart, nonce.dataStart, counter, rounds)
  }

  /**
   * Fábrica desde punteros crudos — zero-alloc via arena local.
   * Carga la clave y el nonce directamente en registros del contexto.
   */
  static createFromPtr(kPtr: usize, nPtr: usize, counter: u32 = 0, rounds: i32 = 20): ChaCha20 {
    let ctxPtr = LocalArena.alloc(offsetof<ChaCha20>())
    let ctx = changetype<ChaCha20>(ctxPtr)
    ctx.blockPtr = LocalArena.alloc(64)

    ctx.k0 = load<u32>(kPtr, 0)
    ctx.k1 = load<u32>(kPtr, 4)
    ctx.k2 = load<u32>(kPtr, 8)
    ctx.k3 = load<u32>(kPtr, 12)
    ctx.k4 = load<u32>(kPtr, 16)
    ctx.k5 = load<u32>(kPtr, 20)
    ctx.k6 = load<u32>(kPtr, 24)
    ctx.k7 = load<u32>(kPtr, 28)
    ctx.n0 = load<u32>(nPtr, 0)
    ctx.n1 = load<u32>(nPtr, 4)
    ctx.n2 = load<u32>(nPtr, 8)
    ctx.counter = counter
    ctx.rounds = rounds

    return ctx
  }

  // =========================================================================
  // API DE Uint8Array (compatibilidad con código existente)
  // =========================================================================

  /**
   * Cifrado con interfaz Uint8Array. Ideal para uso directo desde JS/TS.
   */
  encrypt(data: Uint8Array, output: Uint8Array): void {
    let len = <u32>data.length
    if (<u32>output.length < len) throw new Error("chacha20: buffer de salida muy pequeño")
    if (len == 0) return
    encryptCore(this, data.dataStart, output.dataStart, len)
  }

  decrypt(data: Uint8Array, output: Uint8Array): void {
    this.encrypt(data, output)
  }

  // =========================================================================
  // 🚀 API DE PUNTEROS (para AEAD y uso interno zero-alloc)
  // =========================================================================

  /**
   * Cifrado/descifrado con punteros crudos. Cero objetos GC involucrados.
   * Diseñado específicamente para que el módulo AEAD pueda operar sin
   * crear Uint8Array intermedios (SHARED_AUTH_KEY, Uint8Array.wrap, etc).
   *
   * @param inPtr  - Puntero a los datos de entrada
   * @param outPtr - Puntero al buffer de salida (puede ser == inPtr para in-place)
   * @param len    - Longitud de los datos en bytes
   */
  encryptPtr(inPtr: usize, outPtr: usize, len: u32): void {
    if (len == 0) return
    encryptCore(this, inPtr, outPtr, len)
  }

  // =========================================================================
  // Métodos estáticos de conveniencia
  // =========================================================================

  static encrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, output: Uint8Array, counter: u32 = 0): void {
    const marker = LocalArena.save()
    const ctx = ChaCha20.create(key, nonce, counter)
    ctx.encrypt(data, output)
    LocalArena.restore(marker)
  }

  static decrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, output: Uint8Array, counter: u32 = 0): void {
    ChaCha20.encrypt(key, nonce, data, output, counter)
  }
}

// =============================================================================
// 🏛️ XChaCha20 (Nonce extendido de 24 bytes)
// =============================================================================

@final
@unmanaged
export class XChaCha20 {
  k0!: u32
  k1!: u32
  k2!: u32
  k3!: u32
  k4!: u32
  k5!: u32
  k6!: u32
  k7!: u32
  n0!: u32
  n1!: u32
  n2!: u32
  counter!: u32
  rounds!: i32
  blockPtr!: usize

  static create(key: Uint8Array, nonce: Uint8Array, counter: u32 = 0, rounds: i32 = 20): XChaCha20 {
    if (key.length != 32) throw new Error("xchacha20: clave debe ser 32 bytes")
    if (nonce.length != 24) throw new Error("xchacha20: nonce debe ser 24 bytes")
    return XChaCha20.createFromPtr(key.dataStart, nonce.dataStart, counter, rounds)
  }

  /**
   * Fábrica con derivación HChaCha20.
   * Pasos: 1) HChaCha20(key, nonce[0..16]) → subclave de 32 bytes
   *        2) Nonce final = [0x00000000, nonce[16..24]]
   */
  static createFromPtr(kPtr: usize, nPtr: usize, counter: u32 = 0, rounds: i32 = 20): XChaCha20 {
    let ctxPtr = LocalArena.alloc(offsetof<XChaCha20>())
    let ctx = changetype<XChaCha20>(ctxPtr)
    ctx.blockPtr = LocalArena.alloc(64)
    let bPtr = ctx.blockPtr

    // Derivar subclave via HChaCha20
    hchacha(
      load<u32>(kPtr, 0), load<u32>(kPtr, 4),
      load<u32>(kPtr, 8), load<u32>(kPtr, 12),
      load<u32>(kPtr, 16), load<u32>(kPtr, 20),
      load<u32>(kPtr, 24), load<u32>(kPtr, 28),
      load<u32>(nPtr, 0), load<u32>(nPtr, 4),
      load<u32>(nPtr, 8), load<u32>(nPtr, 12),
      bPtr
    )

    ctx.k0 = load<u32>(bPtr, 0)
    ctx.k1 = load<u32>(bPtr, 4)
    ctx.k2 = load<u32>(bPtr, 8)
    ctx.k3 = load<u32>(bPtr, 12)
    ctx.k4 = load<u32>(bPtr, 16)
    ctx.k5 = load<u32>(bPtr, 20)
    ctx.k6 = load<u32>(bPtr, 24)
    ctx.k7 = load<u32>(bPtr, 28)

    // Nonce extendido: primer u32 = 0, últimos 8 bytes del nonce original
    ctx.n0 = 0
    ctx.n1 = load<u32>(nPtr, 16)
    ctx.n2 = load<u32>(nPtr, 20)
    ctx.counter = counter
    ctx.rounds = rounds
    memory.fill(bPtr, 0, 32) // Limpiar subclave del scratchpad

    return ctx
  }

  // =========================================================================
  // API de Uint8Array
  // =========================================================================

  encrypt(data: Uint8Array, output: Uint8Array): void {
    let len = <u32>data.length
    if (<u32>output.length < len) throw new Error("xchacha20: buffer de salida muy pequeño")
    if (len == 0) return
    xEncryptCore(this, data.dataStart, output.dataStart, len)
  }

  decrypt(data: Uint8Array, output: Uint8Array): void {
    this.encrypt(data, output)
  }

  // =========================================================================
  // 🚀 API de punteros (para AEAD)
  // =========================================================================

  encryptPtr(inPtr: usize, outPtr: usize, len: u32): void {
    if (len == 0) return
    xEncryptCore(this, inPtr, outPtr, len)
  }

  // =========================================================================
  // Métodos estáticos
  // =========================================================================

  static encrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, output: Uint8Array, counter: u32 = 0): void {
    const marker = LocalArena.save()
    const ctx = XChaCha20.create(key, nonce, counter)
    ctx.encrypt(data, output)
    LocalArena.restore(marker)
  }

  static decrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, output: Uint8Array, counter: u32 = 0): void {
    XChaCha20.encrypt(key, nonce, data, output, counter)
  }
}

// =============================================================================
// 📦 EXPORTS DE ALTO NIVEL
// =============================================================================

export function chacha20_encrypt(
  key: Uint8Array, nonce: Uint8Array,
  data: Uint8Array, output: Uint8Array,
  counter: u32 = 0
): void {
  ChaCha20.encrypt(key, nonce, data, output, counter)
}

export function chacha20_decrypt(
  key: Uint8Array, nonce: Uint8Array,
  data: Uint8Array, output: Uint8Array,
  counter: u32 = 0
): void {
  ChaCha20.encrypt(key, nonce, data, output, counter)
}

export function xchacha20_encrypt(
  key: Uint8Array, nonce: Uint8Array,
  data: Uint8Array, output: Uint8Array,
  counter: u32 = 0
): void {
  XChaCha20.encrypt(key, nonce, data, output, counter)
}

export function xchacha20_decrypt(
  key: Uint8Array, nonce: Uint8Array,
  data: Uint8Array, output: Uint8Array,
  counter: u32 = 0
): void {
  XChaCha20.encrypt(key, nonce, data, output, counter)
}
