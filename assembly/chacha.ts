/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  chacha.ts — ChaCha20 & XChaCha20 (cifradores de flujo)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * ChaCha20  — nonce de 12 bytes (RFC 8439).
 * XChaCha20 — nonce extendido de 24 bytes (HChaCha20 + ChaCha20).
 *
 * 100% ZERO-ALLOC / SOLO PUNTEROS:
 *  • Sin Uint8Array ni `new` — los contextos son structs sobre puntero
 *    (changetype sobre la arena `Memory`).
 *  • Sin `throw` (runtime minimal) — las validaciones de longitud de clave/nonce
 *    las hace el wrapper TypeScript ANTES de llamar al WASM. El núcleo opera
 *    sobre punteros crudos y confía en el caller.
 *  • Funciones exportadas en `snake_case` por convención (p. ej.
 *    `chacha20_encrypt_ptr`); las clases PascalCase son solo para uso interno
 *    del módulo (no llegan al WASM: AS235).
 *
 * ── STREAMING (cifrado de archivos grandes en tiempo real) ────────────────
 * ChaCha20 es incremental: el `counter` y el `blockPos` viven en el contexto y
 * AVANZAN con cada `encryptPtr`. Un mismo contexto puede cifrar un archivo en
 * chunks arbitrarios (no múltiplos de 64) sin acumular nada en memoria:
 *
 *   const ctx = ChaCha20.createFromPtr(keyPtr, noncePtr, 0)  // 1) init
 *   ctx.encryptPtr(chunk1In, chunk1Out, chunk1Len)           // 2) cifra chunk 1
 *   ctx.encryptPtr(chunk2In, chunk2Out, chunk2Len)           //    (counter/blockPos siguen)
 *   ctx.encryptPtr(chunkNIn, chunkNOut, chunkNLen)           //    …tantos como quieras
 *
 * Entre `encryptPtr` y `encryptPtr` NO se reserva memoria nueva. El bloque de
 * keystream parcial (blockPtr) se reusa. Este streaming lo orquesta el AEAD
 * (aead.ts) para cifrar+autenticar archivos por chunks.
 *
 * ── ONE-SHOT (mensajes completos en memoria) ──────────────────────────────
 * Los wrappers exportados (`chacha20_encrypt_ptr`, …) hacen
 * save → createFromPtr → encryptPtr → wipe → restore en una llamada.
 *
 * ── LIMPIEZA DE MATERIAL SENSIBLE ─────────────────────────────────────────
 * `wipe()` limpia TODO el contexto: el keystream pendiente (blockPtr, 64 B) y
 * la clave/nonce/counter (offsetof). Lo llaman los wrappers one-shot antes del
 * restore y el AEAD (wipeAll) al cerrar un stream. `createFromPtr` limpia el
 * buffer recién alojado (basura de la arena / subclave de HChaCha20).
 *
 * Claves de rendimiento: doble ronda desenrollada (columnar + diagonal) por
 * iteración del bucle, máximo throughput en WebAssembly escalar (sin SIMD).
 */
import { Memory } from "./memory"

// ═══════════════════════════════════════════════════════════════════════════
// ⚡ NÚCLEO (HOT PATH) — validado, sin cambios
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Bloque ChaCha20 completo con XOR contra datos de entrada.
 * Procesa exactamente 64 bytes: out[i] = in[i] ^ keystream[i].
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

  // Doble ronda desenrollada (columnar + diagonal)
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
 * Usado para el último bloque parcial y la derivación HChaCha20.
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
 * HChaCha20: deriva una subclave de 32 bytes a partir de una clave de 256 bits
 * y un nonce de 128 bits. Ejecuta las rondas SIN sumar el estado original al
 * final; extrae los primeros 128 bits (x00–x03) y los últimos 128 bits (x12–x15).
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

  // Subclave: primeros 128 bits (x00–x03) + últimos 128 bits (x12–x15)
  store<u32>(outPtr, x00, 0)
  store<u32>(outPtr, x01, 4)
  store<u32>(outPtr, x02, 8)
  store<u32>(outPtr, x03, 12)
  store<u32>(outPtr, x12, 16)
  store<u32>(outPtr, x13, 20)
  store<u32>(outPtr, x14, 24)
  store<u32>(outPtr, x15, 28)
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔧 MOTOR DE CIFRADO (compartido, con punteros, counter/blockPos persistentes)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Motor de cifrado INCREMENTAL (streaming) con punteros.
 * Mantiene el estado del bloque parcial entre llamadas vía ctx.blockPos:
 *  1) completa el bloque pendiente (keystream ya en blockPtr),
 *  2) procesa bloques completos,
 *  3) genera el bloque parcial final y GUARDA el offset (sin tirar el resto
 *     ni avanzar el counter hasta que el bloque se complete).
 * Así el keystream es continuo aunque los chunks no sean múltiplos de 64.
 */
// @ts-ignore
@inline
function encryptCore(ctx: ChaCha20, inPtr: usize, outPtr: usize, len: u32): void {
  if (len == 0) return
  let pos: u32 = 0
  let remaining = len
  const bPtr = ctx.blockPtr

  // 1. Completar el bloque parcial pendiente (keystream ya generado en bPtr)
  let bp = ctx.blockPos
  if (bp > 0) {
    let take = <u32>64 - bp
    if (take > remaining) take = remaining
    for (let i: u32 = 0; i < take; i++) {
      store<u8>(outPtr + pos + i, load<u8>(inPtr + pos + i) ^ load<u8>(bPtr + bp + i))
    }
    bp += take
    pos += take
    remaining -= take
    if (bp == 64) {
      bp = 0
      ctx.counter++
      memory.fill(bPtr, 0, 64) // bloque completado: limpiar keystream
    }
  }

  // 2. Bloques completos
  while (remaining >= 64) {
    chachaXorBlock(
      ctx.k0, ctx.k1, ctx.k2, ctx.k3,
      ctx.k4, ctx.k5, ctx.k6, ctx.k7,
      ctx.n0, ctx.n1, ctx.n2,
      ctx.counter,
      inPtr + pos, outPtr + pos,
      ctx.rounds
    )
    ctx.counter++
    pos += 64
    remaining -= 64
  }

  // 3. Bloque parcial final: generar keystream en bPtr y guardar el offset
  //    (NO se incrementa el counter ni se limpia bPtr: se reusa en la próxima llamada)
  if (remaining > 0) {
    chachaKeystreamBlock(
      ctx.k0, ctx.k1, ctx.k2, ctx.k3,
      ctx.k4, ctx.k5, ctx.k6, ctx.k7,
      ctx.n0, ctx.n1, ctx.n2,
      ctx.counter,
      bPtr,
      ctx.rounds
    )
    for (let i: u32 = 0; i < remaining; i++) {
      store<u8>(outPtr + pos + i, load<u8>(inPtr + pos + i) ^ load<u8>(bPtr + i))
    }
    bp = remaining
  }

  ctx.blockPos = bp
}

/**
 * Motor de cifrado para XChaCha20 — lógica idéntica, opera sobre XChaCha20.
 * Duplicado necesario: AssemblyScript no soporta genéricos sobre @unmanaged.
 * También incremental: persiste `ctx.counter`/`ctx.blockPos` al salir.
 */
// @ts-ignore
@inline
function xEncryptCore(ctx: XChaCha20, inPtr: usize, outPtr: usize, len: u32): void {
  if (len == 0) return
  let pos: u32 = 0
  let remaining = len
  const bPtr = ctx.blockPtr

  // 1. Completar el bloque parcial pendiente (keystream ya generado en bPtr)
  let bp = ctx.blockPos
  if (bp > 0) {
    let take = <u32>64 - bp
    if (take > remaining) take = remaining
    for (let i: u32 = 0; i < take; i++) {
      store<u8>(outPtr + pos + i, load<u8>(inPtr + pos + i) ^ load<u8>(bPtr + bp + i))
    }
    bp += take
    pos += take
    remaining -= take
    if (bp == 64) {
      bp = 0
      ctx.counter++
      memory.fill(bPtr, 0, 64) // bloque completado: limpiar keystream
    }
  }

  // 2. Bloques completos
  while (remaining >= 64) {
    chachaXorBlock(
      ctx.k0, ctx.k1, ctx.k2, ctx.k3,
      ctx.k4, ctx.k5, ctx.k6, ctx.k7,
      ctx.n0, ctx.n1, ctx.n2,
      ctx.counter,
      inPtr + pos, outPtr + pos,
      ctx.rounds
    )
    ctx.counter++
    pos += 64
    remaining -= 64
  }

  // 3. Bloque parcial final: generar keystream en bPtr y guardar el offset
  //    (NO se incrementa el counter ni se limpia bPtr: se reusa en la próxima llamada)
  if (remaining > 0) {
    chachaKeystreamBlock(
      ctx.k0, ctx.k1, ctx.k2, ctx.k3,
      ctx.k4, ctx.k5, ctx.k6, ctx.k7,
      ctx.n0, ctx.n1, ctx.n2,
      ctx.counter,
      bPtr,
      ctx.rounds
    )
    for (let i: u32 = 0; i < remaining; i++) {
      store<u8>(outPtr + pos + i, load<u8>(inPtr + pos + i) ^ load<u8>(bPtr + i))
    }
    bp = remaining
  }

  ctx.blockPos = bp
}

// ═══════════════════════════════════════════════════════════════════════════
// 🏛️ ChaCha20 (nonce de 12 bytes — RFC 8439)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Contexto ChaCha20 como struct sobre puntero (zero-alloc, sin `new`).
 * La clave y el nonce se cargan en registros (k0..k7, n0..n2); el bloque de
 * keystream parcial vive en la arena (blockPtr) y se reusa entre chunks.
 *
 * Uso streaming (interno del módulo, p. ej. AEAD para archivos):
 *   const ctx = ChaCha20.createFromPtr(kPtr, nPtr, 0)  // init
 *   ctx.encryptPtr(in1, out1, len1)                     // chunk 1 (counter 0..)
 *   ctx.encryptPtr(in2, out2, len2)                     // chunk 2 (counter sigue)
 */
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
  blockPos!: u32 // bytes ya usados del bloque actual en blockPtr (0..63), para streaming

  /**
   * [STREAMING · INIT] Fábrica desde punteros crudos — zero-alloc vía arena
   * `Memory` (sin `new`). Carga la clave (32 B) y el nonce (12 B) en registros.
   * Limpia el buffer de keystream recién alojado (basura de la arena).
   * El caller garantiza las longitudes (validadas en el wrapper TS).
   */
  static createFromPtr(kPtr: usize, nPtr: usize, counter: u32 = 0, rounds: i32 = 20): ChaCha20 {
    let ctxPtr = Memory.alloc(offsetof<ChaCha20>())
    let ctx = changetype<ChaCha20>(ctxPtr)
    ctx.blockPtr = Memory.alloc(64)
    memory.fill(ctx.blockPtr, 0, 64) // limpiar basura de la arena (defensa en profundidad)

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
    ctx.blockPos = 0
    return ctx
  }

  /**
   * [STREAMING · UPDATE] Cifrado/descifrado incremental con punteros crudos.
   * Cero objetos GC. El `counter`/`blockPos` del contexto avanzan con los bytes
   * procesados, así llamadas sucesivas continúan el keystream (chunks arbitrarios).
   *
   * @param inPtr  Puntero a los datos de entrada (del chunk).
   * @param outPtr Puntero al buffer de salida (puede ser == inPtr para in-place).
   * @param len    Longitud del chunk en bytes.
   */
  encryptPtr(inPtr: usize, outPtr: usize, len: u32): void {
    encryptCore(this, inPtr, outPtr, len) // encryptCore ya hace `if (len == 0) return`
  }

  /**
   * Limpia TODO el material sensible: el keystream pendiente (blockPtr, 64 B)
   * y el contexto completo (clave k0..k7, nonce n0..n2, counter, blockPos).
   * Lo llaman los wrappers one-shot antes del restore y el AEAD (wipeAll).
   */
  // @ts-ignore
  @inline
  wipe(): void {
    memory.fill(this.blockPtr, 0, 64) // buffer de keystream parcial
    memory.fill(changetype<usize>(this), 0, offsetof<ChaCha20>()) // k, n, counter, blockPtr…
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🏛️ XChaCha20 (nonce extendido de 24 bytes)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Contexto XChaCha20 como struct sobre puntero (zero-alloc, sin `new`).
 * Deriva la subclave vía HChaCha20 en createFromPtr; el nonce final es
 * [0x00000000, nonce[16..24]]. Incremental igual que ChaCha20.
 *
 * Uso streaming (interno del módulo):
 *   const ctx = XChaCha20.createFromPtr(kPtr, nPtr, 0)
 *   ctx.encryptPtr(in1, out1, len1)
 *   ctx.encryptPtr(in2, out2, len2)
 */
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
  blockPos!: u32 // bytes ya usados del bloque actual en blockPtr (0..63), para streaming

  /**
   * [STREAMING · INIT] Fábrica con derivación HChaCha20 (zero-alloc, sin `new`):
   *  1) HChaCha20(key, nonce[0..16]) → subclave de 32 bytes.
   *  2) Nonce final = [0x00000000, nonce[16..24]].
   * Limpia el buffer completo (subclave + basura restante, 64 B).
   * El caller garantiza las longitudes (clave 32 B, nonce 24 B).
   */
  static createFromPtr(kPtr: usize, nPtr: usize, counter: u32 = 0, rounds: i32 = 20): XChaCha20 {
    let ctxPtr = Memory.alloc(offsetof<XChaCha20>())
    let ctx = changetype<XChaCha20>(ctxPtr)
    ctx.blockPtr = Memory.alloc(64)
    let bPtr = ctx.blockPtr

    // Derivar subclave vía HChaCha20
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
    ctx.blockPos = 0
    memory.fill(bPtr, 0, 64) // limpiar subclave (32 B) + basura restante (32 B)

    return ctx
  }

  /**
   * [STREAMING · UPDATE] Cifrado/descifrado incremental con punteros crudos.
   * El `counter`/`blockPos` persisten entre llamadas (streaming por chunks).
   */
  encryptPtr(inPtr: usize, outPtr: usize, len: u32): void {
    xEncryptCore(this, inPtr, outPtr, len) // xEncryptCore ya hace `if (len == 0) return`
  }

  /**
   * Limpia TODO el material sensible: el keystream pendiente (blockPtr, 64 B)
   * y el contexto completo (subclave k0..k7, nonce n0..n2, counter, blockPos).
   */
  // @ts-ignore
  @inline
  wipe(): void {
    memory.fill(this.blockPtr, 0, 64) // buffer de keystream parcial
    memory.fill(changetype<usize>(this), 0, offsetof<XChaCha20>()) // k, n, counter, blockPtr…
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🚀 WRAPPERS EXPORTADOS (one-shot, solo punteros, snake_case)
// ═══════════════════════════════════════════════════════════════════════════
// NOTA: con --runtime stub NO se permiten parámetros con valor por defecto en
// funciones EXPORTADAS (el runtime no provee __argumentsLength y el export
// trapea con `unreachable`). Por eso `counter` es OBLIGATORIO aquí; el wrapper
// TypeScript siempre lo pasa. Los defaults siguen disponibles en las funciones
// internas (createFromPtr), que asc resuelve en compile-time.

/** [ONE-SHOT] ChaCha20 encrypt/decrypt (in-place posible: inPtr == outPtr). */
export function chacha20_encrypt_ptr(
  kPtr: usize, nPtr: usize,
  inPtr: usize, outPtr: usize, len: u32,
  counter: u32
): void {
  const marker = Memory.save()
  const ctx = ChaCha20.createFromPtr(kPtr, nPtr, counter)
  ctx.encryptPtr(inPtr, outPtr, len)
  ctx.wipe() // limpiar keystream pendiente + clave/nonce (seguridad)
  Memory.restore(marker)
}

export function chacha20_decrypt_ptr(
  kPtr: usize, nPtr: usize,
  inPtr: usize, outPtr: usize, len: u32,
  counter: u32
): void {
  chacha20_encrypt_ptr(kPtr, nPtr, inPtr, outPtr, len, counter)
}

/** [ONE-SHOT] XChaCha20 encrypt/decrypt (in-place posible: inPtr == outPtr). */
export function xchacha20_encrypt_ptr(
  kPtr: usize, nPtr: usize,
  inPtr: usize, outPtr: usize, len: u32,
  counter: u32
): void {
  const marker = Memory.save()
  const ctx = XChaCha20.createFromPtr(kPtr, nPtr, counter)
  ctx.encryptPtr(inPtr, outPtr, len)
  ctx.wipe() // limpiar keystream pendiente + subclave/nonce (seguridad)
  Memory.restore(marker)
}

export function xchacha20_decrypt_ptr(
  kPtr: usize, nPtr: usize,
  inPtr: usize, outPtr: usize, len: u32,
  counter: u32
): void {
  xchacha20_encrypt_ptr(kPtr, nPtr, inPtr, outPtr, len, counter)
}