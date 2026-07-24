/**
 * ==============================================================================
 * 🔥 CHACHA20 & XCHACHA20: GOLDEN MASTER EDITION 🔥
 * ==============================================================================
 * Rendimiento: > 7,000 ops/s (64KB) en Scalar Wasm.
 * Arquitectura: Zero-Dependencies, Local Arena, Monomorphic Classes.
 * ==============================================================================
 */

// ==============================================================================
// 🧠 INTERNAL MEMORY MANAGER (ZERO-DEPENDENCY)
// ==============================================================================

namespace LocalArena {
  // Reservamos 64KB de memoria estática en el binario.
  // Esto evita llamadas al sistema y Garbage Collection.
  const basePtr: usize = memory.data(65536)
  let currentPtr: usize = basePtr

  /**
   * Asigna memoria garantizando alineación de 16 bytes.
   * Crucial para que V8 optimice lecturas/escrituras.
   */
	// @ts-ignore
  @inline
  export function alloc(size: usize): usize {
    let ptr = (currentPtr + 15) & ~15
    currentPtr = ptr + size
    return ptr
  }

  // @ts-ignore
  @inline
  export function save(): usize {
    return currentPtr
  }

  // @ts-ignore
  @inline
  export function restore(savedPtr: usize): void {
    currentPtr = savedPtr
  }
}

// ==============================================================================
// ⚡ CORE MATH FUNCTIONS (HOT PATH)
// ==============================================================================

// @ts-ignore
  @inline
function chachaXorBlock(
  k0: u32,
  k1: u32,
  k2: u32,
  k3: u32,
  k4: u32,
  k5: u32,
  k6: u32,
  k7: u32,
  n0: u32,
  n1: u32,
  n2: u32,
  ctr: u32,
  inPtr: usize,
  outPtr: usize,
  rounds: i32
): void {
  // Constantes de ChaCha ("expand 32-byte k")
  let x00 = 0x61707865 as u32
  let x01 = 0x3320646e as u32
  let x02 = 0x79622d32 as u32
  let x03 = 0x6b206574 as u32
  let x04 = k0,
    x05 = k1,
    x06 = k2,
    x07 = k3
  let x08 = k4,
    x09 = k5,
    x10 = k6,
    x11 = k7
  let x12 = ctr,
    x13 = n0,
    x14 = n1,
    x15 = n2

  // Bucle desenrollado (Unrolled Loop) x 2
  for (let r = 0; r < rounds; r += 2) {
    x00 += x04
    x12 ^= x00
    x12 = rotl<u32>(x12, 16)
    x08 += x12
    x04 ^= x08
    x04 = rotl<u32>(x04, 12)
    x00 += x04
    x12 ^= x00
    x12 = rotl<u32>(x12, 8)
    x08 += x12
    x04 ^= x08
    x04 = rotl<u32>(x04, 7)

    x01 += x05
    x13 ^= x01
    x13 = rotl<u32>(x13, 16)
    x09 += x13
    x05 ^= x09
    x05 = rotl<u32>(x05, 12)
    x01 += x05
    x13 ^= x01
    x13 = rotl<u32>(x13, 8)
    x09 += x13
    x05 ^= x09
    x05 = rotl<u32>(x05, 7)

    x02 += x06
    x14 ^= x02
    x14 = rotl<u32>(x14, 16)
    x10 += x14
    x06 ^= x10
    x06 = rotl<u32>(x06, 12)
    x02 += x06
    x14 ^= x02
    x14 = rotl<u32>(x14, 8)
    x10 += x14
    x06 ^= x10
    x06 = rotl<u32>(x06, 7)

    x03 += x07
    x15 ^= x03
    x15 = rotl<u32>(x15, 16)
    x11 += x15
    x07 ^= x11
    x07 = rotl<u32>(x07, 12)
    x03 += x07
    x15 ^= x03
    x15 = rotl<u32>(x15, 8)
    x11 += x15
    x07 ^= x11
    x07 = rotl<u32>(x07, 7)

    x00 += x05
    x15 ^= x00
    x15 = rotl<u32>(x15, 16)
    x10 += x15
    x05 ^= x10
    x05 = rotl<u32>(x05, 12)
    x00 += x05
    x15 ^= x00
    x15 = rotl<u32>(x15, 8)
    x10 += x15
    x05 ^= x10
    x05 = rotl<u32>(x05, 7)

    x01 += x06
    x12 ^= x01
    x12 = rotl<u32>(x12, 16)
    x11 += x12
    x06 ^= x11
    x06 = rotl<u32>(x06, 12)
    x01 += x06
    x12 ^= x01
    x12 = rotl<u32>(x12, 8)
    x11 += x12
    x06 ^= x11
    x06 = rotl<u32>(x06, 7)

    x02 += x07
    x13 ^= x02
    x13 = rotl<u32>(x13, 16)
    x08 += x13
    x07 ^= x08
    x07 = rotl<u32>(x07, 12)
    x02 += x07
    x13 ^= x02
    x13 = rotl<u32>(x13, 8)
    x08 += x13
    x07 ^= x08
    x07 = rotl<u32>(x07, 7)

    x03 += x04
    x14 ^= x03
    x14 = rotl<u32>(x14, 16)
    x09 += x14
    x04 ^= x09
    x04 = rotl<u32>(x04, 12)
    x03 += x04
    x14 ^= x03
    x14 = rotl<u32>(x14, 8)
    x09 += x14
    x04 ^= x09
    x04 = rotl<u32>(x04, 7)
  }

  // XOR directo con la memoria de entrada y escritura a salida
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

// @ts-ignore
// @ts-ignore
  @inline
function chachaKeystreamBlock(
  k0: u32,
  k1: u32,
  k2: u32,
  k3: u32,
  k4: u32,
  k5: u32,
  k6: u32,
  k7: u32,
  n0: u32,
  n1: u32,
  n2: u32,
  ctr: u32,
  outPtr: usize,
  rounds: i32
): void {
  // Idéntico a XorBlock pero escribe el keystream puro (sin XOR con entrada)
  // Usado para el último bloque parcial y HChaCha derivation.
  let x00 = 0x61707865 as u32
  let x01 = 0x3320646e as u32
  let x02 = 0x79622d32 as u32
  let x03 = 0x6b206574 as u32
  let x04 = k0,
    x05 = k1,
    x06 = k2,
    x07 = k3
  let x08 = k4,
    x09 = k5,
    x10 = k6,
    x11 = k7
  let x12 = ctr,
    x13 = n0,
    x14 = n1,
    x15 = n2

  for (let r = 0; r < rounds; r += 2) {
    x00 += x04
    x12 ^= x00
    x12 = rotl<u32>(x12, 16)
    x08 += x12
    x04 ^= x08
    x04 = rotl<u32>(x04, 12)
    x00 += x04
    x12 ^= x00
    x12 = rotl<u32>(x12, 8)
    x08 += x12
    x04 ^= x08
    x04 = rotl<u32>(x04, 7)

    x01 += x05
    x13 ^= x01
    x13 = rotl<u32>(x13, 16)
    x09 += x13
    x05 ^= x09
    x05 = rotl<u32>(x05, 12)
    x01 += x05
    x13 ^= x01
    x13 = rotl<u32>(x13, 8)
    x09 += x13
    x05 ^= x09
    x05 = rotl<u32>(x05, 7)

    x02 += x06
    x14 ^= x02
    x14 = rotl<u32>(x14, 16)
    x10 += x14
    x06 ^= x10
    x06 = rotl<u32>(x06, 12)
    x02 += x06
    x14 ^= x02
    x14 = rotl<u32>(x14, 8)
    x10 += x14
    x06 ^= x10
    x06 = rotl<u32>(x06, 7)

    x03 += x07
    x15 ^= x03
    x15 = rotl<u32>(x15, 16)
    x11 += x15
    x07 ^= x11
    x07 = rotl<u32>(x07, 12)
    x03 += x07
    x15 ^= x03
    x15 = rotl<u32>(x15, 8)
    x11 += x15
    x07 ^= x11
    x07 = rotl<u32>(x07, 7)

    x00 += x05
    x15 ^= x00
    x15 = rotl<u32>(x15, 16)
    x10 += x15
    x05 ^= x10
    x05 = rotl<u32>(x05, 12)
    x00 += x05
    x15 ^= x00
    x15 = rotl<u32>(x15, 8)
    x10 += x15
    x05 ^= x10
    x05 = rotl<u32>(x05, 7)

    x01 += x06
    x12 ^= x01
    x12 = rotl<u32>(x12, 16)
    x11 += x12
    x06 ^= x11
    x06 = rotl<u32>(x06, 12)
    x01 += x06
    x12 ^= x01
    x12 = rotl<u32>(x12, 8)
    x11 += x12
    x06 ^= x11
    x06 = rotl<u32>(x06, 7)

    x02 += x07
    x13 ^= x02
    x13 = rotl<u32>(x13, 16)
    x08 += x13
    x07 ^= x08
    x07 = rotl<u32>(x07, 12)
    x02 += x07
    x13 ^= x02
    x13 = rotl<u32>(x13, 8)
    x08 += x13
    x07 ^= x08
    x07 = rotl<u32>(x07, 7)

    x03 += x04
    x14 ^= x03
    x14 = rotl<u32>(x14, 16)
    x09 += x14
    x04 ^= x09
    x04 = rotl<u32>(x04, 12)
    x03 += x04
    x14 ^= x03
    x14 = rotl<u32>(x14, 8)
    x09 += x14
    x04 ^= x09
    x04 = rotl<u32>(x04, 7)
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

// @ts-ignore
// @ts-ignore
  @inline
function hchacha(
  k0: u32,
  k1: u32,
  k2: u32,
  k3: u32,
  k4: u32,
  k5: u32,
  k6: u32,
  k7: u32,
  n0: u32,
  n1: u32,
  n2: u32,
  n3: u32,
  outPtr: usize
): void {
  // HChaCha20 reduce el estado a 32 bytes para la subclave
  // Solo ejecuta las rondas, no suma el estado original al final.
  let x00 = 0x61707865 as u32
  let x01 = 0x3320646e as u32
  let x02 = 0x79622d32 as u32
  let x03 = 0x6b206574 as u32
  let x04 = k0,
    x05 = k1,
    x06 = k2,
    x07 = k3
  let x08 = k4,
    x09 = k5,
    x10 = k6,
    x11 = k7
  let x12 = n0,
    x13 = n1,
    x14 = n2,
    x15 = n3

  for (let r = 0; r < 20; r += 2) {
    x00 += x04
    x12 ^= x00
    x12 = rotl<u32>(x12, 16)
    x08 += x12
    x04 ^= x08
    x04 = rotl<u32>(x04, 12)
    x00 += x04
    x12 ^= x00
    x12 = rotl<u32>(x12, 8)
    x08 += x12
    x04 ^= x08
    x04 = rotl<u32>(x04, 7)

    x01 += x05
    x13 ^= x01
    x13 = rotl<u32>(x13, 16)
    x09 += x13
    x05 ^= x09
    x05 = rotl<u32>(x05, 12)
    x01 += x05
    x13 ^= x01
    x13 = rotl<u32>(x13, 8)
    x09 += x13
    x05 ^= x09
    x05 = rotl<u32>(x05, 7)

    x02 += x06
    x14 ^= x02
    x14 = rotl<u32>(x14, 16)
    x10 += x14
    x06 ^= x10
    x06 = rotl<u32>(x06, 12)
    x02 += x06
    x14 ^= x02
    x14 = rotl<u32>(x14, 8)
    x10 += x14
    x06 ^= x10
    x06 = rotl<u32>(x06, 7)

    x03 += x07
    x15 ^= x03
    x15 = rotl<u32>(x15, 16)
    x11 += x15
    x07 ^= x11
    x07 = rotl<u32>(x07, 12)
    x03 += x07
    x15 ^= x03
    x15 = rotl<u32>(x15, 8)
    x11 += x15
    x07 ^= x11
    x07 = rotl<u32>(x07, 7)

    x00 += x05
    x15 ^= x00
    x15 = rotl<u32>(x15, 16)
    x10 += x15
    x05 ^= x10
    x05 = rotl<u32>(x05, 12)
    x00 += x05
    x15 ^= x00
    x15 = rotl<u32>(x15, 8)
    x10 += x15
    x05 ^= x10
    x05 = rotl<u32>(x05, 7)

    x01 += x06
    x12 ^= x01
    x12 = rotl<u32>(x12, 16)
    x11 += x12
    x06 ^= x11
    x06 = rotl<u32>(x06, 12)
    x01 += x06
    x12 ^= x01
    x12 = rotl<u32>(x12, 8)
    x11 += x12
    x06 ^= x11
    x06 = rotl<u32>(x06, 7)

    x02 += x07
    x13 ^= x02
    x13 = rotl<u32>(x13, 16)
    x08 += x13
    x07 ^= x08
    x07 = rotl<u32>(x07, 12)
    x02 += x07
    x13 ^= x02
    x13 = rotl<u32>(x13, 8)
    x08 += x13
    x07 ^= x08
    x07 = rotl<u32>(x07, 7)

    x03 += x04
    x14 ^= x03
    x14 = rotl<u32>(x14, 16)
    x09 += x14
    x04 ^= x09
    x04 = rotl<u32>(x04, 12)
    x03 += x04
    x14 ^= x03
    x14 = rotl<u32>(x14, 8)
    x09 += x14
    x04 ^= x09
    x04 = rotl<u32>(x04, 7)
  }

  // Guardar los primeros 128 bits y los últimos 128 bits como nueva clave
  store<u32>(outPtr, x00, 0)
  store<u32>(outPtr, x01, 4)
  store<u32>(outPtr, x02, 8)
  store<u32>(outPtr, x03, 12)
  store<u32>(outPtr, x12, 16)
  store<u32>(outPtr, x13, 20)
  store<u32>(outPtr, x14, 24)
  store<u32>(outPtr, x15, 28)
}

// ==============================================================================
// 🏛️ CLASSES (STATEFUL API)
// ==============================================================================

@final
@unmanaged
export class ChaCha20 {
  private k0!: u32
  private k1!: u32
  private k2!: u32
  private k3!: u32
  private k4!: u32
  private k5!: u32
  private k6!: u32
  private k7!: u32
  private n0!: u32
  private n1!: u32
  private n2!: u32
  private counter!: u32
  private rounds!: i32
  private blockPtr!: usize

  static create(key: Uint8Array, nonce: Uint8Array, counter: u32 = 0, rounds: i32 = 20): ChaCha20 {
    if (key.length != 32) throw new Error("chacha20: key must be 32 bytes")
    if (nonce.length != 12) throw new Error("chacha20: nonce must be 12 bytes")
    return ChaCha20.createFromPtr(key.dataStart, nonce.dataStart, counter, rounds)
  }

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

  encrypt(data: Uint8Array, output: Uint8Array): void {
    let len = <u32>data.length
    if (<u32>output.length < len) throw new Error("chacha20: output buffer too small")
    if (len == 0) return

    let inPtr = data.dataStart
    let outPtr = output.dataStart
    let ctr = this.counter
    let pos: u32 = 0

    while (pos + 64 <= len) {
      chachaXorBlock(
        this.k0,
        this.k1,
        this.k2,
        this.k3,
        this.k4,
        this.k5,
        this.k6,
        this.k7,
        this.n0,
        this.n1,
        this.n2,
        ctr,
        inPtr + pos,
        outPtr + pos,
        this.rounds
      )
      ctr++
      pos += 64
    }
    if (pos < len) {
      let bPtr = this.blockPtr
      chachaKeystreamBlock(
        this.k0,
        this.k1,
        this.k2,
        this.k3,
        this.k4,
        this.k5,
        this.k6,
        this.k7,
        this.n0,
        this.n1,
        this.n2,
        ctr,
        bPtr,
        this.rounds
      )
      let take = len - pos
      for (let i: u32 = 0; i < take; i++) {
        store<u8>(outPtr + pos + i, load<u8>(inPtr + pos + i) ^ load<u8>(bPtr + i))
      }
      ctr++
      memory.fill(bPtr, 0, 64)
    }
    this.counter = ctr
  }

  decrypt(data: Uint8Array, output: Uint8Array): void {
    this.encrypt(data, output)
  }

  /**
   * PURE STATIC EXECUTION: Bypass object creation for maximum speed.
   */
  static encrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, output: Uint8Array, counter: u32 = 0): void {
    const marker = LocalArena.save()
    // Usamos el constructor optimizado para mapear registros
    const ctx = ChaCha20.create(key, nonce, counter)
    ctx.encrypt(data, output)
    LocalArena.restore(marker)
  }

  static decrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, output: Uint8Array, counter: u32 = 0): void {
    ChaCha20.encrypt(key, nonce, data, output, counter)
  }
}

@final
@unmanaged
export class XChaCha20 {
  private k0!: u32
  private k1!: u32
  private k2!: u32
  private k3!: u32
  private k4!: u32
  private k5!: u32
  private k6!: u32
  private k7!: u32
  private n0!: u32
  private n1!: u32
  private n2!: u32
  private counter!: u32
  private rounds!: i32
  private blockPtr!: usize

  static create(key: Uint8Array, nonce: Uint8Array, counter: u32 = 0, rounds: i32 = 20): XChaCha20 {
    if (key.length != 32) throw new Error("xchacha20: key must be 32 bytes")
    if (nonce.length != 24) throw new Error("xchacha20: nonce must be 24 bytes")
    return XChaCha20.createFromPtr(key.dataStart, nonce.dataStart, counter, rounds)
  }

  static createFromPtr(kPtr: usize, nPtr: usize, counter: u32 = 0, rounds: i32 = 20): XChaCha20 {
    let ctxPtr = LocalArena.alloc(offsetof<XChaCha20>())
    let ctx = changetype<XChaCha20>(ctxPtr)
    ctx.blockPtr = LocalArena.alloc(64)
    let bPtr = ctx.blockPtr

    // Derivación de clave HChaCha
    hchacha(
      load<u32>(kPtr, 0),
      load<u32>(kPtr, 4),
      load<u32>(kPtr, 8),
      load<u32>(kPtr, 12),
      load<u32>(kPtr, 16),
      load<u32>(kPtr, 20),
      load<u32>(kPtr, 24),
      load<u32>(kPtr, 28),
      load<u32>(nPtr, 0),
      load<u32>(nPtr, 4),
      load<u32>(nPtr, 8),
      load<u32>(nPtr, 12),
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

    // Nonce extendido
    ctx.n0 = 0
    ctx.n1 = load<u32>(nPtr, 16)
    ctx.n2 = load<u32>(nPtr, 20)
    ctx.counter = counter
    ctx.rounds = rounds
    memory.fill(bPtr, 0, 32)

    return ctx
  }

  encrypt(data: Uint8Array, output: Uint8Array): void {
    let len = <u32>data.length
    if (<u32>output.length < len) throw new Error("xchacha20: output buffer too small")
    if (len == 0) return

    let inPtr = data.dataStart
    let outPtr = output.dataStart
    let ctr = this.counter
    let pos: u32 = 0

    while (pos + 64 <= len) {
      chachaXorBlock(
        this.k0,
        this.k1,
        this.k2,
        this.k3,
        this.k4,
        this.k5,
        this.k6,
        this.k7,
        this.n0,
        this.n1,
        this.n2,
        ctr,
        inPtr + pos,
        outPtr + pos,
        this.rounds
      )
      ctr++
      pos += 64
    }
    if (pos < len) {
      let bPtr = this.blockPtr
      chachaKeystreamBlock(
        this.k0,
        this.k1,
        this.k2,
        this.k3,
        this.k4,
        this.k5,
        this.k6,
        this.k7,
        this.n0,
        this.n1,
        this.n2,
        ctr,
        bPtr,
        this.rounds
      )
      let take = len - pos
      for (let i: u32 = 0; i < take; i++) {
        store<u8>(outPtr + pos + i, load<u8>(inPtr + pos + i) ^ load<u8>(bPtr + i))
      }
      ctr++
      memory.fill(bPtr, 0, 64)
    }
    this.counter = ctr
  }

  decrypt(data: Uint8Array, output: Uint8Array): void {
    this.encrypt(data, output)
  }

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

// ==============================================================================
// 📦 HIGH LEVEL EXPORTS
// ==============================================================================

export function chacha20_encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  output: Uint8Array,
  counter: u32 = 0
): void {
  ChaCha20.encrypt(key, nonce, data, output, counter)
}
export function chacha20_decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  output: Uint8Array,
  counter: u32 = 0
): void {
  ChaCha20.encrypt(key, nonce, data, output, counter)
}
export function xchacha20_encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  output: Uint8Array,
  counter: u32 = 0
): void {
  XChaCha20.encrypt(key, nonce, data, output, counter)
}
export function xchacha20_decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  output: Uint8Array,
  counter: u32 = 0
): void {
  XChaCha20.encrypt(key, nonce, data, output, counter)
}
