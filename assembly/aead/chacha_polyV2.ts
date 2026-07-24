/**
 * ==============================================================================
 * 🔥 ChaCha20-Poly1305 AEAD V2 — 100% Zero-Alloc 🔥
 * ==============================================================================
 *
 * OPTIMIZACIONES:
 *
 * 1. 100% ZERO-ALLOC: Gracias a encryptPtr() de ChaCha20 V8 y la API de
 *    punteros de PolyV5, toda la operación AEAD se ejecuta sin crear un
 *    solo objeto Uint8Array intermedio. Cero presión sobre el GC.
 *
 * 2. MEMORIA ESTÁTICA (memory.data): Todos los buffers compartidos (authKey,
 *    lenBuf, tagBuf, zeroPad) residen en la sección .data del módulo WASM.
 *
 * 3. ARENA COMPARTIDA: Usa LocalArena como allocator unificado.
 *    Esto evita tener dos arenas de 64KB separadas (LocalArena + Memory.ts).
 *    El contexto de AEAD, ChaCha20 y los bloques temporales comparten la misma
 *    arena con ciclos de vida controlados por save/restore.
 *
 * 4. DEDUPLICACIÓN: polyAuth() y wipeSensitive() son funciones @inline
 *    compartidas por ChaCha20Poly1305 y XChaCha20Poly1305.
 *
 * 5. @final: Devirtualización de llamadas a métodos.
 * ==============================================================================
 */

import { ChaCha20, XChaCha20 } from "../chacha"
import { Poly1305 } from "../poly1305"
import { LocalArena } from "../utils/LocalArena"

// =============================================================================
// 📦 MEMORIA ESTÁTICA — Sección .data del módulo WASM
// =============================================================================

// 32 bytes para la clave de autenticación derivada
const AUTH_KEY_PTR: usize = memory.data(32)
// 16 bytes para el buffer de longitudes [aadLen_u64_LE | ctLen_u64_LE]
const LEN_BUF_PTR: usize = memory.data(16)
// 16 bytes para el tag computado
const TAG_BUF_PTR: usize = memory.data(16)
// 15 bytes de ceros para padding AEAD (inicializado a 0 por WASM)
const ZERO_PAD_PTR: usize = memory.data(15)

// =============================================================================
// 🔧 FUNCIONES INTERNAS (100% Zero-Alloc)
// =============================================================================

/**
 * Autenticación Poly1305 según RFC 8439 §2.8:
 *   tag = Poly1305(AAD || pad16(AAD) || CT || pad16(CT) || len64(AAD) || len64(CT))
 *
 * Prerequisito: AUTH_KEY_PTR debe contener la clave derivada (32 bytes).
 */
// @ts-ignore
@inline
function polyAuth(
  aadPtr: usize, aadLen: u32,
  ctPtr: usize, ctLen: u32
): void {
  let h = Poly1305.createFromPtr(AUTH_KEY_PTR)

  // 1. AAD + padding a múltiplo de 16
  if (aadLen > 0) {
    h.update(aadPtr, aadLen)
    let padA = (16 - (aadLen & 15)) & 15
    if (padA > 0) h.update(ZERO_PAD_PTR, padA)
  }

  // 2. Ciphertext + padding a múltiplo de 16
  if (ctLen > 0) {
    h.update(ctPtr, ctLen)
    let padC = (16 - (ctLen & 15)) & 15
    if (padC > 0) h.update(ZERO_PAD_PTR, padC)
  }

  // 3. Longitudes como u64 LE
  store<u64>(LEN_BUF_PTR, <u64>aadLen)
  store<u64>(LEN_BUF_PTR + 8, <u64>ctLen)
  h.update(LEN_BUF_PTR, 16)

  // 4. Finalizar — tag en TAG_BUF_PTR
  h.digest(TAG_BUF_PTR)
}

/**
 * Comparación en tiempo constante de 16 bytes.
 */
// @ts-ignore
@inline
function secureEqual16(ptrA: usize, ptrB: usize): bool {
  let v0 = load<u64>(ptrA) ^ load<u64>(ptrB)
  let v1 = load<u64>(ptrA, 8) ^ load<u64>(ptrB, 8)
  return (v0 | v1) == 0
}

/**
 * Limpieza de material criptográfico sensible.
 */
// @ts-ignore
@inline
function wipeSensitive(): void {
  memory.fill(AUTH_KEY_PTR, 0, 32)
  memory.fill(TAG_BUF_PTR, 0, 16)
}

// =============================================================================
// 🔐 ChaCha20-Poly1305 (Nonce de 12 bytes — RFC 8439)
// =============================================================================
@final
@unmanaged
export class ChaCha20Poly1305 {
  private keyPtr!: usize
  private noncePtr!: usize
  private aadPtr!: usize
  private aadLen!: u32

  /**
   * Cifrado AEAD: plaintext → output[0..pLen] || tag[pLen..pLen+16]
   *
   * 100% zero-alloc: encryptPtr() + PolyV5 punteros. Cero Uint8Array.
   */
  encrypt(plaintext: Uint8Array, output: Uint8Array): void {
    let pLen = <u32>plaintext.length
    if (<u32>output.length < pLen + 16) throw new Error("buffer de salida muy pequeño")

    let marker = LocalArena.save()

    // Derivar authKey: keystream de counter=0 sobre 32 ceros
    memory.fill(AUTH_KEY_PTR, 0, 32)
    let cipher0 = ChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 0)
    cipher0.encryptPtr(AUTH_KEY_PTR, AUTH_KEY_PTR, 32)

    // Cifrar plaintext con counter=1
    let cipher1 = ChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 1)
    cipher1.encryptPtr(plaintext.dataStart, output.dataStart, pLen)

    // Computar tag y concatenarlo al output
    polyAuth(this.aadPtr, this.aadLen, output.dataStart, pLen)
    memory.copy(output.dataStart + pLen, TAG_BUF_PTR, 16)

    LocalArena.restore(marker)
    wipeSensitive()
  }

  /**
   * Descifrado AEAD: verifica tag y descifra sólo si es válido.
   */
  decrypt(ciphertext: Uint8Array, output: Uint8Array): bool {
    let cLen = <u32>ciphertext.length
    if (cLen < 16) return false

    let pLen = cLen - 16
    if (<u32>output.length < pLen) throw new Error("buffer de salida muy pequeño")

    let marker = LocalArena.save()

    // Derivar authKey
    memory.fill(AUTH_KEY_PTR, 0, 32)
    let cipher0 = ChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 0)
    cipher0.encryptPtr(AUTH_KEY_PTR, AUTH_KEY_PTR, 32)

    // Computar y verificar tag
    polyAuth(this.aadPtr, this.aadLen, ciphertext.dataStart, pLen)
    let valid = secureEqual16(ciphertext.dataStart + pLen, TAG_BUF_PTR)

    if (!valid) {
      LocalArena.restore(marker)
      wipeSensitive()
      return false
    }

    // Descifrar con counter=1 — punteros directos, sin Uint8Array.wrap()
    let cipher1 = ChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 1)
    cipher1.encryptPtr(ciphertext.dataStart, output.dataStart, pLen)

    LocalArena.restore(marker)
    wipeSensitive()

    return true
  }

  static create(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null = null): ChaCha20Poly1305 {
    if (key.length != 32) throw new Error("clave debe ser 32 bytes")
    if (nonce.length != 12) throw new Error("nonce debe ser 12 bytes")

    let ctxPtr = LocalArena.alloc(offsetof<ChaCha20Poly1305>())
    let ctx = changetype<ChaCha20Poly1305>(ctxPtr)

    ctx.keyPtr = key.dataStart
    ctx.noncePtr = nonce.dataStart

    if (aad) {
      ctx.aadPtr = aad.dataStart
      ctx.aadLen = aad.length
    } else {
      ctx.aadPtr = 0
      ctx.aadLen = 0
    }
    return ctx
  }

  static encrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null, plaintext: Uint8Array, output: Uint8Array): void {
    let marker = LocalArena.save()
    let inst = ChaCha20Poly1305.create(key, nonce, aad)
    inst.encrypt(plaintext, output)
    LocalArena.restore(marker)
  }

  static decrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null, ciphertext: Uint8Array, output: Uint8Array): bool {
    let marker = LocalArena.save()
    let inst = ChaCha20Poly1305.create(key, nonce, aad)
    let result = inst.decrypt(ciphertext, output)
    LocalArena.restore(marker)
    return result
  }
}

// =============================================================================
// 🔐 XChaCha20-Poly1305 (Nonce extendido de 24 bytes)
// =============================================================================
@final
@unmanaged
export class XChaCha20Poly1305 {
  private keyPtr!: usize
  private noncePtr!: usize
  private aadPtr!: usize
  private aadLen!: u32

  encrypt(plaintext: Uint8Array, output: Uint8Array): void {
    let pLen = <u32>plaintext.length
    if (<u32>output.length < pLen + 16) throw new Error("buffer de salida muy pequeño")

    let marker = LocalArena.save()

    // Derivar authKey via XChaCha20
    memory.fill(AUTH_KEY_PTR, 0, 32)
    let cipher0 = XChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 0)
    cipher0.encryptPtr(AUTH_KEY_PTR, AUTH_KEY_PTR, 32)

    // Cifrar con counter=1
    let cipher1 = XChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 1)
    cipher1.encryptPtr(plaintext.dataStart, output.dataStart, pLen)

    // Computar tag y concatenar
    polyAuth(this.aadPtr, this.aadLen, output.dataStart, pLen)
    memory.copy(output.dataStart + pLen, TAG_BUF_PTR, 16)

    LocalArena.restore(marker)
    wipeSensitive()
  }

  decrypt(ciphertext: Uint8Array, output: Uint8Array): bool {
    let cLen = <u32>ciphertext.length
    if (cLen < 16) return false

    let pLen = cLen - 16
    if (<u32>output.length < pLen) throw new Error("buffer de salida muy pequeño")

    let marker = LocalArena.save()

    // Derivar authKey
    memory.fill(AUTH_KEY_PTR, 0, 32)
    let cipher0 = XChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 0)
    cipher0.encryptPtr(AUTH_KEY_PTR, AUTH_KEY_PTR, 32)

    // Computar y verificar tag
    polyAuth(this.aadPtr, this.aadLen, ciphertext.dataStart, pLen)
    let valid = secureEqual16(ciphertext.dataStart + pLen, TAG_BUF_PTR)

    if (!valid) {
      LocalArena.restore(marker)
      wipeSensitive()
      return false
    }

    // Descifrar — punteros directos
    let cipher1 = XChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 1)
    cipher1.encryptPtr(ciphertext.dataStart, output.dataStart, pLen)

    LocalArena.restore(marker)
    wipeSensitive()

    return true
  }

  static create(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null = null): XChaCha20Poly1305 {
    if (key.length != 32) throw new Error("clave debe ser 32 bytes")
    if (nonce.length != 24) throw new Error("nonce debe ser 24 bytes")

    let ctxPtr = LocalArena.alloc(offsetof<XChaCha20Poly1305>())
    let ctx = changetype<XChaCha20Poly1305>(ctxPtr)

    ctx.keyPtr = key.dataStart
    ctx.noncePtr = nonce.dataStart

    if (aad) {
      ctx.aadPtr = aad.dataStart
      ctx.aadLen = aad.length
    } else {
      ctx.aadPtr = 0
      ctx.aadLen = 0
    }
    return ctx
  }

  static encrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null, plaintext: Uint8Array, output: Uint8Array): void {
    let marker = LocalArena.save()
    let inst = XChaCha20Poly1305.create(key, nonce, aad)
    inst.encrypt(plaintext, output)
    LocalArena.restore(marker)
  }

  static decrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null, ciphertext: Uint8Array, output: Uint8Array): bool {
    let marker = LocalArena.save()
    let inst = XChaCha20Poly1305.create(key, nonce, aad)
    let result = inst.decrypt(ciphertext, output)
    LocalArena.restore(marker)
    return result
  }
}

// =============================================================================
// 🚀 WRAPPERS EXPORTADOS
// =============================================================================
export function chacha20poly1305_encrypt(
  key: Uint8Array, nonce: Uint8Array,
  aad: Uint8Array | null,
  plaintext: Uint8Array, output: Uint8Array
): void {
  ChaCha20Poly1305.encrypt(key, nonce, aad, plaintext, output)
}

export function chacha20poly1305_decrypt(
  key: Uint8Array, nonce: Uint8Array,
  aad: Uint8Array | null,
  ciphertext: Uint8Array, output: Uint8Array
): bool {
  return ChaCha20Poly1305.decrypt(key, nonce, aad, ciphertext, output)
}

export function xchacha20poly1305_encrypt(
  key: Uint8Array, nonce: Uint8Array,
  aad: Uint8Array | null,
  plaintext: Uint8Array, output: Uint8Array
): void {
  XChaCha20Poly1305.encrypt(key, nonce, aad, plaintext, output)
}

export function xchacha20poly1305_decrypt(
  key: Uint8Array, nonce: Uint8Array,
  aad: Uint8Array | null,
  ciphertext: Uint8Array, output: Uint8Array
): bool {
  return XChaCha20Poly1305.decrypt(key, nonce, aad, ciphertext, output)
}
