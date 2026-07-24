/**
 * ChaCha20-Poly1305 AEAD - Velocidad Extrema (--runtime minimal)
 */

import { ChaCha20, XChaCha20 } from "../chacha/chachaV1"
import { Poly1305 } from "../poly1305/PolyV1"
import { LocalArena as Memory } from "../utils/LocalArena"

const SHARED_AUTH_KEY = new Uint8Array(32)
const SHARED_LEN_BUF = new Uint8Array(16)
const SHARED_TAG_BUF = new Uint8Array(16)

const PAD_0 = new Uint8Array(0)
const PAD_1 = new Uint8Array(1)
const PAD_2 = new Uint8Array(2)
const PAD_3 = new Uint8Array(3)
const PAD_4 = new Uint8Array(4)
const PAD_5 = new Uint8Array(5)
const PAD_6 = new Uint8Array(6)
const PAD_7 = new Uint8Array(7)
const PAD_8 = new Uint8Array(8)
const PAD_9 = new Uint8Array(9)
const PAD_10 = new Uint8Array(10)
const PAD_11 = new Uint8Array(11)
const PAD_12 = new Uint8Array(12)
const PAD_13 = new Uint8Array(13)
const PAD_14 = new Uint8Array(14)
const PAD_15 = new Uint8Array(15)

// @ts-ignore
@inline
function getZeroPad(len: i32): Uint8Array {
  switch (len) {
    case 1:
      return PAD_1
    case 2:
      return PAD_2
    case 3:
      return PAD_3
    case 4:
      return PAD_4
    case 5:
      return PAD_5
    case 6:
      return PAD_6
    case 7:
      return PAD_7
    case 8:
      return PAD_8
    case 9:
      return PAD_9
    case 10:
      return PAD_10
    case 11:
      return PAD_11
    case 12:
      return PAD_12
    case 13:
      return PAD_13
    case 14:
      return PAD_14
    case 15:
      return PAD_15
    default:
      return PAD_0
  }
}

// @ts-ignore
@inline
function secureEqual16(ptrA: usize, ptrB: usize): bool {
  let v0 = load<u64>(ptrA) ^ load<u64>(ptrB)
  let v1 = load<u64>(ptrA, 8) ^ load<u64>(ptrB, 8)
  return (v0 | v1) == 0
}

@unmanaged
export class ChaCha20Poly1305 {
  private keyPtr!: usize
  private noncePtr!: usize
  private aadPtr!: usize
  private aadLen!: u32

  encrypt(plaintext: Uint8Array, output: Uint8Array): void {
    let pLen = <u32>plaintext.length
    if (<u32>output.length < pLen + 16) throw new Error("output buffer too small")
    
    let marker = Memory.save()

    memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
    let cipher0 = ChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 0)
    cipher0.encrypt(SHARED_AUTH_KEY, SHARED_AUTH_KEY)

    let cipher1 = ChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 1)
    cipher1.encrypt(plaintext, output) // writes to first pLen bytes

    let h = Poly1305.createFromPtr(SHARED_AUTH_KEY.dataStart)
    
    if (this.aadPtr != 0) {
      const aadView = Uint8Array.wrap(changetype<ArrayBuffer>(this.aadPtr), 0, this.aadLen)
      h.update(aadView)
      let padA = (16 - (this.aadLen & 15)) & 15
      if (padA > 0) h.update(getZeroPad(padA))
    }

    const cView = Uint8Array.wrap(output.buffer, output.byteOffset, pLen)
    h.update(cView)
    let padC = (16 - (pLen & 15)) & 15
    if (padC > 0) h.update(getZeroPad(padC))

    let lPtr = SHARED_LEN_BUF.dataStart
    store<u64>(lPtr, <u64>this.aadLen)
    store<u64>(lPtr + 8, <u64>pLen)
    h.update(SHARED_LEN_BUF)
    h.digest(SHARED_TAG_BUF)

    memory.copy(output.dataStart + pLen, SHARED_TAG_BUF.dataStart, 16)

    Memory.restore(marker)
    memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
    memory.fill(SHARED_TAG_BUF.dataStart, 0, 16)
  }

  decrypt(ciphertext: Uint8Array, output: Uint8Array): bool {
    let cLen = <u32>ciphertext.length
    if (cLen < 16) return false

    let pLen = cLen - 16
    if (<u32>output.length < pLen) throw new Error("output buffer too small")
    
    let marker = Memory.save()

    memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
    let cipher0 = ChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 0)
    cipher0.encrypt(SHARED_AUTH_KEY, SHARED_AUTH_KEY)

    let h = Poly1305.createFromPtr(SHARED_AUTH_KEY.dataStart)

    if (this.aadPtr != 0) {
      const aadView = Uint8Array.wrap(changetype<ArrayBuffer>(this.aadPtr), 0, this.aadLen)
      h.update(aadView)
      let padA = (16 - (this.aadLen & 15)) & 15
      if (padA > 0) h.update(getZeroPad(padA))
    }

    const cView = Uint8Array.wrap(ciphertext.buffer, ciphertext.byteOffset, pLen)
    h.update(cView)
    let padC = (16 - (pLen & 15)) & 15
    if (padC > 0) h.update(getZeroPad(padC))

    let lPtr = SHARED_LEN_BUF.dataStart
    store<u64>(lPtr, <u64>this.aadLen)
    store<u64>(lPtr + 8, <u64>pLen)
    h.update(SHARED_LEN_BUF)
    h.digest(SHARED_TAG_BUF)

    let passedTagPtr = ciphertext.dataStart + pLen
    let computedTagPtr = SHARED_TAG_BUF.dataStart
    let valid = secureEqual16(passedTagPtr, computedTagPtr)

    if (!valid) {
      Memory.restore(marker)
      memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
      memory.fill(SHARED_TAG_BUF.dataStart, 0, 16)
      return false
    }

    let cipher1 = ChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 1)
    cipher1.encrypt(cView, output)

    Memory.restore(marker)
    memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
    memory.fill(SHARED_TAG_BUF.dataStart, 0, 16)

    return true
  }

  static create(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null = null): ChaCha20Poly1305 {
    if (key.length != 32) throw new Error("key must be 32 bytes")
    if (nonce.length != 12) throw new Error("nonce must be 12 bytes")
    
    let ctxPtr = Memory.alloc(offsetof<ChaCha20Poly1305>())
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
    let marker = Memory.save()
    let inst = ChaCha20Poly1305.create(key, nonce, aad)
    inst.encrypt(plaintext, output)
    Memory.restore(marker)
  }

  static decrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null, ciphertext: Uint8Array, output: Uint8Array): bool {
    let marker = Memory.save()
    let inst = ChaCha20Poly1305.create(key, nonce, aad)
    let result = inst.decrypt(ciphertext, output)
    Memory.restore(marker)
    return result
  }
}

@unmanaged
export class XChaCha20Poly1305 {
  private keyPtr!: usize
  private noncePtr!: usize
  private aadPtr!: usize
  private aadLen!: u32

  encrypt(plaintext: Uint8Array, output: Uint8Array): void {
    let pLen = <u32>plaintext.length
    if (<u32>output.length < pLen + 16) throw new Error("output buffer too small")
    
    let marker = Memory.save()

    memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
    let cipher0 = XChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 0)
    cipher0.encrypt(SHARED_AUTH_KEY, SHARED_AUTH_KEY)

    let cipher1 = XChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 1)
    cipher1.encrypt(plaintext, output)

    let h = Poly1305.createFromPtr(SHARED_AUTH_KEY.dataStart)
    
    if (this.aadPtr != 0) {
      const aadView = Uint8Array.wrap(changetype<ArrayBuffer>(this.aadPtr), 0, this.aadLen)
      h.update(aadView)
      let padA = (16 - (this.aadLen & 15)) & 15
      if (padA > 0) h.update(getZeroPad(padA))
    }

    const cView = Uint8Array.wrap(output.buffer, output.byteOffset, pLen)
    h.update(cView)
    let padC = (16 - (pLen & 15)) & 15
    if (padC > 0) h.update(getZeroPad(padC))

    let lPtr = SHARED_LEN_BUF.dataStart
    store<u64>(lPtr, <u64>this.aadLen)
    store<u64>(lPtr + 8, <u64>pLen)
    h.update(SHARED_LEN_BUF)
    h.digest(SHARED_TAG_BUF)

    memory.copy(output.dataStart + pLen, SHARED_TAG_BUF.dataStart, 16)

    Memory.restore(marker)
    memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
    memory.fill(SHARED_TAG_BUF.dataStart, 0, 16)
  }

  decrypt(ciphertext: Uint8Array, output: Uint8Array): bool {
    let cLen = <u32>ciphertext.length
    if (cLen < 16) return false

    let pLen = cLen - 16
    if (<u32>output.length < pLen) throw new Error("output buffer too small")
    
    let marker = Memory.save()

    memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
    let cipher0 = XChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 0)
    cipher0.encrypt(SHARED_AUTH_KEY, SHARED_AUTH_KEY)

    let h = Poly1305.createFromPtr(SHARED_AUTH_KEY.dataStart)

    if (this.aadPtr != 0) {
      const aadView = Uint8Array.wrap(changetype<ArrayBuffer>(this.aadPtr), 0, this.aadLen)
      h.update(aadView)
      let padA = (16 - (this.aadLen & 15)) & 15
      if (padA > 0) h.update(getZeroPad(padA))
    }

    const cView = Uint8Array.wrap(ciphertext.buffer, ciphertext.byteOffset, pLen)
    h.update(cView)
    let padC = (16 - (pLen & 15)) & 15
    if (padC > 0) h.update(getZeroPad(padC))

    let lPtr = SHARED_LEN_BUF.dataStart
    store<u64>(lPtr, <u64>this.aadLen)
    store<u64>(lPtr + 8, <u64>pLen)
    h.update(SHARED_LEN_BUF)
    h.digest(SHARED_TAG_BUF)

    let passedTagPtr = ciphertext.dataStart + pLen
    let computedTagPtr = SHARED_TAG_BUF.dataStart
    let valid = secureEqual16(passedTagPtr, computedTagPtr)

    if (!valid) {
      Memory.restore(marker)
      memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
      memory.fill(SHARED_TAG_BUF.dataStart, 0, 16)
      return false
    }

    let cipher1 = XChaCha20.createFromPtr(this.keyPtr, this.noncePtr, 1)
    cipher1.encrypt(cView, output)

    Memory.restore(marker)
    memory.fill(SHARED_AUTH_KEY.dataStart, 0, 32)
    memory.fill(SHARED_TAG_BUF.dataStart, 0, 16)

    return true
  }

  static create(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null = null): XChaCha20Poly1305 {
    if (key.length != 32) throw new Error("key must be 32 bytes")
    if (nonce.length != 24) throw new Error("nonce must be 24 bytes")
    
    let ctxPtr = Memory.alloc(offsetof<XChaCha20Poly1305>())
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
    let marker = Memory.save()
    let inst = XChaCha20Poly1305.create(key, nonce, aad)
    inst.encrypt(plaintext, output)
    Memory.restore(marker)
  }

  static decrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array | null, ciphertext: Uint8Array, output: Uint8Array): bool {
    let marker = Memory.save()
    let inst = XChaCha20Poly1305.create(key, nonce, aad)
    let result = inst.decrypt(ciphertext, output)
    Memory.restore(marker)
    return result
  }
}

export function chacha20poly1305_encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array | null,
  plaintext: Uint8Array,
  output: Uint8Array
): void {
  ChaCha20Poly1305.encrypt(key, nonce, aad, plaintext, output)
}

export function chacha20poly1305_decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array | null,
  ciphertext: Uint8Array,
  output: Uint8Array
): bool {
  return ChaCha20Poly1305.decrypt(key, nonce, aad, ciphertext, output)
}

export function xchacha20poly1305_encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array | null,
  plaintext: Uint8Array,
  output: Uint8Array
): void {
  XChaCha20Poly1305.encrypt(key, nonce, aad, plaintext, output)
}

export function xchacha20poly1305_decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array | null,
  ciphertext: Uint8Array,
  output: Uint8Array
): bool {
  return XChaCha20Poly1305.decrypt(key, nonce, aad, ciphertext, output)
}

