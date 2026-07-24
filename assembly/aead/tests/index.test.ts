// bun builder.ts aead -fm 76 -t (4,864 kb)

import { hexToBytes, bytesToHex, freeObject } from "../../lib"
import { ChaCha20Poly1305, XChaCha20Poly1305 } from "../chacha_polyV2"
import { LocalArena } from "../../lib/LocalArena"
import { stablelib_chacha20poly1305_vectors } from "./stablelib_chacha20poly1305"
import { stablelib_xchacha20poly1305_vectors } from "./stablelib_xchacha20poly1305"

export function test_chacha20poly1305_vectors(): bool {
  for (let i = 0; i < stablelib_chacha20poly1305_vectors.length; i++) {
    const v = stablelib_chacha20poly1305_vectors[i]
    let key = hexToBytes(v.key)
    let nonce = hexToBytes(v.nonce)
    let aad: Uint8Array | null = v.aad.length > 0 ? hexToBytes(v.aad) : null
    let plaintext = hexToBytes(v.msg)
    let expected = v.result

    let marker = LocalArena.save()
    let cipher = ChaCha20Poly1305.create(key, nonce, aad)
    let output = new Uint8Array(plaintext.length + 16)
    cipher.encrypt(plaintext, output)
    LocalArena.restore(marker)

    if (bytesToHex(output) != expected) {
      trace("FAIL CHACHA20POLY1305 AT INDEX", 1, i)
      return false
    }

    marker = LocalArena.save()
    let cipher2 = ChaCha20Poly1305.create(key, nonce, aad)
    let decrypted = new Uint8Array(output.length - 16)
    let ok = cipher2.decrypt(output, decrypted)
    LocalArena.restore(marker)

    if (!ok || bytesToHex(decrypted) != bytesToHex(plaintext)) {
      trace("DECRYPT FAIL CHACHA20POLY1305 AT INDEX", 1, i)
      return false
    }

    freeObject(output)
    freeObject(decrypted)
  }
  return true
}

export function test_xchacha20poly1305_vectors(): bool {
  for (let i = 0; i < stablelib_xchacha20poly1305_vectors.length; i++) {
    const v = stablelib_xchacha20poly1305_vectors[i]
    let key = hexToBytes(v.key)
    let nonce = hexToBytes(v.nonce)
    let aad: Uint8Array | null = v.aad.length > 0 ? hexToBytes(v.aad) : null
    let plaintext = hexToBytes(v.msg)
    let expected = v.result

    let marker = LocalArena.save()
    let cipher = XChaCha20Poly1305.create(key, nonce, aad)
    let output = new Uint8Array(plaintext.length + 16)
    cipher.encrypt(plaintext, output)
    LocalArena.restore(marker)

    if (bytesToHex(output) != expected) {
      trace("FAIL XCHACHA20POLY1305 AT INDEX", 1, i)
      return false
    }

    marker = LocalArena.save()
    let cipher2 = XChaCha20Poly1305.create(key, nonce, aad)
    let decrypted = new Uint8Array(output.length - 16)
    let ok = cipher2.decrypt(output, decrypted)
    LocalArena.restore(marker)

    if (!ok || bytesToHex(decrypted) != bytesToHex(plaintext)) {
      trace("DECRYPT FAIL XCHACHA20POLY1305 AT INDEX", 1, i)
      return false
    }

    freeObject(output)
    freeObject(decrypted)
  }
  return true
}

export function test_aead_memory_leaks(): bool {
  const key = new Uint8Array(32)
  const nonce = new Uint8Array(12)
  const xnonce = new Uint8Array(24)
  const aad = new Uint8Array(16)
  const plaintext = new Uint8Array(1024)

  for (let i = 0; i < 1000; i++) {
    let marker = LocalArena.save()

    // --- ChaCha20Poly1305 ---
    let cipher = ChaCha20Poly1305.create(key, nonce, aad)
    let output = new Uint8Array(plaintext.length + 16)
    cipher.encrypt(plaintext, output)

    let decrypted = new Uint8Array(output.length - 16)
    cipher.decrypt(output, decrypted)

    // Limpieza manual (Requerida por --runtime stub)
    freeObject(output)
    freeObject(decrypted)

    // --- XChaCha20Poly1305 ---
    let xcipher = XChaCha20Poly1305.create(key, xnonce, aad)
    let xoutput = new Uint8Array(plaintext.length + 16)
    xcipher.encrypt(plaintext, xoutput)

    let xdecrypted = new Uint8Array(xoutput.length - 16)
    xcipher.decrypt(xoutput, xdecrypted)

    // Limpieza manual
    freeObject(xoutput)
    freeObject(xdecrypted)

    LocalArena.restore(marker)
  }
  return true
}
