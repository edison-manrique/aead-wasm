/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  aead.ts — ChaCha20-Poly1305 & XChaCha20-Poly1305 (cifrado autenticado)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Módulo principal del paquete. Cifrado autenticado con datos asociados (AEAD)
 * según RFC 8439, con dos modos:
 *
 *  • ONE-SHOT  — mensaje completo en memoria:
 *      encrypt / decrypt            → formato combined (ciphertext ‖ tag)
 *      encryptDetached / decryptDetached → ciphertext y tag por separado
 *
 *  • STREAMING — archivos / flujos grandes, por chunks de 1 MB (memoria plana):
 *      createEncryptStream / createDecryptStream → update(chunk) / final()
 *
 * IMPLEMENTACIÓN SIN DUPLICACIÓN: ChaCha20-Poly1305 y XChaCha20-Poly1305
 * comparten toda la lógica mediante operaciones parametrizadas por `variant`
 * ("chacha" | "xchacha"); cada clase es una fachada delgada que fija su
 * variante. Así hay UNA sola implementación de one-shot y de streams.
 *
 * 🔒 REGLA DE SEGURIDAD DEL DECRYPT STREAMING (heredada de RFC 8439):
 * En un AEAD de tag único, el plaintext se produce en `update` ANTES de que
 * llegue el tag (que va al final). Por tanto el plaintext de `update` NO es
 * confiable hasta que `final(tag)` retorne `true`. Si retorna `false`, el
 * caller DEBE descartar todo el plaintext emitido (igual que libsodium
 * crypto_secretstream). Se documenta en `createDecryptStream` con un ejemplo.
 */
import { AeadWasm } from "./aead-wasm"
import {
  AeadVariant,
  AeadEncryptStream,
  AeadDecryptStream,
  Detached,
  KEY_BYTES,
  NONCE_BYTES,
  XNONCE_BYTES,
  TAG_BYTES,
  toUint8Array,
  concatBytes
} from "./types"

// ── Validaciones ────────────────────────────────────────────────────────────
function assertKey(key: Uint8Array): void {
  if (key.length !== KEY_BYTES) {
    throw new Error(`AEAD: la clave debe ser ${KEY_BYTES} bytes (recibidos ${key.length}).`)
  }
}
function assertNonce(nonce: Uint8Array, variant: AeadVariant): void {
  const expected = variant === "chacha" ? NONCE_BYTES : XNONCE_BYTES
  if (nonce.length !== expected) {
    throw new Error(`AEAD: el nonce debe ser ${expected} bytes para ${variant} (recibidos ${nonce.length}).`)
  }
}
function assertTag(tag: Uint8Array): void {
  if (tag.length !== TAG_BYTES) {
    throw new Error(`AEAD: el tag debe ser ${TAG_BYTES} bytes (recibidos ${tag.length}).`)
  }
}

// ── One-shot parametrizado por variante ─────────────────────────────────────

function encryptCombined(
  wasm: AeadWasm, variant: AeadVariant,
  key: Uint8Array, nonce: Uint8Array,
  plaintext: Uint8Array | string, aad?: Uint8Array | string | null
): Uint8Array {
  assertKey(key)
  assertNonce(nonce, variant)
  const pt = toUint8Array(plaintext)
  const a = aad == null ? null : toUint8Array(aad)
  return wasm.aeadEncrypt(variant, key, nonce, pt, a)
}

function encryptDetached(
  wasm: AeadWasm, variant: AeadVariant,
  key: Uint8Array, nonce: Uint8Array,
  plaintext: Uint8Array | string, aad?: Uint8Array | string | null
): Detached {
  const combined = encryptCombined(wasm, variant, key, nonce, plaintext, aad)
  const ctLen = combined.length - TAG_BYTES
  // Copias independientes: el caller puede mutar ciphertext y tag por separado.
  return { ciphertext: combined.slice(0, ctLen), tag: combined.slice(ctLen) }
}

function decryptCombined(
  wasm: AeadWasm, variant: AeadVariant,
  key: Uint8Array, nonce: Uint8Array,
  combined: Uint8Array, aad?: Uint8Array | string | null
): Uint8Array | null {
  assertKey(key)
  assertNonce(nonce, variant)
  const a = aad == null ? null : toUint8Array(aad)
  return wasm.aeadDecrypt(variant, key, nonce, combined, a)
}

function decryptDetached(
  wasm: AeadWasm, variant: AeadVariant,
  key: Uint8Array, nonce: Uint8Array,
  ciphertext: Uint8Array, tag: Uint8Array, aad?: Uint8Array | string | null
): Uint8Array | null {
  assertKey(key)
  assertNonce(nonce, variant)
  assertTag(tag)
  const combined = concatBytes(ciphertext, tag)
  const a = aad == null ? null : toUint8Array(aad)
  return wasm.aeadDecrypt(variant, key, nonce, combined, a)
}

// ── Fábricas de streams parametrizadas por variante ─────────────────────────

function makeEncryptStream(
  wasm: AeadWasm, variant: AeadVariant,
  key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | string | null
): AeadEncryptStream {
  assertKey(key)
  assertNonce(nonce, variant)
  const a = aad == null ? null : toUint8Array(aad)
  let ctx = wasm.aeadInitEncrypt(variant, key, nonce, a)
  let done = false

  return {
    update(chunk: Uint8Array): Uint8Array {
      if (done) throw new Error("AeadEncryptStream: stream ya finalizado o liberado.")
      return wasm.aeadUpdate(ctx, chunk)
    },
    final(): Uint8Array {
      if (done) throw new Error("AeadEncryptStream: final() llamado dos veces.")
      done = true
      const tag = wasm.aeadFinalEncrypt(ctx)
      ctx = 0
      return tag
    },
    free(): void {
      if (done) return
      done = true
      wasm.aeadFree(ctx)
      ctx = 0
    }
  }
}

function makeDecryptStream(
  wasm: AeadWasm, variant: AeadVariant,
  key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | string | null
): AeadDecryptStream {
  assertKey(key)
  assertNonce(nonce, variant)
  const a = aad == null ? null : toUint8Array(aad)
  let ctx = wasm.aeadInitDecrypt(variant, key, nonce, a)
  let done = false

  return {
    update(chunk: Uint8Array): Uint8Array {
      if (done) throw new Error("AeadDecryptStream: stream ya finalizado o liberado.")
      // ⚠️ plaintext NO confiable hasta que final(tag) retorne true.
      return wasm.aeadUpdate(ctx, chunk)
    },
    final(tag: Uint8Array): boolean {
      if (done) throw new Error("AeadDecryptStream: final() llamado dos veces.")
      done = true
      assertTag(tag)
      const valid = wasm.aeadFinalDecrypt(ctx, tag)
      ctx = 0
      return valid
    },
    free(): void {
      if (done) return
      done = true
      wasm.aeadFree(ctx)
      ctx = 0
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 ChaCha20-Poly1305 (nonce de 12 bytes — RFC 8439)
// ═══════════════════════════════════════════════════════════════════════════

export class ChaCha20Poly1305 {
  private readonly key: Uint8Array

  /**
   * Crea una instancia con clave fija (el nonce se pasa por llamada).
   * La clave se copia para garantizar inmutabilidad.
   */
  constructor(key: Uint8Array) {
    assertKey(key)
    this.key = new Uint8Array(key)
  }

  // ── Estáticos (one-shot) ──

  /** Cifra + autentica → `ciphertext ‖ tag` (combined). */
  static encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array | string, aad?: Uint8Array | string | null): Uint8Array {
    return encryptCombined(AeadWasm.getInstance(), "chacha", key, nonce, plaintext, aad)
  }

  /** Cifra + autentica → `{ ciphertext, tag }` (detached). */
  static encryptDetached(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array | string, aad?: Uint8Array | string | null): Detached {
    return encryptDetached(AeadWasm.getInstance(), "chacha", key, nonce, plaintext, aad)
  }

  /** Verifica + descifra `ciphertext ‖ tag` → plaintext, o `null` si el tag es inválido. */
  static decrypt(key: Uint8Array, nonce: Uint8Array, combined: Uint8Array, aad?: Uint8Array | string | null): Uint8Array | null {
    return decryptCombined(AeadWasm.getInstance(), "chacha", key, nonce, combined, aad)
  }

  /** Verifica + descifra (detached) → plaintext, o `null` si el tag es inválido. */
  static decryptDetached(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad?: Uint8Array | string | null): Uint8Array | null {
    return decryptDetached(AeadWasm.getInstance(), "chacha", key, nonce, ciphertext, tag, aad)
  }

  /** Stream de cifrado por chunks (memoria plana). `final()` devuelve el tag. */
  static createEncryptStream(key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | string | null): AeadEncryptStream {
    return makeEncryptStream(AeadWasm.getInstance(), "chacha", key, nonce, aad)
  }

  /**
   * Stream de descifrado por chunks. `final(tag)` verifica y devuelve validez.
   *
   * ⚠️ El plaintext de `update()` NO es confiable hasta que `final(tag) === true`.
   * Si `final` retorna `false`, descarta todo el plaintext emitido.
   *
   * @example
   * ```ts
   * const stream = ChaCha20Poly1305.createDecryptStream(key, nonce, aad)
   * const out: Uint8Array[] = []
   * try {
   *   for (const chunk of chunks) out.push(stream.update(chunk))
   *   if (!stream.final(tag)) throw new Error("tag inválido: descartar plaintext")
   *   // aquí `out` es confiable
   * } catch (e) { stream.free(); throw e }
   * ```
   */
  static createDecryptStream(key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | string | null): AeadDecryptStream {
    return makeDecryptStream(AeadWasm.getInstance(), "chacha", key, nonce, aad)
  }

  // ── Instancia (clave fija) ──

  encrypt(nonce: Uint8Array, plaintext: Uint8Array | string, aad?: Uint8Array | string | null): Uint8Array {
    return ChaCha20Poly1305.encrypt(this.key, nonce, plaintext, aad)
  }
  encryptDetached(nonce: Uint8Array, plaintext: Uint8Array | string, aad?: Uint8Array | string | null): Detached {
    return ChaCha20Poly1305.encryptDetached(this.key, nonce, plaintext, aad)
  }
  decrypt(nonce: Uint8Array, combined: Uint8Array, aad?: Uint8Array | string | null): Uint8Array | null {
    return ChaCha20Poly1305.decrypt(this.key, nonce, combined, aad)
  }
  decryptDetached(nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad?: Uint8Array | string | null): Uint8Array | null {
    return ChaCha20Poly1305.decryptDetached(this.key, nonce, ciphertext, tag, aad)
  }
  createEncryptStream(nonce: Uint8Array, aad?: Uint8Array | string | null): AeadEncryptStream {
    return ChaCha20Poly1305.createEncryptStream(this.key, nonce, aad)
  }
  createDecryptStream(nonce: Uint8Array, aad?: Uint8Array | string | null): AeadDecryptStream {
    return ChaCha20Poly1305.createDecryptStream(this.key, nonce, aad)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 XChaCha20-Poly1305 (nonce extendido de 24 bytes)
// ═══════════════════════════════════════════════════════════════════════════

export class XChaCha20Poly1305 {
  private readonly key: Uint8Array

  constructor(key: Uint8Array) {
    assertKey(key)
    this.key = new Uint8Array(key)
  }

  static encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array | string, aad?: Uint8Array | string | null): Uint8Array {
    return encryptCombined(AeadWasm.getInstance(), "xchacha", key, nonce, plaintext, aad)
  }
  static encryptDetached(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array | string, aad?: Uint8Array | string | null): Detached {
    return encryptDetached(AeadWasm.getInstance(), "xchacha", key, nonce, plaintext, aad)
  }
  static decrypt(key: Uint8Array, nonce: Uint8Array, combined: Uint8Array, aad?: Uint8Array | string | null): Uint8Array | null {
    return decryptCombined(AeadWasm.getInstance(), "xchacha", key, nonce, combined, aad)
  }
  static decryptDetached(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad?: Uint8Array | string | null): Uint8Array | null {
    return decryptDetached(AeadWasm.getInstance(), "xchacha", key, nonce, ciphertext, tag, aad)
  }
  static createEncryptStream(key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | string | null): AeadEncryptStream {
    return makeEncryptStream(AeadWasm.getInstance(), "xchacha", key, nonce, aad)
  }
  static createDecryptStream(key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | string | null): AeadDecryptStream {
    return makeDecryptStream(AeadWasm.getInstance(), "xchacha", key, nonce, aad)
  }

  encrypt(nonce: Uint8Array, plaintext: Uint8Array | string, aad?: Uint8Array | string | null): Uint8Array {
    return XChaCha20Poly1305.encrypt(this.key, nonce, plaintext, aad)
  }
  encryptDetached(nonce: Uint8Array, plaintext: Uint8Array | string, aad?: Uint8Array | string | null): Detached {
    return XChaCha20Poly1305.encryptDetached(this.key, nonce, plaintext, aad)
  }
  decrypt(nonce: Uint8Array, combined: Uint8Array, aad?: Uint8Array | string | null): Uint8Array | null {
    return XChaCha20Poly1305.decrypt(this.key, nonce, combined, aad)
  }
  decryptDetached(nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad?: Uint8Array | string | null): Uint8Array | null {
    return XChaCha20Poly1305.decryptDetached(this.key, nonce, ciphertext, tag, aad)
  }
  createEncryptStream(nonce: Uint8Array, aad?: Uint8Array | string | null): AeadEncryptStream {
    return XChaCha20Poly1305.createEncryptStream(this.key, nonce, aad)
  }
  createDecryptStream(nonce: Uint8Array, aad?: Uint8Array | string | null): AeadDecryptStream {
    return XChaCha20Poly1305.createDecryptStream(this.key, nonce, aad)
  }
}