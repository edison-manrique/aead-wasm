/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  aead.ts — ChaCha20-Poly1305 & XChaCha20-Poly1305 (AEAD, RFC 8439)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * AEAD = cifrado autenticado con datos asociados. Construido sobre ChaCha20
 * (cifrado) y Poly1305 (autenticación) según RFC 8439 §2.8:
 *   authKey = ChaCha20(key, nonce, counter=0)[0..32]
 *   tag     = Poly1305(authKey, AAD ‖ pad16(AAD) ‖ CT ‖ pad16(CT)
 *                       ‖ len64_LE(AAD) ‖ len64_LE(CT))
 *
 * 100% ZERO-ALLOC / SOLO PUNTEROS:
 *  • Sin Uint8Array ni `new` — el contexto streaming es un struct sobre puntero
 *    (changetype sobre la arena `Memory`).
 *  • Sin `throw` (runtime minimal). `final_decrypt` retorna `false` si el tag
 *    es inválido o la entrada es corta (nunca aborta).
 *  • Funciones exportadas en `snake_case` por convención.
 *
 * ── UN SOLO CONTEXTO PARA ChaCha20 Y XChaCha20 ────────────────────────────
 * ChaCha20 y XChaCha20 tienen un layout de campos IDÉNTICO, así que un único
 * struct `AeadStream` sirve para ambos mediante un flag `isX` y helpers de
 * despacho (`cipherCreate` / `cipherEncrypt` / `cipherFinishBlock`).
 *
 * ── CICLO DE VIDA DEL CIFRADOR (authKey → payload) ────────────────────────
 * El mismo cifrador deriva la authKey (32 B con counter 0) y cifra el payload
 * (counter 1+). Como el cifrador es INCREMENTAL (blockPos), tras la authKey hay
 * que "completar" el bloque 0 con `cipherFinishBlock` para que el payload
 * empiece en counter 1, blockPos 0 (equivale al `ctr++` del one-shot antiguo).
 *
 * ── LIMPIEZA DE MATERIAL SENSIBLE (centralizada en wipeAll) ───────────────
 * Toda la limpieza se hace en `wipeAll()`, llamado por final* y free:
 *   • tagBuf / lenBuf      → buffers de trabajo del tag y longitudes
 *   • cipher blockPtr      → keystream pendiente del bloque parcial
 *   • polyPtr (Poly1305)   → acumulador h, clave r, padding s y buffer parcial
 * Así final* y free son consistentes (antes free no limpiaba el cipher/poly).
 *
 * ── STREAMING (cifrado/auth de archivos grandes en tiempo real) ───────────
 * El contexto persiste entre chunks: el `counter` de ChaCha20 y el estado de
 * Poly1305 avanzan chunk a chunk sin acumular nada en memoria (memoria plana).
 *
 *   ENCRYPT: init_encrypt → update × N → final_encrypt(tagOut)
 *   DECRYPT: init_decrypt → update × N → final_decrypt(expectedTag) → bool
 *
 *   ⚠️ ADVERTENCIA (decrypt streaming): el plaintext se escribe en `update`
 *   ANTES de verificar el tag (que llega al final). El caller NO DEBE consumir
 *   el plaintext hasta que `final_decrypt` retorne `true`; si retorna `false`,
 *   debe descartarlo. Inherente al streaming de RFC 8439 (un solo tag final).
 *
 * ── GESTIÓN DE MEMORIA (arena bump con marco persistente) ─────────────────
 * `init_*` hace `Memory.save()` y NO restaura: el marco vive hasta `final_*`/
 * `free`, que hacen `Memory.restore(marker)` y liberan TODO de golpe. `update_*`
 * NO aloca nada. Uso correcto: SECUENCIAL (cerrar con final/free antes de iniciar
 * otro stream, o anidar en orden LIFO).
 */
import { ChaCha20, XChaCha20 } from "./chacha"
import { Poly1305 } from "./poly1305"
import { Memory } from "./memory"

// ═══════════════════════════════════════════════════════════════════════════
// 🔧 HELPERS LIBRES (zero-alloc, reentrantes)
// ═══════════════════════════════════════════════════════════════════════════

/** Despacho de creación del cifrador (ChaCha20 o XChaCha20), counter = 0. */
// @ts-ignore
@inline
function cipherCreate(kPtr: usize, nPtr: usize, isX: bool): usize {
  if (isX) return changetype<usize>(XChaCha20.createFromPtr(kPtr, nPtr, 0))
  return changetype<usize>(ChaCha20.createFromPtr(kPtr, nPtr, 0))
}

/** Despacho de cifrado/descifrado incremental sobre el contexto guardado. */
// @ts-ignore
@inline
function cipherEncrypt(cipherPtr: usize, inPtr: usize, outPtr: usize, len: u32, isX: bool): void {
  if (isX) changetype<XChaCha20>(cipherPtr).encryptPtr(inPtr, outPtr, len)
  else changetype<ChaCha20>(cipherPtr).encryptPtr(inPtr, outPtr, len)
}

/**
 * Completa el bloque parcial actual del cifrador (si lo hay): limpia el
 * keystream pendiente, resetea blockPos y avanza el counter al siguiente bloque.
 * Se usa tras derivar la authKey (32 B con counter 0) para que el payload
 * empiece en counter 1 — equivalente al `ctr++` que el one-shot hacía antes.
 */
// @ts-ignore
@inline
function cipherFinishBlock(cipherPtr: usize, isX: bool): void {
  if (isX) {
    const c = changetype<XChaCha20>(cipherPtr)
    if (c.blockPos > 0) {
      memory.fill(c.blockPtr, 0, 64) // limpiar keystream de la authKey (seguridad)
      c.blockPos = 0
      c.counter++
    }
  } else {
    const c = changetype<ChaCha20>(cipherPtr)
    if (c.blockPos > 0) {
      memory.fill(c.blockPtr, 0, 64)
      c.blockPos = 0
      c.counter++
    }
  }
}

/** Alimenta el AAD y su padding a 16 B al contexto Poly1305 (ya creado). */
// @ts-ignore
@inline
function polyFeedAad(polyPtr: usize, aadPtr: usize, aadLen: u32, zeroPadPtr: usize): void {
  if (aadLen == 0) return
  let h = changetype<Poly1305>(polyPtr)
  h.update(aadPtr, aadLen)
  let padA = (16 - (aadLen & 15)) & 15
  if (padA > 0) h.update(zeroPadPtr, padA)
}

/** Alimenta un chunk de ciphertext al contexto Poly1305. */
// @ts-ignore
@inline
function polyFeedCt(polyPtr: usize, ctPtr: usize, ctLen: u32): void {
  if (ctLen == 0) return
  changetype<Poly1305>(polyPtr).update(ctPtr, ctLen)
}

/**
 * Cierra la autenticación: padding del CT + bloque de longitudes + digest.
 * Escribe el tag de 16 B en tagBufPtr.
 */
// @ts-ignore
@inline
function polyFinal(
  polyPtr: usize,
  aadLen: u64, ctLen: u64,
  zeroPadPtr: usize, lenBufPtr: usize, tagBufPtr: usize
): void {
  let h = changetype<Poly1305>(polyPtr)
  let padC = <u32>((16 - (ctLen & 15)) & 15)
  if (padC > 0) h.update(zeroPadPtr, padC)
  store<u64>(lenBufPtr, aadLen) // len64_LE(AAD)
  store<u64>(lenBufPtr + 8, ctLen) // len64_LE(CT)
  h.update(lenBufPtr, 16)
  h.digest(tagBufPtr)
}

/** Comparación en tiempo constante de 16 bytes (sin early-exit). */
// @ts-ignore
@inline
function secureEqual16(ptrA: usize, ptrB: usize): bool {
  let v0 = load<u64>(ptrA) ^ load<u64>(ptrB)
  let v1 = load<u64>(ptrA, 8) ^ load<u64>(ptrB, 8)
  return (v0 | v1) == 0
}

/** Limpia los buffers de trabajo del tag y las longitudes (16 B c/u). */
// @ts-ignore
@inline
function wipe(tagBufPtr: usize, lenBufPtr: usize): void {
  memory.fill(tagBufPtr, 0, 16)
  memory.fill(lenBufPtr, 0, 16)
}

// ═══════════════════════════════════════════════════════════════════════════
// 🧩 CONTEXTO STREAMING (interno del módulo, NO se exporta al WASM)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Contexto AEAD incremental como struct sobre puntero (zero-alloc, sin `new`).
 * Un único struct para ChaCha20-Poly1305 y XChaCha20-Poly1305 (flag `isX`).
 *
 *  marker     → punto de `Memory.save()` de init; `final`/`free` restauran aquí.
 *  cipherPtr  → contexto ChaCha20/XChaCha20 (counter/blockPos persistentes).
 *  polyPtr    → contexto Poly1305 (estado persistente entre chunks).
 *  aadLen/ctLen → longitudes totales para el bloque final de longitudes.
 *  zeroPadPtr/lenBufPtr/tagBufPtr → buffers de trabajo reusados en `final`.
 *  mode       → 0 = encrypt, 1 = decrypt.
 *  isX        → false = ChaCha20, true = XChaCha20.
 *  finished   → sellado tras `final`/`free` (evita doble digest / doble free).
 */
@final
@unmanaged
class AeadStream {
  marker!: usize
  cipherPtr!: usize
  polyPtr!: usize
  aadLen!: u64
  ctLen!: u64
  zeroPadPtr!: usize
  lenBufPtr!: usize
  tagBufPtr!: usize
  mode!: u32
  isX!: bool
  finished!: bool

  /**
   * Limpia TODO el material sensible (centralizado): buffers de trabajo,
   * keystream pendiente del cifrador y estado del Poly1305 (clave r incluida).
   * Lo llaman final* y free para que la limpieza sea consistente.
   */
  private wipeAll(): void {
    wipe(this.tagBufPtr, this.lenBufPtr) // tag + longitudes
    changetype<ChaCha20>(this.cipherPtr).wipe() // keystream del bloque parcial (vale para XChaCha20: mismo layout)
    changetype<Poly1305>(this.polyPtr).wipe() // acumulador h, clave r, padding s, buffer parcial
  }

  /**
   * [STREAMING · INIT] Reserva el marco y deriva authKey + estado Poly1305.
   * Hace `Memory.save()` SIN restaurar (el marco vive hasta `final*`/`free`).
   * Reusa el cifrador para authKey (counter 0) y payload (counter 1+).
   */
  static initPtr(
    keyPtr: usize, noncePtr: usize,
    aadPtr: usize, aadLen: u32,
    isX: bool, mode: u32
  ): usize {
    const marker = Memory.save()

    const aeadPtr = Memory.alloc(offsetof<AeadStream>())
    const aead = changetype<AeadStream>(aeadPtr)
    aead.marker = marker
    aead.isX = isX
    aead.mode = mode
    aead.finished = false
    aead.aadLen = <u64>aadLen
    aead.ctLen = 0

    // Buffers de trabajo (reusados en final)
    const zeroPadPtr = Memory.alloc(16)
    memory.fill(zeroPadPtr, 0, 16)
    const lenBufPtr = Memory.alloc(16)
    const tagBufPtr = Memory.alloc(16)
    aead.zeroPadPtr = zeroPadPtr
    aead.lenBufPtr = lenBufPtr
    aead.tagBufPtr = tagBufPtr

    // Cifrador (counter 0) y derivación de authKey in-place (32 B del bloque 0)
    const cipherPtr = cipherCreate(keyPtr, noncePtr, isX)
    aead.cipherPtr = cipherPtr
    const authPtr = Memory.alloc(32)
    memory.fill(authPtr, 0, 32)
    cipherEncrypt(cipherPtr, authPtr, authPtr, 32, isX) // usa el bloque 0 (counter 0)
    cipherFinishBlock(cipherPtr, isX) // ← completa el bloque 0 → counter 1, blockPos 0 (payload empieza en bloque 1)

    // Poly1305 con authKey; luego wipe de authKey (ya internalizada en r/pad)
    const polyPtr = changetype<usize>(Poly1305.createFromPtr(authPtr))
    aead.polyPtr = polyPtr
    memory.fill(authPtr, 0, 32)

    // AAD + su padding (el CT se alimenta en update)
    polyFeedAad(polyPtr, aadPtr, aadLen, zeroPadPtr)

    return aeadPtr
  }

  /**
   * [STREAMING · UPDATE] Procesa un chunk. Cifra/descifra y autentica el CT.
   * NO aloca memoria (usa los contextos ya reservados en init).
   *   encrypt: cifra in→out, luego autentica out.
   *   decrypt: autentica in (CT), luego descifra in→out.
   */
  updatePtr(inPtr: usize, outPtr: usize, len: u32): void {
    if (this.finished || len == 0) return
    if (this.mode == 0) {
      cipherEncrypt(this.cipherPtr, inPtr, outPtr, len, this.isX)
      polyFeedCt(this.polyPtr, outPtr, len)
    } else {
      polyFeedCt(this.polyPtr, inPtr, len)
      cipherEncrypt(this.cipherPtr, inPtr, outPtr, len, this.isX)
    }
    this.ctLen += <u64>len
  }

  /** [STREAMING · FINAL encrypt] Calcula el tag y lo escribe en tagOutPtr (16 B). */
  finalEncryptPtr(tagOutPtr: usize): void {
    if (this.finished) return
    this.finished = true
    polyFinal(this.polyPtr, this.aadLen, this.ctLen, this.zeroPadPtr, this.lenBufPtr, this.tagBufPtr)
    memory.copy(tagOutPtr, this.tagBufPtr, 16) // copiar tag ANTES de limpiar
    this.wipeAll()
    Memory.restore(this.marker)
  }

  /**
   * [STREAMING · FINAL decrypt] Calcula el tag y lo compara (constant-time)
   * con expectedPtr. Retorna validez. NO libera plaintext: el caller decide.
   */
  finalDecryptPtr(expectedPtr: usize): bool {
    if (this.finished) return false
    this.finished = true
    polyFinal(this.polyPtr, this.aadLen, this.ctLen, this.zeroPadPtr, this.lenBufPtr, this.tagBufPtr)
    const valid = secureEqual16(this.tagBufPtr, expectedPtr) // comparar ANTES de limpiar
    this.wipeAll()
    Memory.restore(this.marker)
    return valid
  }

  /** [ABORT] Libera el stream sin finalizar (limpia material sensible). */
  static freePtr(ctxPtr: usize): void {
    const aead = changetype<AeadStream>(ctxPtr)
    if (aead.finished) return
    aead.finished = true
    aead.wipeAll() // consistente con final* (antes free no limpiaba cipher/poly)
    Memory.restore(aead.marker)
  }

  // ── ONE-SHOT (construidos sobre el path streaming) ──

  /** One-shot encrypt: out debe tener len + 16 bytes (CT ‖ tag). */
  static encryptOnePtr(
    keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32,
    inPtr: usize, outPtr: usize, len: u32, isX: bool
  ): void {
    const ctx = AeadStream.initPtr(keyPtr, noncePtr, aadPtr, aadLen, isX, 0)
    const aead = changetype<AeadStream>(ctx)
    aead.updatePtr(inPtr, outPtr, len)
    aead.finalEncryptPtr(outPtr + len) // tag concatenado tras el CT
  }

  /** One-shot decrypt: in tiene len bytes (CT ‖ tag). Retorna validez. */
  static decryptOnePtr(
    keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32,
    inPtr: usize, outPtr: usize, len: u32, isX: bool
  ): bool {
    if (len < 16) return false
    const ctx = AeadStream.initPtr(keyPtr, noncePtr, aadPtr, aadLen, isX, 1)
    const aead = changetype<AeadStream>(ctx)
    aead.updatePtr(inPtr, outPtr, len - 16) // autentica CT, descifra
    return aead.finalDecryptPtr(inPtr + len - 16) // verifica tag
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🚀 WRAPPERS EXPORTADOS — ONE-SHOT (snake_case, solo punteros)
// ═══════════════════════════════════════════════════════════════════════════

/** ChaCha20-Poly1305 one-shot encrypt. out = CT ‖ tag (len + 16 B). */
export function chacha20poly1305_encrypt_ptr(
  keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32,
  inPtr: usize, outPtr: usize, len: u32
): void {
  AeadStream.encryptOnePtr(keyPtr, noncePtr, aadPtr, aadLen, inPtr, outPtr, len, false)
}

/** ChaCha20-Poly1305 one-shot decrypt. in = CT ‖ tag (len B). Retorna validez. */
export function chacha20poly1305_decrypt_ptr(
  keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32,
  inPtr: usize, outPtr: usize, len: u32
): bool {
  return AeadStream.decryptOnePtr(keyPtr, noncePtr, aadPtr, aadLen, inPtr, outPtr, len, false)
}

/** XChaCha20-Poly1305 one-shot encrypt. out = CT ‖ tag (len + 16 B). */
export function xchacha20poly1305_encrypt_ptr(
  keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32,
  inPtr: usize, outPtr: usize, len: u32
): void {
  AeadStream.encryptOnePtr(keyPtr, noncePtr, aadPtr, aadLen, inPtr, outPtr, len, true)
}

/** XChaCha20-Poly1305 one-shot decrypt. in = CT ‖ tag (len B). Retorna validez. */
export function xchacha20poly1305_decrypt_ptr(
  keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32,
  inPtr: usize, outPtr: usize, len: u32
): bool {
  return AeadStream.decryptOnePtr(keyPtr, noncePtr, aadPtr, aadLen, inPtr, outPtr, len, true)
}

// ═══════════════════════════════════════════════════════════════════════════
// 🚀 WRAPPERS EXPORTADOS — STREAMING (snake_case, solo punteros)
// ═══════════════════════════════════════════════════════════════════════════
// init retorna el puntero al contexto (usize); el wrapper lo conserva y lo
// pasa a update/final. Cerrar SIEMPRE con final (o free para abortar).

// ── ChaCha20-Poly1305 streaming ──

export function chacha20poly1305_init_encrypt_ptr(
  keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32
): usize {
  return AeadStream.initPtr(keyPtr, noncePtr, aadPtr, aadLen, false, 0)
}

export function chacha20poly1305_init_decrypt_ptr(
  keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32
): usize {
  return AeadStream.initPtr(keyPtr, noncePtr, aadPtr, aadLen, false, 1)
}

export function chacha20poly1305_update_ptr(
  ctxPtr: usize, inPtr: usize, outPtr: usize, len: u32
): void {
  changetype<AeadStream>(ctxPtr).updatePtr(inPtr, outPtr, len)
}

export function chacha20poly1305_final_encrypt_ptr(ctxPtr: usize, tagOutPtr: usize): void {
  changetype<AeadStream>(ctxPtr).finalEncryptPtr(tagOutPtr)
}

export function chacha20poly1305_final_decrypt_ptr(ctxPtr: usize, expectedTagPtr: usize): bool {
  return changetype<AeadStream>(ctxPtr).finalDecryptPtr(expectedTagPtr)
}

// ── XChaCha20-Poly1305 streaming ──

export function xchacha20poly1305_init_encrypt_ptr(
  keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32
): usize {
  return AeadStream.initPtr(keyPtr, noncePtr, aadPtr, aadLen, true, 0)
}

export function xchacha20poly1305_init_decrypt_ptr(
  keyPtr: usize, noncePtr: usize, aadPtr: usize, aadLen: u32
): usize {
  return AeadStream.initPtr(keyPtr, noncePtr, aadPtr, aadLen, true, 1)
}

export function xchacha20poly1305_update_ptr(
  ctxPtr: usize, inPtr: usize, outPtr: usize, len: u32
): void {
  changetype<AeadStream>(ctxPtr).updatePtr(inPtr, outPtr, len)
}

export function xchacha20poly1305_final_encrypt_ptr(ctxPtr: usize, tagOutPtr: usize): void {
  changetype<AeadStream>(ctxPtr).finalEncryptPtr(tagOutPtr)
}

export function xchacha20poly1305_final_decrypt_ptr(ctxPtr: usize, expectedTagPtr: usize): bool {
  return changetype<AeadStream>(ctxPtr).finalDecryptPtr(expectedTagPtr)
}

/** Libera un stream sin finalizar (abort). Limpia material sensible. */
export function aead_free_ptr(ctxPtr: usize): void {
  AeadStream.freePtr(ctxPtr)
}