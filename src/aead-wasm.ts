/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  aead-wasm.ts — Cargador del WASM + API de bajo nivel
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Clase central (singleton) que:
 *  1. Carga/instancia el módulo WASM (load / fromUrl / fromBuffer).
 *  2. Lee las regiones de I/O plano (PARAM_IN/OUT, 1 MB c/u) y crea el
 *     WasmAllocator.
 *  3. Expone la API de bajo nivel: todas las operaciones toman/devuelven
 *     Uint8Array; el allocator hace la copia a/desde la memoria lineal.
 *
 * Estrategia de I/O:
 *  • one-shot directo cuando key+nonce+aad+datos caben en PARAM_IN (~1 MB);
 *  • streaming transparente por chunks de 1 MB cuando no caben (el AEAD
 *    internaliza key/nonce/aad en `init`, así cada chunk reusa PARAM_IN[0]).
 *
 * NOTA: las primitivas de streaming `update/final/free` llaman a las funciones
 * `chacha20poly1305_*` porque el contexto (struct `AeadStream`) ya conoce su
 * variante vía el flag interno `isX`; las variantes `_ptr` de update/final son
 * idénticas para ChaCha20 y XChaCha20.
 */
import {
  AsmExports,
  AeadVariant,
  KEY_BYTES,
  NONCE_BYTES,
  XNONCE_BYTES,
  TAG_BYTES,
  getGlobalValue,
  concatBytes
} from "./types"
import { WasmAllocator } from "./allocator"

export class AeadWasm {
  private exp: AsmExports
  private allocator: WasmAllocator
  private static instance: AeadWasm | null = null

  private constructor(exp: AsmExports) {
    this.exp = exp
    const inPtr = getGlobalValue(exp.PARAM_IN_PTR, 0)
    const inSize = getGlobalValue(exp.PARAM_IN_SIZE, 1 << 20)
    const outPtr = getGlobalValue(exp.PARAM_OUT_PTR, 0)
    const outSize = getGlobalValue(exp.PARAM_OUT_SIZE, (1 << 20) + 64)
    this.allocator = new WasmAllocator(exp.memory, inPtr, inSize, outPtr, outSize)
  }

  /** Singleton global. Lanza si aún no se ha cargado el WASM. */
  static getInstance(): AeadWasm {
    if (!AeadWasm.instance) {
      throw new Error("AeadWasm no inicializado. Usa await AeadWasm.load() / fromBuffer() / fromUrl() primero.")
    }
    return AeadWasm.instance
  }

  getAllocator(): WasmAllocator {
    return this.allocator
  }

  getExports(): AsmExports {
    return this.exp
  }

  // ── Carga del módulo ──────────────────────────────────────────────────────

  static getDefaultWasmUrl(): string {
    const baseUrl = "./aead.wasm"
    try {
      return new URL(baseUrl, import.meta.url).href
    } catch {
      return baseUrl
    }
  }

  private static buildImports(imports: WebAssembly.Imports): WebAssembly.Imports {
    const defaultImports = {
      env: {
        abort() {
          console.error("WASM Abort")
        },
        seed() {
          return Math.random()
        }
      }
    }
    return {
      ...defaultImports,
      ...imports,
      env: { ...defaultImports.env, ...((imports.env as Record<string, unknown>) || {}) }
    }
  }

  static async load(url?: string, imports: WebAssembly.Imports = {}): Promise<AeadWasm> {
    if (AeadWasm.instance) return AeadWasm.instance
    return AeadWasm.fromUrl(url || AeadWasm.getDefaultWasmUrl(), imports)
  }

  static async fromUrl(url: string, imports: WebAssembly.Imports = {}): Promise<AeadWasm> {
    const finalImports = AeadWasm.buildImports(imports)
    let instance: WebAssembly.Instance
    if (typeof WebAssembly.instantiateStreaming === "function") {
      instance = (await WebAssembly.instantiateStreaming(await fetch(url), finalImports)).instance
    } else {
      const buffer = await (await fetch(url)).arrayBuffer()
      instance = (await WebAssembly.instantiate(buffer, finalImports)).instance
    }
    AeadWasm.instance = new AeadWasm(instance.exports as unknown as AsmExports)
    return AeadWasm.instance
  }

  static async fromBuffer(buffer: ArrayBuffer | Uint8Array, imports: WebAssembly.Imports = {}): Promise<AeadWasm> {
    const finalImports = AeadWasm.buildImports(imports)
    // Normaliza a ArrayBuffer exacto: respeta byteOffset/byteLength de vistas y
    // fuerza la sobrecarga instantiate(BufferSource) → { instance } (TS2339).
    const buf = (
      buffer instanceof Uint8Array
        ? buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
        : buffer
    ) as ArrayBuffer
    const { instance } = await WebAssembly.instantiate(buf, finalImports)
    AeadWasm.instance = new AeadWasm(instance.exports as unknown as AsmExports)
    return AeadWasm.instance
  }

  // ── Helpers privados de layout en PARAM_IN ────────────────────────────────

  /** Escribe key‖nonce‖aad al inicio de PARAM_IN y devuelve sus punteros. */
  private layoutHeader(key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null) {
    let offset = 0
    const keyPtr = this.allocator.writeInput(key, offset)
    offset += KEY_BYTES
    const noncePtr = this.allocator.writeInput(nonce, offset)
    offset += nonce.length
    let aadPtr = 0
    let aadLen = 0
    if (aad && aad.length > 0) {
      aadPtr = this.allocator.writeInput(aad, offset)
      aadLen = aad.length
      offset += aadLen
    }
    return { keyPtr, noncePtr, aadPtr, aadLen, headerSize: offset }
  }

  private nonceLen(variant: AeadVariant): number {
    return variant === "chacha" ? NONCE_BYTES : XNONCE_BYTES
  }

  // ── ChaCha20 / XChaCha20 (one-shot) ───────────────────────────────────────

  /** ChaCha20 one-shot (nonce 12 B). Datos hasta ~1 MB; más allá usa AEAD streaming. */
  chacha20(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, counter: number = 0): Uint8Array {
    const capacity = this.allocator.inSize - KEY_BYTES - NONCE_BYTES
    if (data.length > capacity) throw new Error("ChaCha20: datos > 1 MB; usa AEAD streaming o cifra por bloques.")
    const keyPtr = this.allocator.writeInput(key, 0)
    const noncePtr = this.allocator.writeInput(nonce, KEY_BYTES)
    const inPtr = this.allocator.writeInput(data, KEY_BYTES + NONCE_BYTES)
    this.exp.chacha20_encrypt_ptr(keyPtr, noncePtr, inPtr, this.allocator.outPtr, data.length, counter)
    return this.allocator.readOutput(data.length)
  }

  /** XChaCha20 one-shot (nonce 24 B). */
  xchacha20(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, counter: number = 0): Uint8Array {
    const capacity = this.allocator.inSize - KEY_BYTES - XNONCE_BYTES
    if (data.length > capacity) throw new Error("XChaCha20: datos > 1 MB; usa AEAD streaming o cifra por bloques.")
    const keyPtr = this.allocator.writeInput(key, 0)
    const noncePtr = this.allocator.writeInput(nonce, KEY_BYTES)
    const inPtr = this.allocator.writeInput(data, KEY_BYTES + XNONCE_BYTES)
    this.exp.xchacha20_encrypt_ptr(keyPtr, noncePtr, inPtr, this.allocator.outPtr, data.length, counter)
    return this.allocator.readOutput(data.length)
  }

  // ── Poly1305 (MAC one-shot) ───────────────────────────────────────────────

  /** Poly1305 MAC (tag 16 B). Mensaje hasta ~1 MB; más allá usa AEAD streaming. */
  poly1305Mac(key: Uint8Array, msg: Uint8Array): Uint8Array {
    const capacity = this.allocator.inSize - KEY_BYTES
    if (msg.length > capacity) throw new Error("Poly1305: mensaje > 1 MB; usa AEAD streaming.")
    const keyPtr = this.allocator.writeInput(key, 0)
    const msgPtr = this.allocator.writeInput(msg, KEY_BYTES)
    this.exp.poly1305_mac_ptr(msgPtr, msg.length, keyPtr, this.allocator.outPtr)
    return this.allocator.readOutput(TAG_BYTES)
  }

  // ── AEAD one-shot (combined = ct‖tag) ─────────────────────────────────────

  /** Cifra y autentica → `ct‖tag`. Streaming transparente si no cabe en PARAM_IN. */
  aeadEncrypt(
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array | null
  ): Uint8Array {
    const aadLen = aad ? aad.length : 0
    const headerSize = KEY_BYTES + this.nonceLen(variant) + aadLen
    if (headerSize + plaintext.length <= this.allocator.inSize) {
      const { keyPtr, noncePtr, aadPtr, aadLen: al } = this.layoutHeader(key, nonce, aad)
      const inPtr = this.allocator.writeInput(plaintext, headerSize)
      const fn = variant === "chacha" ? this.exp.chacha20poly1305_encrypt_ptr : this.exp.xchacha20poly1305_encrypt_ptr
      fn(keyPtr, noncePtr, aadPtr, al, inPtr, this.allocator.outPtr, plaintext.length)
      return this.allocator.readOutput(plaintext.length + TAG_BYTES)
    }
    return this.aeadEncryptStreamed(variant, key, nonce, plaintext, aad)
  }

  /** Verifica y descifra `ct‖tag` → plaintext, o `null` si el tag es inválido. */
  aeadDecrypt(
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    combined: Uint8Array,
    aad?: Uint8Array | null
  ): Uint8Array | null {
    if (combined.length < TAG_BYTES) return null
    const headerSize = KEY_BYTES + this.nonceLen(variant) + (aad ? aad.length : 0)
    if (headerSize + combined.length <= this.allocator.inSize) {
      const { keyPtr, noncePtr, aadPtr, aadLen: al } = this.layoutHeader(key, nonce, aad)
      const inPtr = this.allocator.writeInput(combined, headerSize)
      const fn = variant === "chacha" ? this.exp.chacha20poly1305_decrypt_ptr : this.exp.xchacha20poly1305_decrypt_ptr
      const ok = fn(keyPtr, noncePtr, aadPtr, al, inPtr, this.allocator.outPtr, combined.length)
      if (ok === 0) return null
      return this.allocator.readOutput(combined.length - TAG_BYTES)
    }
    return this.aeadDecryptStreamed(variant, key, nonce, combined, aad)
  }

  /** One-shot grande vía streaming interno (chunks de 1 MB). */
  private aeadEncryptStreamed(
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array | null
  ): Uint8Array {
    const ctx = this.aeadInitEncrypt(variant, key, nonce, aad)
    const chunks: Uint8Array[] = []
    const chunkSize = this.allocator.inSize
    for (let offset = 0; offset < plaintext.length; offset += chunkSize) {
      const end = Math.min(offset + chunkSize, plaintext.length)
      chunks.push(this.aeadUpdate(ctx, plaintext.subarray(offset, end)))
    }
    chunks.push(this.aeadFinalEncrypt(ctx))
    return concatBytes(...chunks)
  }

  private aeadDecryptStreamed(
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    combined: Uint8Array,
    aad?: Uint8Array | null
  ): Uint8Array | null {
    const ctLen = combined.length - TAG_BYTES
    const tag = combined.subarray(ctLen)
    const ctx = this.aeadInitDecrypt(variant, key, nonce, aad)
    const chunks: Uint8Array[] = []
    const chunkSize = this.allocator.inSize
    for (let offset = 0; offset < ctLen; offset += chunkSize) {
      const end = Math.min(offset + chunkSize, ctLen)
      chunks.push(this.aeadUpdate(ctx, combined.subarray(offset, end)))
    }
    const valid = this.aeadFinalDecrypt(ctx, tag)
    if (!valid) return null
    return concatBytes(...chunks)
  }

  // ── AEAD streaming (primitivas; las usan las clases de dominio) ───────────

  /** Inicia un stream de cifrado → ctxPtr opaco. key/nonce/aad se internalizan. */
  aeadInitEncrypt(variant: AeadVariant, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): number {
    const { keyPtr, noncePtr, aadPtr, aadLen } = this.layoutHeader(key, nonce, aad)
    return variant === "chacha"
      ? this.exp.chacha20poly1305_init_encrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
      : this.exp.xchacha20poly1305_init_encrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
  }

  /** Inicia un stream de descifrado → ctxPtr opaco. */
  aeadInitDecrypt(variant: AeadVariant, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): number {
    const { keyPtr, noncePtr, aadPtr, aadLen } = this.layoutHeader(key, nonce, aad)
    return variant === "chacha"
      ? this.exp.chacha20poly1305_init_decrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
      : this.exp.xchacha20poly1305_init_decrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
  }

  /** Procesa un chunk (cifra o descifra según el modo del ctx) → output del chunk. */
  aeadUpdate(ctx: number, chunk: Uint8Array): Uint8Array {
    if (chunk.length === 0) return new Uint8Array(0)
    const inPtr = this.allocator.writeInput(chunk, 0)
    this.exp.chacha20poly1305_update_ptr(ctx, inPtr, this.allocator.outPtr, chunk.length)
    return this.allocator.readOutput(chunk.length)
  }

  /** Cierra un stream de cifrado → tag (16 B). Libera el contexto. */
  aeadFinalEncrypt(ctx: number): Uint8Array {
    this.exp.chacha20poly1305_final_encrypt_ptr(ctx, this.allocator.outPtr)
    return this.allocator.readOutput(TAG_BYTES)
  }

  /** Cierra un stream de descifrado, verifica el tag → validez. Libera el contexto. */
  aeadFinalDecrypt(ctx: number, tag: Uint8Array): boolean {
    const tagPtr = this.allocator.writeInput(tag, 0)
    return this.exp.chacha20poly1305_final_decrypt_ptr(ctx, tagPtr) !== 0
  }

  /** Libera un stream SIN finalizar (abort). Requiere `aead_free_ptr` en el núcleo. */
  aeadFree(ctx: number): void {
    if (this.exp.aead_free_ptr) this.exp.aead_free_ptr(ctx)
  }
}
