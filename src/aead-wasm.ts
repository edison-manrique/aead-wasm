/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  aead-wasm.ts — Cargador del WASM (ST & MT) + API de bajo nivel con Lock
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Clase central (singleton) que:
 *  1. Carga/instancia el módulo WASM en variante single-thread (`aead.wasm`)
 *     o multithread (`aead.mt.wasm` con `SharedArrayBuffer` y memoria compartida).
 *  2. Lee las regiones de I/O plano (PARAM_IN/OUT, 1 MB c/u) y crea el
 *     WasmAllocator.
 *  3. Protege todas las operaciones sobre `PARAM_IN`/`PARAM_OUT` mediante el
 *     lock de `Arena` (`arena_lock` / `arena_try_lock` / `arena_unlock`) para
 *     impedir sobreescrituras mientras una operación está en curso.
 */
import {
  AsmExports,
  AeadVariant,
  ArenaStats,
  KEY_BYTES,
  NONCE_BYTES,
  XNONCE_BYTES,
  TAG_BYTES,
  getGlobalValue,
  concatBytes
} from "./types"
import { WasmAllocator } from "./allocator"

const DEFAULT_MEMORY_PAGES = 34 // 34 * 64 KB = 2.125 MB (Arena 64KB + I/O 2MB)

export class AeadWasm {
  private exp: AsmExports
  private allocator: WasmAllocator
  private compiledModule: WebAssembly.Module | null
  private jsFallbackLocked: boolean = false
  private static instance: AeadWasm | null = null

  private constructor(exp: AsmExports, compiledModule: WebAssembly.Module | null = null) {
    this.exp = exp
    this.compiledModule = compiledModule
    const inPtr = getGlobalValue(exp.PARAM_IN_PTR, 0)
    const inSize = getGlobalValue(exp.PARAM_IN_SIZE, 1 << 20)
    const outPtr = getGlobalValue(exp.PARAM_OUT_PTR, 0)
    const outSize = getGlobalValue(exp.PARAM_OUT_SIZE, (1 << 20) + 64)
    this.allocator = new WasmAllocator(exp.memory, inPtr, inSize, outPtr, outSize)
  }

  /** Singleton global. Lanza si aún no se ha cargado el WASM. */
  static getInstance(): AeadWasm {
    if (!AeadWasm.instance) {
      throw new Error("AeadWasm no inicializado. Usa await AeadWasm.load() / loadThreaded() / fromBuffer() primero.")
    }
    return AeadWasm.instance
  }

  getAllocator(): WasmAllocator {
    return this.allocator
  }

  getExports(): AsmExports {
    return this.exp
  }

  getMemory(): WebAssembly.Memory {
    return this.exp.memory
  }

  getModule(): WebAssembly.Module | null {
    return this.compiledModule
  }

  // ── Lock de memoria y diagnósticos de Arena ───────────────────────────────

  /** Indica si el módulo WASM cargado soporta threads y memoria compartida. */
  isThreaded(): boolean {
    return this.exp.arena_is_threaded ? this.exp.arena_is_threaded() !== 0 : false
  }

  /** Indica si la memoria I/O está bloqueada actualmente por otra operación. */
  isLocked(): boolean {
    return this.exp.arena_is_locked ? this.exp.arena_is_locked() !== 0 : this.jsFallbackLocked
  }

  /** Intenta adquirir el lock sin bloquear. Devuelve `false` si ya está ocupado. */
  tryLock(): boolean {
    if (this.exp.arena_try_lock) {
      return this.exp.arena_try_lock() !== 0
    }
    if (this.jsFallbackLocked) return false
    this.jsFallbackLocked = true
    return true
  }

  /**
   * Adquiere el lock exclusivo de memoria I/O.
   * • En multithread: espera mediante spinlock atómico WASM hasta quedar libre.
   * • En single-thread: lanza inmediatamente si ya está ocupado (evita sobreescritura).
   */
  lock(): void {
    if (this.exp.arena_lock && this.isThreaded()) {
      this.exp.arena_lock()
      return
    }
    if (!this.tryLock()) {
      throw new Error("AeadWasm: memoria bloqueada por otra operación en curso; no se puede sobreescribir.")
    }
  }

  /** Libera el lock exclusivo de memoria. */
  unlock(): void {
    if (this.exp.arena_unlock) {
      this.exp.arena_unlock()
    } else {
      this.jsFallbackLocked = false
    }
  }

  /** Devuelve métricas actuales de la Arena WASM y estado del lock. */
  getArenaStats(): ArenaStats {
    return {
      used: this.exp.arena_used ? this.exp.arena_used() : 0,
      capacity: this.exp.arena_capacity ? this.exp.arena_capacity() : 65536,
      locked: this.isLocked(),
      threaded: this.isThreaded()
    }
  }

  private withIoLock<T>(fn: () => T): T {
    this.lock()
    try {
      return fn()
    } finally {
      this.unlock()
    }
  }

  // ── Carga del módulo (ST & MT) ────────────────────────────────────────────

  static getDefaultWasmUrl(): string {
    const baseUrl = "./aead.wasm"
    try {
      return new URL(baseUrl, import.meta.url).href
    } catch {
      return baseUrl
    }
  }

  static getDefaultThreadedWasmUrl(): string {
    const baseUrl = "./aead.mt.wasm"
    try {
      return new URL(baseUrl, import.meta.url).href
    } catch {
      return baseUrl
    }
  }

  /** Crea una WebAssembly.Memory compartida (SharedArrayBuffer) lista para workers MT. */
  static createSharedMemory(pages: number = DEFAULT_MEMORY_PAGES): WebAssembly.Memory {
    return new WebAssembly.Memory({ initial: pages, maximum: pages, shared: true })
  }

  private static buildImports(imports: WebAssembly.Imports, module?: WebAssembly.Module): WebAssembly.Imports {
    const envImports: Record<string, unknown> = {
      abort() {
        console.error("WASM Abort")
      },
      seed() {
        return Math.random()
      },
      ...((imports.env as Record<string, unknown>) || {})
    }

    if (module && !envImports.memory) {
      const needsImportedMemory = WebAssembly.Module.imports(module).some(
        (imp) => imp.module === "env" && imp.name === "memory" && imp.kind === "memory"
      )
      if (needsImportedMemory) {
        envImports.memory = AeadWasm.createSharedMemory(DEFAULT_MEMORY_PAGES)
      }
    }

    return {
      ...imports,
      env: envImports as WebAssembly.ModuleImports
    }
  }

  /** Carga la versión single-thread por defecto (o una URL personalizada). */
  static async load(url?: string, imports: WebAssembly.Imports = {}): Promise<AeadWasm> {
    if (AeadWasm.instance) return AeadWasm.instance
    return AeadWasm.fromUrl(url || AeadWasm.getDefaultWasmUrl(), imports)
  }

  /** Carga la versión multithread (`aead.mt.wasm`) con memoria compartida. */
  static async loadThreaded(url?: string, imports: WebAssembly.Imports = {}): Promise<AeadWasm> {
    if (AeadWasm.instance && AeadWasm.instance.isThreaded()) return AeadWasm.instance
    return AeadWasm.fromUrl(url || AeadWasm.getDefaultThreadedWasmUrl(), imports)
  }

  static async fromUrl(url: string, imports: WebAssembly.Imports = {}): Promise<AeadWasm> {
    let mod: WebAssembly.Module
    const res = await fetch(url)
    if (!res.ok) {
      throw new Error(`No se pudo cargar WASM (${res.status} ${res.statusText}): ${url}`)
    }
    if (typeof WebAssembly.compileStreaming === "function") {
      try {
        mod = await WebAssembly.compileStreaming(res.clone())
      } catch {
        mod = await WebAssembly.compile(await res.arrayBuffer())
      }
    } else {
      mod = await WebAssembly.compile(await res.arrayBuffer())
    }
    return AeadWasm.fromModule(mod, imports)
  }

  static async fromBuffer(buffer: ArrayBuffer | Uint8Array, imports: WebAssembly.Imports = {}): Promise<AeadWasm> {
    const buf = (
      buffer instanceof Uint8Array
        ? buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
        : buffer
    ) as ArrayBuffer
    const mod = await WebAssembly.compile(buf)
    return AeadWasm.fromModule(mod, imports)
  }

  /** Instancia desde un `WebAssembly.Module` ya compilado (ideal para Workers MT). */
  static async fromModule(module: WebAssembly.Module, imports: WebAssembly.Imports = {}): Promise<AeadWasm> {
    const finalImports = AeadWasm.buildImports(imports, module)
    const instance = await WebAssembly.instantiate(module, finalImports)
    const exportsObj = instance.exports as unknown as AsmExports
    if (!exportsObj.memory && finalImports.env && (finalImports.env as Record<string, unknown>).memory) {
      ;(exportsObj as unknown as { memory: WebAssembly.Memory }).memory = (
        finalImports.env as Record<string, WebAssembly.Memory>
      ).memory
    }
    AeadWasm.instance = new AeadWasm(exportsObj, module)
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
    return this.withIoLock(() => {
      const keyPtr = this.allocator.writeInput(key, 0)
      const noncePtr = this.allocator.writeInput(nonce, KEY_BYTES)
      const inPtr = this.allocator.writeInput(data, KEY_BYTES + NONCE_BYTES)
      this.exp.chacha20_encrypt_ptr(keyPtr, noncePtr, inPtr, this.allocator.outPtr, data.length, counter)
      return this.allocator.readOutput(data.length)
    })
  }

  /** XChaCha20 one-shot (nonce 24 B). */
  xchacha20(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, counter: number = 0): Uint8Array {
    const capacity = this.allocator.inSize - KEY_BYTES - XNONCE_BYTES
    if (data.length > capacity) throw new Error("XChaCha20: datos > 1 MB; usa AEAD streaming o cifra por bloques.")
    return this.withIoLock(() => {
      const keyPtr = this.allocator.writeInput(key, 0)
      const noncePtr = this.allocator.writeInput(nonce, KEY_BYTES)
      const inPtr = this.allocator.writeInput(data, KEY_BYTES + XNONCE_BYTES)
      this.exp.xchacha20_encrypt_ptr(keyPtr, noncePtr, inPtr, this.allocator.outPtr, data.length, counter)
      return this.allocator.readOutput(data.length)
    })
  }

  // ── Poly1305 (MAC one-shot) ───────────────────────────────────────────────

  /** Poly1305 MAC (tag 16 B). Mensaje hasta ~1 MB; más allá usa AEAD streaming. */
  poly1305Mac(key: Uint8Array, msg: Uint8Array): Uint8Array {
    const capacity = this.allocator.inSize - KEY_BYTES
    if (msg.length > capacity) throw new Error("Poly1305: mensaje > 1 MB; usa AEAD streaming.")
    return this.withIoLock(() => {
      const keyPtr = this.allocator.writeInput(key, 0)
      const msgPtr = this.allocator.writeInput(msg, KEY_BYTES)
      this.exp.poly1305_mac_ptr(msgPtr, msg.length, keyPtr, this.allocator.outPtr)
      return this.allocator.readOutput(TAG_BYTES)
    })
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
    return this.withIoLock(() => {
      if (headerSize + plaintext.length <= this.allocator.inSize) {
        const { keyPtr, noncePtr, aadPtr, aadLen: al } = this.layoutHeader(key, nonce, aad)
        const inPtr = this.allocator.writeInput(plaintext, headerSize)
        const fn = variant === "chacha" ? this.exp.chacha20poly1305_encrypt_ptr : this.exp.xchacha20poly1305_encrypt_ptr
        fn(keyPtr, noncePtr, aadPtr, al, inPtr, this.allocator.outPtr, plaintext.length)
        return this.allocator.readOutput(plaintext.length + TAG_BYTES)
      }
      return this.aeadEncryptStreamedUnlocked(variant, key, nonce, plaintext, aad)
    })
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
    return this.withIoLock(() => {
      if (headerSize + combined.length <= this.allocator.inSize) {
        const { keyPtr, noncePtr, aadPtr, aadLen: al } = this.layoutHeader(key, nonce, aad)
        const inPtr = this.allocator.writeInput(combined, headerSize)
        const fn = variant === "chacha" ? this.exp.chacha20poly1305_decrypt_ptr : this.exp.xchacha20poly1305_decrypt_ptr
        const ok = fn(keyPtr, noncePtr, aadPtr, al, inPtr, this.allocator.outPtr, combined.length)
        if (ok === 0) return null
        return this.allocator.readOutput(combined.length - TAG_BYTES)
      }
      return this.aeadDecryptStreamedUnlocked(variant, key, nonce, combined, aad)
    })
  }

  /** One-shot grande vía streaming interno (bajo un único lock continuo). */
  private aeadEncryptStreamedUnlocked(
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array | null
  ): Uint8Array {
    const ctx = this.aeadInitEncryptUnlocked(variant, key, nonce, aad)
    try {
      const chunks: Uint8Array[] = []
      const chunkSize = this.allocator.inSize
      for (let offset = 0; offset < plaintext.length; offset += chunkSize) {
        const end = Math.min(offset + chunkSize, plaintext.length)
        chunks.push(this.aeadUpdateUnlocked(ctx, plaintext.subarray(offset, end)))
      }
      chunks.push(this.aeadFinalEncryptUnlocked(ctx))
      return concatBytes(...chunks)
    } catch (e) {
      this.aeadFreeUnlocked(ctx)
      throw e
    }
  }

  private aeadDecryptStreamedUnlocked(
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    combined: Uint8Array,
    aad?: Uint8Array | null
  ): Uint8Array | null {
    const ctLen = combined.length - TAG_BYTES
    const tag = combined.subarray(ctLen)
    const ctx = this.aeadInitDecryptUnlocked(variant, key, nonce, aad)
    try {
      const chunks: Uint8Array[] = []
      const chunkSize = this.allocator.inSize
      for (let offset = 0; offset < ctLen; offset += chunkSize) {
        const end = Math.min(offset + chunkSize, ctLen)
        chunks.push(this.aeadUpdateUnlocked(ctx, combined.subarray(offset, end)))
      }
      const valid = this.aeadFinalDecryptUnlocked(ctx, tag)
      if (!valid) return null
      return concatBytes(...chunks)
    } catch (e) {
      this.aeadFreeUnlocked(ctx)
      throw e
    }
  }

  // ── AEAD streaming (primitivas internas sin re-adquirir lock) ─────────────

  private aeadInitEncryptUnlocked(variant: AeadVariant, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): number {
    const { keyPtr, noncePtr, aadPtr, aadLen } = this.layoutHeader(key, nonce, aad)
    return variant === "chacha"
      ? this.exp.chacha20poly1305_init_encrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
      : this.exp.xchacha20poly1305_init_encrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
  }

  private aeadInitDecryptUnlocked(variant: AeadVariant, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): number {
    const { keyPtr, noncePtr, aadPtr, aadLen } = this.layoutHeader(key, nonce, aad)
    return variant === "chacha"
      ? this.exp.chacha20poly1305_init_decrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
      : this.exp.xchacha20poly1305_init_decrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
  }

  private aeadUpdateUnlocked(ctx: number, chunk: Uint8Array): Uint8Array {
    if (chunk.length === 0) return new Uint8Array(0)
    const inPtr = this.allocator.writeInput(chunk, 0)
    this.exp.chacha20poly1305_update_ptr(ctx, inPtr, this.allocator.outPtr, chunk.length)
    return this.allocator.readOutput(chunk.length)
  }

  private aeadFinalEncryptUnlocked(ctx: number): Uint8Array {
    this.exp.chacha20poly1305_final_encrypt_ptr(ctx, this.allocator.outPtr)
    return this.allocator.readOutput(TAG_BYTES)
  }

  private aeadFinalDecryptUnlocked(ctx: number, tag: Uint8Array): boolean {
    const tagPtr = this.allocator.writeInput(tag, 0)
    return this.exp.chacha20poly1305_final_decrypt_ptr(ctx, tagPtr) !== 0
  }

  private aeadFreeUnlocked(ctx: number): void {
    if (this.exp.aead_free_ptr && ctx !== 0) this.exp.aead_free_ptr(ctx)
  }

  // ── AEAD streaming (primitivas públicas protegidas por lock) ──────────────

  /** Inicia un stream de cifrado → ctxPtr opaco. key/nonce/aad se internalizan. */
  aeadInitEncrypt(variant: AeadVariant, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): number {
    return this.withIoLock(() => this.aeadInitEncryptUnlocked(variant, key, nonce, aad))
  }

  /** Inicia un stream de descifrado → ctxPtr opaco. */
  aeadInitDecrypt(variant: AeadVariant, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): number {
    return this.withIoLock(() => this.aeadInitDecryptUnlocked(variant, key, nonce, aad))
  }

  /** Procesa un chunk (cifra o descifra según el modo del ctx) → output del chunk. */
  aeadUpdate(ctx: number, chunk: Uint8Array): Uint8Array {
    if (chunk.length === 0) return new Uint8Array(0)
    return this.withIoLock(() => this.aeadUpdateUnlocked(ctx, chunk))
  }

  /** Cierra un stream de cifrado → tag (16 B). Libera el contexto. */
  aeadFinalEncrypt(ctx: number): Uint8Array {
    return this.withIoLock(() => this.aeadFinalEncryptUnlocked(ctx))
  }

  /** Cierra un stream de descifrado, verifica el tag → validez. Libera el contexto. */
  aeadFinalDecrypt(ctx: number, tag: Uint8Array): boolean {
    return this.withIoLock(() => this.aeadFinalDecryptUnlocked(ctx, tag))
  }

  /** Libera un stream SIN finalizar (abort). Requiere `aead_free_ptr` en el núcleo. */
  aeadFree(ctx: number): void {
    this.withIoLock(() => this.aeadFreeUnlocked(ctx))
  }
}
