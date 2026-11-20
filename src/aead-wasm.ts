/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  aead-wasm.ts — Cargador del WASM (ST & Multi-Slot MT) + API de bajo nivel
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Clase central (singleton por hilo/worker) que:
 *  1. Carga/instancia el módulo WASM en variante single-thread (`aead.wasm`,
 *     1 slot, 34 págs) o multithread (`aead.mt.wasm`, 8 slots independientes,
 *     264 págs sobre `SharedArrayBuffer`).
 *  2. Construye un pool de `WasmAllocator` (1 por slot I/O) para aislar
 *     concurrentemente a múltiples workers sin contención de locks.
 *  3. Sincroniza el acceso a cada slot con `Atomics` en JS (0 llamadas extra
 *     al WASM y 0 instrucciones atómicas dentro de la arena en el hot path).
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

const DEFAULT_MT_MEMORY_PAGES = 264 // 264 * 64 KB = 16.5 MB (8 slots MT)

export class AeadWasm {
  private exp: AsmExports
  private allocator: WasmAllocator
  private slotAllocators: WasmAllocator[]
  private compiledModule: WebAssembly.Module | null
  private threaded: boolean
  private slotCount: number
  private ctrlI32: Int32Array | null = null
  private offU32: Uint32Array | null = null
  private preferredSlot: number = 0
  private boundSlot: number = -1
  private boundOffset: number = 0
  private jsFallbackLocked: boolean = false
  private static instance: AeadWasm | null = null

  private constructor(exp: AsmExports, compiledModule: WebAssembly.Module | null = null) {
    this.exp = exp
    this.compiledModule = compiledModule
    this.threaded = exp.arena_is_threaded ? exp.arena_is_threaded() !== 0 : false
    this.slotCount = exp.arena_slot_count ? exp.arena_slot_count() : 1

    const inSize = getGlobalValue(exp.PARAM_IN_SIZE, 1 << 20)
    const outSize = getGlobalValue(exp.PARAM_OUT_SIZE, (1 << 20) + 64)
    const slot0In = getGlobalValue(exp.PARAM_IN_PTR, 0)
    const slot0Out = getGlobalValue(exp.PARAM_OUT_PTR, 0)

    this.slotAllocators = new Array<WasmAllocator>(this.slotCount)
    this.slotAllocators[0] = new WasmAllocator(exp.memory, slot0In, inSize, slot0Out, outSize)
    for (let s = 1; s < this.slotCount; s++) {
      const sIn = exp.arena_slot_in_ptr ? exp.arena_slot_in_ptr(s) : slot0In
      const sOut = exp.arena_slot_out_ptr ? exp.arena_slot_out_ptr(s) : slot0Out
      this.slotAllocators[s] = new WasmAllocator(exp.memory, sIn, inSize, sOut, outSize)
    }
    this.allocator = this.slotAllocators[0]

    if (exp.arena_ctrl_ptr) {
      const ctrlPtr = exp.arena_ctrl_ptr()
      this.ctrlI32 = new Int32Array(exp.memory.buffer, ctrlPtr, this.slotCount)
    }
    if (this.threaded) {
      if (exp.arena_worker_hint_ptr) {
        const hintPtr = exp.arena_worker_hint_ptr()
        const hintI32 = new Int32Array(exp.memory.buffer, hintPtr, 1)
        this.preferredSlot = (Atomics.add(hintI32, 0, 1) >>> 0) % this.slotCount
      }
      if (exp.arena_off_ptr) {
        const offPtr = exp.arena_off_ptr()
        this.offU32 = new Uint32Array(exp.memory.buffer, offPtr, this.slotCount)
      }
    }
  }

  /** Singleton global (por hilo/worker). Lanza si aún no se ha cargado el WASM. */
  static getInstance(): AeadWasm {
    if (!AeadWasm.instance) {
      throw new Error("AeadWasm no inicializado. Usa await AeadWasm.load() / loadThreaded() / fromBuffer() primero.")
    }
    return AeadWasm.instance
  }

  getAllocator(): WasmAllocator {
    return this.allocator
  }

  getSlotAllocator(slot: number = 0): WasmAllocator {
    return this.slotAllocators[slot] || this.allocator
  }

  getSlotCount(): number {
    return this.slotCount
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

  // ── Lock de memoria por slot y diagnósticos de Arena ──────────────────────

  /** Indica si el módulo WASM cargado soporta threads y memoria compartida. */
  isThreaded(): boolean {
    return this.threaded
  }

  /** Indica si un slot específico (por defecto Slot 0) está bloqueado. */
  isSlotLocked(slot: number = 0): boolean {
    if (slot < 0 || slot >= this.slotCount) return false
    if (this.ctrlI32) {
      return this.threaded ? Atomics.load(this.ctrlI32, slot) !== 0 : this.ctrlI32[slot] !== 0
    }
    return this.exp.arena_is_locked ? this.exp.arena_is_locked() !== 0 : this.jsFallbackLocked
  }

  /** Indica si el Slot 0 (`PARAM_IN_PTR`/`PARAM_OUT_PTR`) está bloqueado. */
  isLocked(): boolean {
    return this.isSlotLocked(0)
  }

  /** Intenta adquirir el lock de un slot concreto sin bloquear. */
  tryLockSlot(slot: number = 0): boolean {
    if (slot < 0 || slot >= this.slotCount) return false
    if (this.ctrlI32) {
      if (this.threaded) {
        const ok = Atomics.compareExchange(this.ctrlI32, slot, 0, 1) === 0
        if (ok) this.boundSlot = -1
        return ok
      }
      if (this.ctrlI32[slot] !== 0) return false
      this.ctrlI32[slot] = 1
      this.boundSlot = -1
      return true
    }
    if (this.exp.arena_try_lock) {
      return this.exp.arena_try_lock() !== 0
    }
    if (this.jsFallbackLocked) return false
    this.jsFallbackLocked = true
    return true
  }

  /** Intenta adquirir el lock del Slot 0 sin bloquear. */
  tryLock(): boolean {
    return this.tryLockSlot(0)
  }

  /** Adquiere el lock de un slot concreto (spin-wait en MT, fail-fast en ST). */
  lockSlot(slot: number = 0): void {
    if (slot < 0 || slot >= this.slotCount) {
      throw new RangeError(`Slot inválido: ${slot}`)
    }
    if (this.threaded && this.ctrlI32) {
      while (Atomics.compareExchange(this.ctrlI32, slot, 0, 1) !== 0) {
        // spin-wait atómico
      }
      this.boundSlot = -1
      return
    }
    if (!this.tryLockSlot(slot)) {
      throw new Error("AeadWasm: memoria bloqueada por otra operación en curso; no se puede sobreescribir.")
    }
  }

  /**
   * Adquiere el lock exclusivo del Slot 0 (`PARAM_IN_PTR`/`PARAM_OUT_PTR`).
   * • En multithread: espera mediante spinlock atómico hasta quedar libre.
   * • En single-thread: lanza inmediatamente si ya está ocupado.
   */
  lock(): void {
    this.lockSlot(0)
  }

  /** Libera el lock de un slot concreto. */
  unlockSlot(slot: number = 0): void {
    if (slot < 0 || slot >= this.slotCount) return
    if (this.ctrlI32) {
      if (this.threaded) {
        Atomics.store(this.ctrlI32, slot, 0)
      } else {
        this.ctrlI32[slot] = 0
      }
      this.boundSlot = -1
      return
    }
    if (this.exp.arena_unlock) {
      this.exp.arena_unlock()
    } else {
      this.jsFallbackLocked = false
    }
  }

  /** Libera el lock exclusivo del Slot 0. */
  unlock(): void {
    this.unlockSlot(0)
  }

  /** Devuelve métricas actuales de la Arena WASM y estado del lock. */
  getArenaStats(): ArenaStats {
    return {
      used: this.exp.arena_used ? this.exp.arena_used() : 0,
      capacity: this.exp.arena_capacity ? this.exp.arena_capacity() : 65536,
      locked: this.isLocked(),
      threaded: this.threaded,
      slots: this.slotCount
    }
  }

  // ── Gestión de pool de slots sin contención ───────────────────────────────

  private acquireAnySlot(): number {
    if (!this.threaded) {
      if (this.ctrlI32) {
        if (this.ctrlI32[0] !== 0) {
          throw new Error("AeadWasm: memoria bloqueada por otra operación en curso; no se puede sobreescribir.")
        }
        this.ctrlI32[0] = 1
        return 0
      }
      if (!this.tryLockSlot(0)) {
        throw new Error("AeadWasm: memoria bloqueada por otra operación en curso; no se puede sobreescribir.")
      }
      return 0
    }

    const ctrl = this.ctrlI32!
    const count = this.slotCount
    let s = this.preferredSlot

    // Fast path: 1 solo CAS sin iterar cuando nuestro slot asignado está libre
    if (Atomics.compareExchange(ctrl, s, 0, 1) === 0) {
      return s
    }

    // Buscar otro slot libre antes de entrar en spin-wait
    for (;;) {
      for (let i = 1; i < count; i++) {
        const idx = (s + i) % count
        if (Atomics.compareExchange(ctrl, idx, 0, 1) === 0) {
          return idx
        }
      }
      if (Atomics.compareExchange(ctrl, s, 0, 1) === 0) {
        return s
      }
      s = (s + 1) % count
    }
  }

  private acquireSpecificSlot(slot: number): void {
    if (!this.threaded) {
      if (this.ctrlI32) {
        if (this.ctrlI32[0] !== 0) {
          throw new Error("AeadWasm: memoria bloqueada por otra operación en curso; no se puede sobreescribir.")
        }
        this.ctrlI32[0] = 1
        return
      }
      if (!this.tryLockSlot(0)) {
        throw new Error("AeadWasm: memoria bloqueada por otra operación en curso; no se puede sobreescribir.")
      }
      return
    }
    const ctrl = this.ctrlI32!
    while (Atomics.compareExchange(ctrl, slot, 0, 1) !== 0) {
      // spin-wait hasta liberar el slot propietario del contexto streaming
    }
  }

  private bindSlot(slot: number): void {
    if (!this.threaded || !this.exp.arena_use_slot) return
    const currentOff = this.offU32 ? this.offU32[slot] : 0
    if (this.boundSlot !== slot || this.boundOffset !== currentOff) {
      this.exp.arena_use_slot(slot)
      this.boundSlot = slot
      this.boundOffset = currentOff
    }
  }

  private releaseSlot(slot: number, syncArena: boolean): void {
    if (!this.threaded) {
      if (this.ctrlI32) {
        this.ctrlI32[0] = 0
      } else {
        this.unlockSlot(0)
      }
      return
    }
    if (syncArena && this.exp.arena_sync_slot) {
      this.exp.arena_sync_slot()
      this.boundOffset = this.offU32 ? this.offU32[slot] : 0
    }
    Atomics.store(this.ctrlI32!, slot, 0)
  }

  private withSlot<T>(fn: (alloc: WasmAllocator, slot: number) => T, syncArena: boolean = false): T {
    const slot = this.acquireAnySlot()
    try {
      this.bindSlot(slot)
      return fn(this.slotAllocators[slot], slot)
    } finally {
      this.releaseSlot(slot, syncArena)
    }
  }

  private withSpecificSlot<T>(slot: number, fn: (alloc: WasmAllocator) => T, syncArena: boolean = false): T {
    this.acquireSpecificSlot(slot)
    try {
      this.bindSlot(slot)
      return fn(this.slotAllocators[slot])
    } finally {
      this.releaseSlot(slot, syncArena)
    }
  }

  private slotForCtx(ctx: number): number {
    if (!this.threaded || !this.exp.arena_slot_for_ptr) return 0
    return this.exp.arena_slot_for_ptr(ctx)
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
  static createSharedMemory(pages: number = DEFAULT_MT_MEMORY_PAGES): WebAssembly.Memory {
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
        envImports.memory = AeadWasm.createSharedMemory(DEFAULT_MT_MEMORY_PAGES)
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

  // ── Helpers privados de layout en PARAM_IN[slot] ──────────────────────────

  /** Escribe key‖nonce‖aad al inicio del slot PARAM_IN y devuelve sus punteros. */
  private layoutHeader(alloc: WasmAllocator, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null) {
    let offset = 0
    const keyPtr = alloc.writeInput(key, offset)
    offset += KEY_BYTES
    const noncePtr = alloc.writeInput(nonce, offset)
    offset += nonce.length
    let aadPtr = 0
    let aadLen = 0
    if (aad && aad.length > 0) {
      aadPtr = alloc.writeInput(aad, offset)
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
    return this.withSlot((alloc) => {
      const keyPtr = alloc.writeInput(key, 0)
      const noncePtr = alloc.writeInput(nonce, KEY_BYTES)
      const inPtr = alloc.writeInput(data, KEY_BYTES + NONCE_BYTES)
      this.exp.chacha20_encrypt_ptr(keyPtr, noncePtr, inPtr, alloc.outPtr, data.length, counter)
      return alloc.readOutput(data.length)
    })
  }

  /** XChaCha20 one-shot (nonce 24 B). */
  xchacha20(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, counter: number = 0): Uint8Array {
    const capacity = this.allocator.inSize - KEY_BYTES - XNONCE_BYTES
    if (data.length > capacity) throw new Error("XChaCha20: datos > 1 MB; usa AEAD streaming o cifra por bloques.")
    return this.withSlot((alloc) => {
      const keyPtr = alloc.writeInput(key, 0)
      const noncePtr = alloc.writeInput(nonce, KEY_BYTES)
      const inPtr = alloc.writeInput(data, KEY_BYTES + XNONCE_BYTES)
      this.exp.xchacha20_encrypt_ptr(keyPtr, noncePtr, inPtr, alloc.outPtr, data.length, counter)
      return alloc.readOutput(data.length)
    })
  }

  // ── Poly1305 (MAC one-shot) ───────────────────────────────────────────────

  /** Poly1305 MAC (tag 16 B). Mensaje hasta ~1 MB; más allá usa AEAD streaming. */
  poly1305Mac(key: Uint8Array, msg: Uint8Array): Uint8Array {
    const capacity = this.allocator.inSize - KEY_BYTES
    if (msg.length > capacity) throw new Error("Poly1305: mensaje > 1 MB; usa AEAD streaming.")
    return this.withSlot((alloc) => {
      const keyPtr = alloc.writeInput(key, 0)
      const msgPtr = alloc.writeInput(msg, KEY_BYTES)
      this.exp.poly1305_mac_ptr(msgPtr, msg.length, keyPtr, alloc.outPtr)
      return alloc.readOutput(TAG_BYTES)
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
    return this.withSlot((alloc) => {
      if (headerSize + plaintext.length <= alloc.inSize) {
        const { keyPtr, noncePtr, aadPtr, aadLen: al } = this.layoutHeader(alloc, key, nonce, aad)
        const inPtr = alloc.writeInput(plaintext, headerSize)
        const fn = variant === "chacha" ? this.exp.chacha20poly1305_encrypt_ptr : this.exp.xchacha20poly1305_encrypt_ptr
        fn(keyPtr, noncePtr, aadPtr, al, inPtr, alloc.outPtr, plaintext.length)
        return alloc.readOutput(plaintext.length + TAG_BYTES)
      }
      return this.aeadEncryptStreamedUnlocked(alloc, variant, key, nonce, plaintext, aad)
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
    return this.withSlot((alloc) => {
      if (headerSize + combined.length <= alloc.inSize) {
        const { keyPtr, noncePtr, aadPtr, aadLen: al } = this.layoutHeader(alloc, key, nonce, aad)
        const inPtr = alloc.writeInput(combined, headerSize)
        const fn = variant === "chacha" ? this.exp.chacha20poly1305_decrypt_ptr : this.exp.xchacha20poly1305_decrypt_ptr
        const ok = fn(keyPtr, noncePtr, aadPtr, al, inPtr, alloc.outPtr, combined.length)
        if (ok === 0) return null
        return alloc.readOutput(combined.length - TAG_BYTES)
      }
      return this.aeadDecryptStreamedUnlocked(alloc, variant, key, nonce, combined, aad)
    })
  }

  /** One-shot grande vía streaming interno (bajo un único lock de slot continuo). */
  private aeadEncryptStreamedUnlocked(
    alloc: WasmAllocator,
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array | null
  ): Uint8Array {
    const ctx = this.aeadInitEncryptUnlocked(alloc, variant, key, nonce, aad)
    try {
      const chunks: Uint8Array[] = []
      const chunkSize = alloc.inSize
      for (let offset = 0; offset < plaintext.length; offset += chunkSize) {
        const end = Math.min(offset + chunkSize, plaintext.length)
        chunks.push(this.aeadUpdateUnlocked(alloc, ctx, plaintext.subarray(offset, end)))
      }
      chunks.push(this.aeadFinalEncryptUnlocked(alloc, ctx))
      return concatBytes(...chunks)
    } catch (e) {
      this.aeadFreeUnlocked(ctx)
      throw e
    }
  }

  private aeadDecryptStreamedUnlocked(
    alloc: WasmAllocator,
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    combined: Uint8Array,
    aad?: Uint8Array | null
  ): Uint8Array | null {
    const ctLen = combined.length - TAG_BYTES
    const tag = combined.subarray(ctLen)
    const ctx = this.aeadInitDecryptUnlocked(alloc, variant, key, nonce, aad)
    try {
      const chunks: Uint8Array[] = []
      const chunkSize = alloc.inSize
      for (let offset = 0; offset < ctLen; offset += chunkSize) {
        const end = Math.min(offset + chunkSize, ctLen)
        chunks.push(this.aeadUpdateUnlocked(alloc, ctx, combined.subarray(offset, end)))
      }
      const valid = this.aeadFinalDecryptUnlocked(alloc, ctx, tag)
      if (!valid) return null
      return concatBytes(...chunks)
    } catch (e) {
      this.aeadFreeUnlocked(ctx)
      throw e
    }
  }

  // ── AEAD streaming (primitivas internas sobre slot bloqueado) ─────────────

  private aeadInitEncryptUnlocked(
    alloc: WasmAllocator,
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array | null
  ): number {
    const { keyPtr, noncePtr, aadPtr, aadLen } = this.layoutHeader(alloc, key, nonce, aad)
    return variant === "chacha"
      ? this.exp.chacha20poly1305_init_encrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
      : this.exp.xchacha20poly1305_init_encrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
  }

  private aeadInitDecryptUnlocked(
    alloc: WasmAllocator,
    variant: AeadVariant,
    key: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array | null
  ): number {
    const { keyPtr, noncePtr, aadPtr, aadLen } = this.layoutHeader(alloc, key, nonce, aad)
    return variant === "chacha"
      ? this.exp.chacha20poly1305_init_decrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
      : this.exp.xchacha20poly1305_init_decrypt_ptr(keyPtr, noncePtr, aadPtr, aadLen)
  }

  private aeadUpdateUnlocked(alloc: WasmAllocator, ctx: number, chunk: Uint8Array): Uint8Array {
    if (chunk.length === 0) return new Uint8Array(0)
    const inPtr = alloc.writeInput(chunk, 0)
    this.exp.chacha20poly1305_update_ptr(ctx, inPtr, alloc.outPtr, chunk.length)
    return alloc.readOutput(chunk.length)
  }

  private aeadFinalEncryptUnlocked(alloc: WasmAllocator, ctx: number): Uint8Array {
    this.exp.chacha20poly1305_final_encrypt_ptr(ctx, alloc.outPtr)
    return alloc.readOutput(TAG_BYTES)
  }

  private aeadFinalDecryptUnlocked(alloc: WasmAllocator, ctx: number, tag: Uint8Array): boolean {
    const tagPtr = alloc.writeInput(tag, 0)
    return this.exp.chacha20poly1305_final_decrypt_ptr(ctx, tagPtr) !== 0
  }

  private aeadFreeUnlocked(ctx: number): void {
    if (this.exp.aead_free_ptr && ctx !== 0) this.exp.aead_free_ptr(ctx)
  }

  // ── AEAD streaming (primitivas públicas protegidas por slot) ──────────────

  /** Inicia un stream de cifrado → ctxPtr opaco. key/nonce/aad se internalizan. */
  aeadInitEncrypt(variant: AeadVariant, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): number {
    return this.withSlot((alloc) => this.aeadInitEncryptUnlocked(alloc, variant, key, nonce, aad), true)
  }

  /** Inicia un stream de descifrado → ctxPtr opaco. */
  aeadInitDecrypt(variant: AeadVariant, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): number {
    return this.withSlot((alloc) => this.aeadInitDecryptUnlocked(alloc, variant, key, nonce, aad), true)
  }

  /** Procesa un chunk (cifra o descifra según el modo del ctx) → output del chunk. */
  aeadUpdate(ctx: number, chunk: Uint8Array): Uint8Array {
    if (chunk.length === 0) return new Uint8Array(0)
    return this.withSpecificSlot(this.slotForCtx(ctx), (alloc) => this.aeadUpdateUnlocked(alloc, ctx, chunk))
  }

  /** Cierra un stream de cifrado → tag (16 B). Libera el contexto. */
  aeadFinalEncrypt(ctx: number): Uint8Array {
    return this.withSpecificSlot(this.slotForCtx(ctx), (alloc) => this.aeadFinalEncryptUnlocked(alloc, ctx), true)
  }

  /** Cierra un stream de descifrado, verifica el tag → validez. Libera el contexto. */
  aeadFinalDecrypt(ctx: number, tag: Uint8Array): boolean {
    return this.withSpecificSlot(this.slotForCtx(ctx), (alloc) => this.aeadFinalDecryptUnlocked(alloc, ctx, tag), true)
  }

  /** Libera un stream SIN finalizar (abort). Requiere `aead_free_ptr` en el núcleo. */
  aeadFree(ctx: number): void {
    this.withSpecificSlot(this.slotForCtx(ctx), () => this.aeadFreeUnlocked(ctx), true)
  }
}
