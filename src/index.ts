/**
 * ==============================================================================
 * 🔐 ChaChaPolyWasm — Wrapper TypeScript Zero-Alloc para WASM
 * ==============================================================================
 *
 * Expone una interfaz limpia y completamente tipada para el módulo WASM de
 * AssemblyScript compilado con `--runtime minimal`.
 *
 * Implementa un asignador estático de memoria personalizado ("scratchpad")
 * para pasar argumentos (Uint8Arrays) a WASM sin requerir los bindings o
 * cargadores por defecto de `asc` ni la exportación de `__new`.
 *
 * Algoritmos soportados:
 *   - ChaCha20       (RFC 8439 — cifrador de flujo, nonce 12 bytes)
 *   - XChaCha20      (Extensión con nonce 24 bytes)
 *   - Poly1305       (MAC de un solo uso — RFC 8439)
 *   - ChaCha20-Poly1305   (AEAD — RFC 8439)
 *   - XChaCha20-Poly1305  (AEAD extendido con nonce 24 bytes)
 * ==============================================================================
 */

// ── Tipos ──────────────────────────────────────────────────────────────────

/** Exports crudos de WASM producidos por AssemblyScript con `--runtime minimal` */
interface AsmExports extends WebAssembly.Exports {
  memory: WebAssembly.Memory

  // ── ChaCha20 (cifrador de flujo) ──────────────────────────────────────
  chacha20_encrypt: (keyPtr: number, noncePtr: number, dataPtr: number, outputPtr: number, counter?: number) => void
  chacha20_decrypt: (keyPtr: number, noncePtr: number, dataPtr: number, outputPtr: number, counter?: number) => void

  // ── XChaCha20 (cifrador de flujo extendido) ───────────────────────────
  xchacha20_encrypt: (keyPtr: number, noncePtr: number, dataPtr: number, outputPtr: number, counter?: number) => void
  xchacha20_decrypt: (keyPtr: number, noncePtr: number, dataPtr: number, outputPtr: number, counter?: number) => void

  // ── Poly1305 (MAC) ────────────────────────────────────────────────────
  Poly1305_mac: (msgPtr: number, keyPtr: number, outPtr: number) => void

  // ── ChaCha20-Poly1305 AEAD (RFC 8439) ─────────────────────────────────
  chacha20poly1305_encrypt: (
    keyPtr: number,
    noncePtr: number,
    aadPtr: number,
    plaintextPtr: number,
    outputPtr: number
  ) => void
  chacha20poly1305_decrypt: (
    keyPtr: number,
    noncePtr: number,
    aadPtr: number,
    ciphertextPtr: number,
    outputPtr: number
  ) => number

  // ── XChaCha20-Poly1305 AEAD (nonce 24 bytes) ─────────────────────────
  xchacha20poly1305_encrypt: (
    keyPtr: number,
    noncePtr: number,
    aadPtr: number,
    plaintextPtr: number,
    outputPtr: number
  ) => void
  xchacha20poly1305_decrypt: (
    keyPtr: number,
    noncePtr: number,
    aadPtr: number,
    ciphertextPtr: number,
    outputPtr: number
  ) => number

  // ── Runtime de AssemblyScript ─────────────────────────────────────────
  __setArgumentsLength: (argc: number) => void
}

// ── Asignador de Memoria Personalizado (Marshaller) ─────────────────────────

/**
 * Gestiona la asignación de memoria WebAssembly para el paso de parámetros.
 * Aloja estructuras de memoria temporales para arreglos de bytes (Uint8Arrays)
 * en un bloque de memoria seguro y dedicado (scratchpad).
 *
 * Layout de cabecera GC de AssemblyScript (runtime minimal):
 *   [0..3]   next  (u32) — puntero GC autorreferencial (pinned)
 *   [4..7]   prev  (u32) — puntero GC autorreferencial (pinned)
 *   [8..11]  classId (u32) — ID de clase (1=ArrayBuffer, 2=String, 7=Uint8Array)
 *   [12..15] size  (u32) — tamaño del payload en bytes
 *   [16..]   payload — datos del objeto
 */
class WasmAllocator {
  private memory: WebAssembly.Memory
  private startOffset: number
  private currentOffset: number

  constructor(memory: WebAssembly.Memory) {
    this.memory = memory
    // Crecemos la memoria en 256 páginas (zona de seguridad de 16 MB)
    // Esto asegura que las alocaciones internas de AS durante la llamada
    // no colisionen con nuestro scratchpad en el extremo superior de la memoria.
    memory.grow(256)
    this.startOffset = memory.buffer.byteLength
    memory.grow(8) // Asignamos 512 KB de espacio de scratchpad para parámetros de entrada
    this.currentOffset = this.startOffset
  }

  /** Restablece el puntero del asignador para la próxima secuencia de llamadas */
  reset(): void {
    this.currentOffset = this.startOffset
  }

  private alloc(size: number): number {
    // Alinear a límites de 8 bytes
    const alignedSize = (size + 7) & ~7
    const ptr = this.currentOffset
    this.currentOffset += alignedSize

    // Si excedemos el tamaño de memoria actual, crecemos dinámicamente
    if (this.currentOffset > this.memory.buffer.byteLength) {
      const needed = this.currentOffset - this.memory.buffer.byteLength
      const pages = Math.ceil(needed / 65536)
      this.memory.grow(pages)
    }
    return ptr
  }

  /** Escribe un Uint8Array de JS en la memoria WASM y retorna el puntero de la estructura de AS */
  writeBytes(data: Uint8Array): number {
    // 1. Alojar y escribir el ArrayBuffer subyacente
    // Layout: 16 bytes de cabecera de metadatos de GC + datos del payload
    const bufPtr = this.alloc(16 + data.length)
    let dv = new DataView(this.memory.buffer)
    let heap = new Uint8Array(this.memory.buffer)

    // Punteros next/prev del GC: autoreferenciales para simular un objeto raíz fijado ("pinned")
    dv.setUint32(bufPtr, bufPtr, true) // .next -> self
    dv.setUint32(bufPtr + 4, bufPtr, true) // .prev -> self
    // Class ID de ArrayBuffer = 1
    dv.setUint32(bufPtr + 8, 1, true)
    // Longitud en bytes del ArrayBuffer
    dv.setUint32(bufPtr + 12, data.length, true)
    // Copiar el contenido del payload
    heap.set(data, bufPtr + 16)

    const dataStart = bufPtr + 16

    // 2. Alojar y escribir la cabecera/estructura contenedora de la clase Uint8Array
    // Layout: 16 bytes de cabecera de metadatos de GC + 12 bytes de campos de la estructura
    const structHeaderPtr = this.alloc(16 + 12)
    // Recreamos DataView por si alloc() causó un redimensionamiento de memoria (grow)
    dv = new DataView(this.memory.buffer)

    dv.setUint32(structHeaderPtr, structHeaderPtr, true) // .next -> self
    dv.setUint32(structHeaderPtr + 4, structHeaderPtr, true) // .prev -> self
    // Class ID de Uint8Array = 7
    dv.setUint32(structHeaderPtr + 8, 7, true)
    // Tamaño del payload de la estructura = 12 bytes
    dv.setUint32(structHeaderPtr + 12, 12, true)

    // Campos de la estructura: { buffer: u32, dataStart: u32, byteLength: u32 }
    const structPtr = structHeaderPtr + 16
    dv.setUint32(structPtr, dataStart, true) // .buffer
    dv.setUint32(structPtr + 4, dataStart, true) // .dataStart
    dv.setUint32(structPtr + 8, data.length, true) // .byteLength

    return structPtr
  }

  /** Lee un Uint8Array de AS desde la memoria WASM a un Uint8Array de JS */
  readBytes(arrPtr: number): Uint8Array {
    if (!arrPtr) return new Uint8Array(0)
    const dv = new DataView(this.memory.buffer)
    const dataStart = dv.getUint32(arrPtr + 4, true) // .dataStart (puntero absoluto a los datos crudos)
    const byteLength = dv.getUint32(arrPtr + 8, true) // .byteLength

    const heap = new Uint8Array(this.memory.buffer)
    return heap.slice(dataStart, dataStart + byteLength)
  }
}

// ── Clase Principal ────────────────────────────────────────────────────────

export class ChaChaPolyWasm {
  private exp: AsmExports
  private allocator: WasmAllocator

  private constructor(exp: AsmExports) {
    this.exp = exp
    this.allocator = new WasmAllocator(exp.memory)
  }

  private static instance: ChaChaPolyWasm | null = null

  /**
   * Resuelve automáticamente la ruta por defecto del archivo WASM respecto a este script.
   */
  static getDefaultWasmUrl(): string {
    const baseUrl = "./aead.wasm"
    try {
      return new URL(baseUrl, import.meta.url).href
    } catch {
      return baseUrl
    }
  }

  /**
   * Carga y devuelve de forma automática la instancia singleton de ChaChaPolyWasm.
   */
  static async load(url?: string, imports: WebAssembly.Imports = {}): Promise<ChaChaPolyWasm> {
    if (this.instance) return this.instance
    const targetUrl = url || this.getDefaultWasmUrl()
    this.instance = await this.fromUrl(targetUrl, imports)
    return this.instance
  }

  /**
   * Carga el módulo WASM desde una URL.
   * Utiliza instanciación por streaming si está disponible para máxima velocidad.
   */
  static async fromUrl(url: string, imports: WebAssembly.Imports = {}): Promise<ChaChaPolyWasm> {
    const defaultImports = {
      env: {
        abort(message: number, fileName: number, lineNumber: number, columnNumber: number) {
          console.error("WASM Abort")
        },
        seed() {
          return Math.random()
        }
      }
    }
    const finalImports = {
      ...defaultImports,
      ...imports,
      env: {
        ...defaultImports.env,
        ...((imports.env as Record<string, unknown>) || {})
      }
    }

    let instance: WebAssembly.Instance
    if (typeof WebAssembly.instantiateStreaming === "function") {
      const response = await fetch(url)
      const result = await WebAssembly.instantiateStreaming(response, finalImports)
      instance = result.instance
    } else {
      const response = await fetch(url)
      const buffer = await response.arrayBuffer()
      const result = await WebAssembly.instantiate(buffer, finalImports)
      instance = result.instance
    }
    return new ChaChaPolyWasm(instance.exports as AsmExports)
  }

  /**
   * Carga el módulo WASM desde un búfer en memoria (ideal para Node.js / Bun).
   */
  static async fromBuffer(
    buffer: ArrayBuffer | Uint8Array,
    imports: WebAssembly.Imports = {}
  ): Promise<ChaChaPolyWasm> {
    const defaultImports = {
      env: {
        abort(message: number, fileName: number, lineNumber: number, columnNumber: number) {
          console.error("WASM Abort")
        },
        seed() {
          return Math.random()
        }
      }
    }
    const finalImports = {
      ...defaultImports,
      ...imports,
      env: {
        ...defaultImports.env,
        ...((imports.env as Record<string, unknown>) || {})
      }
    }
    const buf = buffer instanceof Uint8Array ? buffer.buffer : buffer
    const { instance } = await WebAssembly.instantiate(buf, finalImports)
    return new ChaChaPolyWasm(instance.exports as AsmExports)
  }

  // ── Helpers Internos ─────────────────────────────────────────────────────

  /** Debe ejecutarse previo a cualquier llamada a funciones WASM. */
  private call(argc: number): void {
    this.allocator.reset()
    this.exp.__setArgumentsLength(argc)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ── ChaCha20 (Cifrador de flujo — RFC 8439, nonce 12 bytes) ─────────────
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Cifra datos con ChaCha20.
   * @param key    - Clave de 32 bytes
   * @param nonce  - Nonce de 12 bytes
   * @param data   - Datos a cifrar (cualquier longitud)
   * @param counter - Contador inicial (por defecto 0)
   * @returns Datos cifrados (misma longitud que entrada)
   */
  chacha20Encrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, counter: number = 0): Uint8Array {
    this.call(5)
    const output = new Uint8Array(data.length)
    const keyPtr = this.allocator.writeBytes(key)
    const noncePtr = this.allocator.writeBytes(nonce)
    const dataPtr = this.allocator.writeBytes(data)
    const outputPtr = this.allocator.writeBytes(output)
    this.exp.chacha20_encrypt(keyPtr, noncePtr, dataPtr, outputPtr, counter)
    return this.allocator.readBytes(outputPtr)
  }

  /**
   * Descifra datos con ChaCha20 (operación simétrica = idéntica a encrypt).
   */
  chacha20Decrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, counter: number = 0): Uint8Array {
    return this.chacha20Encrypt(key, nonce, data, counter)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ── XChaCha20 (Cifrador de flujo — nonce extendido 24 bytes) ────────────
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Cifra datos con XChaCha20.
   * @param key    - Clave de 32 bytes
   * @param nonce  - Nonce de 24 bytes
   * @param data   - Datos a cifrar (cualquier longitud)
   * @param counter - Contador inicial (por defecto 0)
   * @returns Datos cifrados (misma longitud que entrada)
   */
  xchacha20Encrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, counter: number = 0): Uint8Array {
    this.call(5)
    const output = new Uint8Array(data.length)
    const keyPtr = this.allocator.writeBytes(key)
    const noncePtr = this.allocator.writeBytes(nonce)
    const dataPtr = this.allocator.writeBytes(data)
    const outputPtr = this.allocator.writeBytes(output)
    this.exp.xchacha20_encrypt(keyPtr, noncePtr, dataPtr, outputPtr, counter)
    return this.allocator.readBytes(outputPtr)
  }

  /**
   * Descifra datos con XChaCha20 (operación simétrica = idéntica a encrypt).
   */
  xchacha20Decrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, counter: number = 0): Uint8Array {
    return this.xchacha20Encrypt(key, nonce, data, counter)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ── Poly1305 (MAC de un solo uso — RFC 8439) ────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Genera un tag de autenticación Poly1305 de 16 bytes.
   * @param message - Mensaje a autenticar
   * @param key     - Clave de un solo uso de 32 bytes
   * @returns Tag MAC de 16 bytes
   */
  poly1305Mac(message: Uint8Array, key: Uint8Array): Uint8Array {
    this.call(3)
    const out = new Uint8Array(16)
    const msgPtr = this.allocator.writeBytes(message)
    const keyPtr = this.allocator.writeBytes(key)
    const outPtr = this.allocator.writeBytes(out)
    this.exp.Poly1305_mac(msgPtr, keyPtr, outPtr)
    return this.allocator.readBytes(outPtr)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ── ChaCha20-Poly1305 AEAD (RFC 8439 — nonce 12 bytes) ─────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Cifrado autenticado AEAD con ChaCha20-Poly1305.
   * @param key       - Clave de 32 bytes
   * @param nonce     - Nonce de 12 bytes (DEBE ser único por mensaje)
   * @param plaintext - Datos a cifrar
   * @param aad       - Datos adicionales autenticados (opcional, null si no se usan)
   * @returns ciphertext || tag (longitud = plaintext.length + 16)
   */
  chacha20Poly1305Encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array | null = null
  ): Uint8Array {
    this.call(5)
    const output = new Uint8Array(plaintext.length + 16)
    const keyPtr = this.allocator.writeBytes(key)
    const noncePtr = this.allocator.writeBytes(nonce)
    const aadPtr = aad ? this.allocator.writeBytes(aad) : 0
    const ptPtr = this.allocator.writeBytes(plaintext)
    const outPtr = this.allocator.writeBytes(output)
    this.exp.chacha20poly1305_encrypt(keyPtr, noncePtr, aadPtr, ptPtr, outPtr)
    return this.allocator.readBytes(outPtr)
  }

  /**
   * Descifrado autenticado AEAD con ChaCha20-Poly1305.
   * Verifica la integridad del tag ANTES de descifrar.
   * @param key        - Clave de 32 bytes
   * @param nonce      - Nonce de 12 bytes
   * @param ciphertext - Datos cifrados con tag (ciphertext || tag, longitud ≥ 16)
   * @param aad        - Datos adicionales autenticados (deben coincidir con el cifrado)
   * @returns Plaintext descifrado, o null si la autenticación falla
   */
  chacha20Poly1305Decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad: Uint8Array | null = null
  ): Uint8Array | null {
    if (ciphertext.length < 16) return null
    this.call(5)
    const ptLen = ciphertext.length - 16
    const output = new Uint8Array(ptLen)
    const keyPtr = this.allocator.writeBytes(key)
    const noncePtr = this.allocator.writeBytes(nonce)
    const aadPtr = aad ? this.allocator.writeBytes(aad) : 0
    const ctPtr = this.allocator.writeBytes(ciphertext)
    const outPtr = this.allocator.writeBytes(output)
    const ok = this.exp.chacha20poly1305_decrypt(keyPtr, noncePtr, aadPtr, ctPtr, outPtr)
    if (!ok) return null
    return this.allocator.readBytes(outPtr)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ── XChaCha20-Poly1305 AEAD (nonce extendido 24 bytes) ──────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Cifrado autenticado AEAD con XChaCha20-Poly1305.
   * @param key       - Clave de 32 bytes
   * @param nonce     - Nonce de 24 bytes (seguro para generación aleatoria)
   * @param plaintext - Datos a cifrar
   * @param aad       - Datos adicionales autenticados (opcional)
   * @returns ciphertext || tag (longitud = plaintext.length + 16)
   */
  xchacha20Poly1305Encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array | null = null
  ): Uint8Array {
    this.call(5)
    const output = new Uint8Array(plaintext.length + 16)
    const keyPtr = this.allocator.writeBytes(key)
    const noncePtr = this.allocator.writeBytes(nonce)
    const aadPtr = aad ? this.allocator.writeBytes(aad) : 0
    const ptPtr = this.allocator.writeBytes(plaintext)
    const outPtr = this.allocator.writeBytes(output)
    this.exp.xchacha20poly1305_encrypt(keyPtr, noncePtr, aadPtr, ptPtr, outPtr)
    return this.allocator.readBytes(outPtr)
  }

  /**
   * Descifrado autenticado AEAD con XChaCha20-Poly1305.
   * Verifica la integridad del tag ANTES de descifrar.
   * @param key        - Clave de 32 bytes
   * @param nonce      - Nonce de 24 bytes
   * @param ciphertext - Datos cifrados con tag (ciphertext || tag, longitud ≥ 16)
   * @param aad        - Datos adicionales autenticados (deben coincidir con el cifrado)
   * @returns Plaintext descifrado, o null si la autenticación falla
   */
  xchacha20Poly1305Decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad: Uint8Array | null = null
  ): Uint8Array | null {
    if (ciphertext.length < 16) return null
    this.call(5)
    const ptLen = ciphertext.length - 16
    const output = new Uint8Array(ptLen)
    const keyPtr = this.allocator.writeBytes(key)
    const noncePtr = this.allocator.writeBytes(nonce)
    const aadPtr = aad ? this.allocator.writeBytes(aad) : 0
    const ctPtr = this.allocator.writeBytes(ciphertext)
    const outPtr = this.allocator.writeBytes(output)
    const ok = this.exp.xchacha20poly1305_decrypt(keyPtr, noncePtr, aadPtr, ctPtr, outPtr)
    if (!ok) return null
    return this.allocator.readBytes(outPtr)
  }
}

export { ChaChaPolyWasm as default }
