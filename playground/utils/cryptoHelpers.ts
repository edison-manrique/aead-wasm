import {
  AeadVariant,
  ChaCha20,
  ChaCha20Poly1305,
  Poly1305,
  XChaCha20,
  XChaCha20Poly1305,
  bytesToHex,
  concatBytes,
  hexToBytes,
  TAG_BYTES
} from "@aead-wasm"
import type { FileProcessResult } from "../types/crypto"

const HEX_REGEX = /^[0-9a-fA-F]*$/

export function parseStrictHex(input: string, expectedBytes: number, label: string): Uint8Array {
  const clean = input.trim().replace(/\s+/g, "")
  if (!HEX_REGEX.test(clean)) {
    throw new Error(`${label}: solo se permiten caracteres hexadecimales (0-9, a-f).`)
  }
  if (clean.length !== expectedBytes * 2) {
    throw new Error(
      `${label}: requiere ${expectedBytes} bytes (${expectedBytes * 2} caracteres hex, recibidos ${clean.length}).`
    )
  }
  return hexToBytes(clean)
}

export function isValidHexLength(input: string, expectedBytes: number): boolean {
  const clean = input.trim().replace(/\s+/g, "")
  return HEX_REGEX.test(clean) && clean.length === expectedBytes * 2
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B"
  const units = ["B", "KB", "MB", "GB"]
  const exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / 1024 ** exp
  return `${value >= 100 || exp === 0 ? value.toFixed(0) : value.toFixed(2)} ${units[exp]}`
}

export function triggerFileDownload(bytes: Uint8Array, fileName: string): void {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  const blob = new Blob([copy.buffer], { type: "application/octet-stream" })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = fileName
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

const AEAD_CHUNK_SIZE = 1024 * 1024 // 1 MB (tamaño óptimo de PARAM_IN)
const STREAM_CIPHER_CHUNK_SIZE = 512 * 1024 // 512 KB = 8192 bloques exactos de 64 B

function yieldToUi(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0))
}

export async function encryptFileAead(
  variant: AeadVariant,
  file: File,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array | null,
  onProgress?: (ratio: number) => void
): Promise<FileProcessResult> {
  const started = performance.now()
  const Impl = variant === "chacha" ? ChaCha20Poly1305 : XChaCha20Poly1305
  const stream = Impl.createEncryptStream(key, nonce, aad)
  const outChunks: Uint8Array[] = []
  const total = file.size

  try {
    let offset = 0
    while (offset < total) {
      const end = Math.min(offset + AEAD_CHUNK_SIZE, total)
      const sliceBuf = await file.slice(offset, end).arrayBuffer()
      outChunks.push(stream.update(new Uint8Array(sliceBuf)))
      offset = end
      onProgress?.(total > 0 ? offset / total : 1)
      if (offset < total) await yieldToUi()
    }
    const tag = stream.final()
    outChunks.push(tag)
    const resultBytes = concatBytes(...outChunks)
    const elapsedMs = Math.max(0.01, performance.now() - started)
    const throughputMBs = total / (1024 * 1024) / (elapsedMs / 1000)
    onProgress?.(1)

    return {
      bytes: resultBytes,
      fileName: `${file.name}.enc`,
      elapsedMs,
      throughputMBs,
      tagHex: bytesToHex(tag)
    }
  } catch (err) {
    stream.free()
    throw err
  }
}

export async function decryptFileAead(
  variant: AeadVariant,
  file: File,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array | null,
  onProgress?: (ratio: number) => void
): Promise<FileProcessResult> {
  if (file.size < TAG_BYTES) {
    throw new Error(`El archivo cifrado debe tener al menos ${TAG_BYTES} bytes para contener el tag Poly1305.`)
  }

  const started = performance.now()
  const Impl = variant === "chacha" ? ChaCha20Poly1305 : XChaCha20Poly1305
  const stream = Impl.createDecryptStream(key, nonce, aad)
  const ctLen = file.size - TAG_BYTES
  const outChunks: Uint8Array[] = []

  try {
    let offset = 0
    while (offset < ctLen) {
      const end = Math.min(offset + AEAD_CHUNK_SIZE, ctLen)
      const sliceBuf = await file.slice(offset, end).arrayBuffer()
      outChunks.push(stream.update(new Uint8Array(sliceBuf)))
      offset = end
      onProgress?.(ctLen > 0 ? offset / ctLen : 1)
      if (offset < ctLen) await yieldToUi()
    }

    const tagBuf = await file.slice(ctLen, file.size).arrayBuffer()
    const tag = new Uint8Array(tagBuf)
    const valid = stream.final(tag)

    if (!valid) {
      throw new Error(
        "Tag inválido: el archivo fue modificado o la clave, el nonce o el AAD no coinciden. Plaintext descartado."
      )
    }

    const resultBytes = concatBytes(...outChunks)
    const elapsedMs = Math.max(0.01, performance.now() - started)
    const throughputMBs = ctLen / (1024 * 1024) / (elapsedMs / 1000)
    onProgress?.(1)

    const outName = file.name.endsWith(".enc") ? file.name.slice(0, -4) || "archivo.dec" : `${file.name}.dec`

    return {
      bytes: resultBytes,
      fileName: outName,
      elapsedMs,
      throughputMBs,
      tagHex: bytesToHex(tag),
      verified: true
    }
  } catch (err) {
    stream.free()
    throw err
  }
}

export async function processFileStreamCipher(
  variant: "chacha" | "xchacha",
  mode: "encrypt" | "decrypt",
  file: File,
  key: Uint8Array,
  nonce: Uint8Array,
  initialCounter: number,
  onProgress?: (ratio: number) => void
): Promise<FileProcessResult> {
  const started = performance.now()
  const Impl = variant === "chacha" ? ChaCha20 : XChaCha20
  const outChunks: Uint8Array[] = []
  const total = file.size
  let counter = initialCounter
  let offset = 0

  while (offset < total) {
    const end = Math.min(offset + STREAM_CIPHER_CHUNK_SIZE, total)
    const sliceBuf = await file.slice(offset, end).arrayBuffer()
    const chunk = new Uint8Array(sliceBuf)
    outChunks.push(Impl.encrypt(key, nonce, chunk, counter))
    counter += Math.ceil(chunk.length / 64)
    offset = end
    onProgress?.(total > 0 ? offset / total : 1)
    if (offset < total) await yieldToUi()
  }

  const resultBytes = concatBytes(...outChunks)
  const elapsedMs = Math.max(0.01, performance.now() - started)
  const throughputMBs = total / (1024 * 1024) / (elapsedMs / 1000)
  onProgress?.(1)

  let fileName: string
  if (mode === "encrypt") {
    fileName = `${file.name}.enc`
  } else {
    fileName = file.name.endsWith(".enc") ? file.name.slice(0, -4) || "archivo.dec" : `${file.name}.dec`
  }

  return {
    bytes: resultBytes,
    fileName,
    elapsedMs,
    throughputMBs
  }
}

export async function computeFilePoly1305(
  file: File,
  key: Uint8Array
): Promise<{ tag: Uint8Array; elapsedMs: number }> {
  const started = performance.now()
  const buffer = await file.arrayBuffer()
  const tag = Poly1305.mac(key, new Uint8Array(buffer))
  const elapsedMs = Math.max(0.01, performance.now() - started)
  return { tag, elapsedMs }
}
