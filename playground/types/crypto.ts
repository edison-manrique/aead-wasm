export type AlgoPageId =
  | "chacha20-poly1305"
  | "xchacha20-poly1305"
  | "chacha20"
  | "xchacha20"
  | "poly1305"
  | "security"
  | "docs"

export type InputMode = "text" | "file"

export interface AlgoPageMeta {
  id: AlgoPageId
  name: string
  category: "AEAD" | "Stream Cipher" | "MAC" | "Docs"
  standard: string
  keyBytes: number | null
  nonceBytes: number | null
  tagBytes: number | null
  description: string
  supportsStreamingFiles: boolean
}

export const ALGO_PAGES: readonly AlgoPageMeta[] = [
  {
    id: "chacha20-poly1305",
    name: "ChaCha20-Poly1305",
    category: "AEAD",
    standard: "RFC 8439",
    keyBytes: 32,
    nonceBytes: 12,
    tagBytes: 16,
    description:
      "Cifrado autenticado con datos asociados (AEAD). Garantiza confidencialidad e integridad mediante verificación constant-time del tag.",
    supportsStreamingFiles: true
  },
  {
    id: "xchacha20-poly1305",
    name: "XChaCha20-Poly1305",
    category: "AEAD",
    standard: "HChaCha20 + RFC 8439",
    keyBytes: 32,
    nonceBytes: 24,
    tagBytes: 16,
    description:
      "Variante AEAD con nonce extendido de 192 bits ideal para generación aleatoria segura sin riesgo práctico de colisión.",
    supportsStreamingFiles: true
  },
  {
    id: "chacha20",
    name: "ChaCha20",
    category: "Stream Cipher",
    standard: "RFC 8439 §2.4",
    keyBytes: 32,
    nonceBytes: 12,
    tagBytes: null,
    description:
      "Cifrador de flujo puro basado en XOR con keystream de 64 bytes por bloque. Simétrico para cifrar y descifrar.",
    supportsStreamingFiles: true
  },
  {
    id: "xchacha20",
    name: "XChaCha20",
    category: "Stream Cipher",
    standard: "HChaCha20 + ChaCha20",
    keyBytes: 32,
    nonceBytes: 24,
    tagBytes: null,
    description:
      "Cifrador de flujo con nonce extendido de 24 bytes derivado mediante HChaCha20 antes del flujo principal.",
    supportsStreamingFiles: true
  },
  {
    id: "poly1305",
    name: "Poly1305",
    category: "MAC",
    standard: "RFC 8439 §2.5",
    keyBytes: 32,
    nonceBytes: null,
    tagBytes: 16,
    description:
      "Código de autenticación de mensajes (MAC) de un solo uso por clave. Produce un tag de 16 bytes sin cifrar el contenido.",
    supportsStreamingFiles: false
  },
  {
    id: "security",
    name: "Seguridad",
    category: "Docs",
    standard: "Modelo de amenazas",
    keyBytes: null,
    nonceBytes: null,
    tagBytes: null,
    description:
      "Garantías criptográficas, lock de Arena contra sobreescrituras (ST/MT), requisitos COOP/COEP y mitigaciones en WebAssembly.",
    supportsStreamingFiles: false
  },
  {
    id: "docs",
    name: "Documentación",
    category: "Docs",
    standard: "Guía ST & MT v1.1",
    keyBytes: null,
    nonceBytes: null,
    tagBytes: null,
    description:
      "Referencia de integración TypeScript/WASM: inicialización Single-Thread y Multithread, Workers, Arena Lock, AEAD y streaming.",
    supportsStreamingFiles: false
  }
] as const

export interface FileProcessResult {
  bytes: Uint8Array
  fileName: string
  elapsedMs: number
  throughputMBs: number
  tagHex?: string
  verified?: boolean
}
