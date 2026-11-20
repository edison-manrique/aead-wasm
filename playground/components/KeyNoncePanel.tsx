import { createSignal, Show } from "solid-js"
import { Copy, Check, Dices } from "lucide-solid"
import { isValidHexLength } from "../utils/cryptoHelpers"
import styles from "./KeyNoncePanel.module.css"

interface KeyNoncePanelProps {
  keyHex: string
  onKeyChange: (val: string) => void
  onGenerateKey: () => void
  nonceHex?: string
  nonceBytes?: number
  onNonceChange?: (val: string) => void
  onGenerateNonce?: () => void
}

export function KeyNoncePanel(props: KeyNoncePanelProps) {
  const [copiedKey, setCopiedKey] = createSignal(false)
  const [copiedNonce, setCopiedNonce] = createSignal(false)

  const keyLen = () => props.keyHex.trim().replace(/\s+/g, "").length
  const keyValid = () => isValidHexLength(props.keyHex, 32)

  const nonceLen = () => (props.nonceHex ?? "").trim().replace(/\s+/g, "").length
  const nonceValid = () => (props.nonceBytes ? isValidHexLength(props.nonceHex ?? "", props.nonceBytes) : true)

  const copyValue = async (text: string, which: "key" | "nonce") => {
    try {
      await navigator.clipboard.writeText(text)
      if (which === "key") {
        setCopiedKey(true)
        setTimeout(() => setCopiedKey(false), 1400)
      } else {
        setCopiedNonce(true)
        setTimeout(() => setCopiedNonce(false), 1400)
      }
    } catch {
      // Clipboard no disponible
    }
  }

  return (
    <div class={styles.grid}>
      <div class={styles.field}>
        <div class={styles.labelRow}>
          <label class={styles.label} for="crypto-key-input">
            Clave secreta (256-bit hex)
          </label>
          <span
            class={`${styles.counter} ${
              keyLen() === 0 ? "" : keyValid() ? styles.counterOk : styles.counterErr
            }`}
          >
            {keyLen()} / 64 hex
          </span>
        </div>
        <div class={styles.inputGroup}>
          <input
            id="crypto-key-input"
            type="text"
            class={`${styles.input} ${keyLen() > 0 && !keyValid() ? styles.inputInvalid : ""}`}
            value={props.keyHex}
            onInput={(e) => props.onKeyChange(e.currentTarget.value)}
            placeholder="64 caracteres hexadecimales..."
            spellcheck={false}
            autocomplete="off"
          />
          <button
            type="button"
            class={styles.iconBtn}
            onClick={() => copyValue(props.keyHex, "key")}
            title="Copiar clave"
          >
            <Show when={copiedKey()} fallback={<Copy size={13} />}>
              <Check size={13} />
            </Show>
          </button>
          <button
            type="button"
            class={styles.iconBtn}
            onClick={props.onGenerateKey}
            title="Generar clave aleatoria (CSPRNG)"
          >
            <Dices size={14} />
            <span>Generar</span>
          </button>
        </div>
      </div>

      <Show when={props.nonceBytes !== undefined && props.onNonceChange && props.onGenerateNonce}>
        <div class={styles.field}>
          <div class={styles.labelRow}>
            <label class={styles.label} for="crypto-nonce-input">
              Nonce ({props.nonceBytes! * 8}-bit hex)
            </label>
            <span
              class={`${styles.counter} ${
                nonceLen() === 0 ? "" : nonceValid() ? styles.counterOk : styles.counterErr
              }`}
            >
              {nonceLen()} / {props.nonceBytes! * 2} hex
            </span>
          </div>
          <div class={styles.inputGroup}>
            <input
              id="crypto-nonce-input"
              type="text"
              class={`${styles.input} ${nonceLen() > 0 && !nonceValid() ? styles.inputInvalid : ""}`}
              value={props.nonceHex ?? ""}
              onInput={(e) => props.onNonceChange?.(e.currentTarget.value)}
              placeholder={`${props.nonceBytes! * 2} caracteres hexadecimales...`}
              spellcheck={false}
              autocomplete="off"
            />
            <button
              type="button"
              class={styles.iconBtn}
              onClick={() => copyValue(props.nonceHex ?? "", "nonce")}
              title="Copiar nonce"
            >
              <Show when={copiedNonce()} fallback={<Copy size={13} />}>
                <Check size={13} />
              </Show>
            </button>
            <button
              type="button"
              class={styles.iconBtn}
              onClick={() => props.onGenerateNonce?.()}
              title="Generar nonce aleatorio (CSPRNG)"
            >
              <Dices size={14} />
              <span>Generar</span>
            </button>
          </div>
        </div>
      </Show>
    </div>
  )
}
