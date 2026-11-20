import { createSignal, Show } from "solid-js"
import { Copy, Check } from "lucide-solid"
import styles from "./OutputBox.module.css"

interface OutputBoxProps {
  label: string
  value: string | null
  placeholder?: string
  status?: "idle" | "ok" | "err" | "warn"
  meta?: string
}

export function OutputBox(props: OutputBoxProps) {
  const [copied, setCopied] = createSignal(false)

  const statusClass = () => {
    switch (props.status) {
      case "ok":
        return styles.boxOk
      case "err":
        return styles.boxErr
      case "warn":
        return styles.boxWarn
      default:
        return ""
    }
  }

  const handleCopy = async () => {
    if (!props.value) return
    try {
      await navigator.clipboard.writeText(props.value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    } catch {
      // Clipboard no disponible
    }
  }

  return (
    <div class={styles.wrapper}>
      <div class={styles.labelRow}>
        <span class={styles.label}>{props.label}</span>
        <Show when={props.meta}>
          <span class={styles.meta}>{props.meta}</span>
        </Show>
      </div>
      <div class={`${styles.box} ${statusClass()}`}>
        <div class={styles.content}>
          <Show
            when={props.value !== null && props.value !== ""}
            fallback={<span class={styles.placeholder}>{props.placeholder ?? "—"}</span>}
          >
            {props.value}
          </Show>
        </div>
        <Show when={props.value && props.status !== "err"}>
          <button type="button" class={styles.copyBtn} onClick={handleCopy}>
            <Show when={copied()} fallback={<Copy size={11} />}>
              <Check size={11} />
            </Show>
            <span>{copied() ? "Copiado" : "Copiar"}</span>
          </button>
        </Show>
      </div>
    </div>
  )
}
