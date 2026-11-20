import { FileText, HardDrive } from "lucide-solid"
import type { InputMode } from "../types/crypto"
import styles from "./ModeSwitch.module.css"

interface ModeSwitchProps {
  mode: InputMode
  onChange: (mode: InputMode) => void
}

export function ModeSwitch(props: ModeSwitchProps) {
  return (
    <div class={styles.root} role="tablist" aria-label="Modo de operación">
      <button
        type="button"
        role="tab"
        aria-selected={props.mode === "text"}
        class={`${styles.option} ${props.mode === "text" ? styles.optionActive : ""}`}
        onClick={() => props.onChange("text")}
      >
        <FileText size={14} />
        <span>Texto / Hex</span>
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={props.mode === "file"}
        class={`${styles.option} ${props.mode === "file" ? styles.optionActive : ""}`}
        onClick={() => props.onChange("file")}
      >
        <HardDrive size={14} />
        <span>Archivos</span>
      </button>
    </div>
  )
}
