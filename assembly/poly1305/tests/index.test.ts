import { hexToBytes, bytesToHex } from "../../lib"
import { Poly1305 } from ".."
import { stablelib_poly1305_vectors } from "./stablelib_poly1305"

export function test_poly1305_basic_vectors(): bool {
  let all_passed = true
  let tag = new Uint8Array(16)

  for (let i = 0; i < stablelib_poly1305_vectors.length; i++) {
    const v = stablelib_poly1305_vectors[i]
    let data = hexToBytes(v.data)
    let key = hexToBytes(v.key)
    let expected = v.mac

    Poly1305.mac(data, key, tag)

    let result = bytesToHex(tag)

    if (result != expected) {
      trace("FAIL AT INDEX", 1, i)
      all_passed = false
    }
  }
  return all_passed
}
