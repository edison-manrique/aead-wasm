import { hexToBytes, bytesToHex, isSameBytes } from "../../lib"
import { ChaCha20 } from ".."
import { LocalArena } from "../../lib/LocalArena"
import { stablelib_chacha20_vectors } from "./stablelib_chacha20"

export function test_chacha20_basic(): bool {
  let key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  let nonce = hexToBytes("000000000000004a00000000")
  let plaintext = hexToBytes(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
  )

  let marker = LocalArena.save()
  let output = new Uint8Array(plaintext.length)
  let chacha = ChaCha20.create(key, nonce, 1)
  chacha.encrypt(plaintext, output)
  LocalArena.restore(marker)

  let expected =
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"

  let hex = bytesToHex(output)
  let ok = hex == expected

  if (ok) {
    marker = LocalArena.save()
    let decrypted = new Uint8Array(output.length)
    let chacha2 = ChaCha20.create(key, nonce, 1)
    chacha2.decrypt(output, decrypted)
    LocalArena.restore(marker)

    if (!isSameBytes(decrypted, plaintext)) ok = false
  }

  return ok
}

export function test_chacha20_stablelib_vectors(): bool {
  for (let i = 0; i < stablelib_chacha20_vectors.length; i++) {
    const v = stablelib_chacha20_vectors[i]

    let key = hexToBytes(v.key)
    let nonce_raw = hexToBytes(v.nonce)
    let nonce: Uint8Array
    if (nonce_raw.length == 8) {
      // Pad 8-byte nonce to 12 bytes
      nonce = new Uint8Array(12)
      for (let j = 0; j < 8; j++) nonce[j + 4] = nonce_raw[j]
    } else {
      nonce = nonce_raw
    }

    let plaintext = new Uint8Array(v.stream.length / 2)
    plaintext.fill(0)
    let output = new Uint8Array(plaintext.length)

    let marker = LocalArena.save()
    let chacha = ChaCha20.create(key, nonce, 0)
    chacha.encrypt(plaintext, output)
    LocalArena.restore(marker)

    let hex = bytesToHex(output)
    let ok = hex == v.stream

    if (!ok) {
      trace("FAIL AT INDEX", 1, i)
      return false
    }
  }
  return true
}
