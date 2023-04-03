# @sjc5/crypto

Simple, high-level crypto utils in TypeScript.

Has two dependencies:
`tweetnacl` for the underlying crypto and `@stablelib/base64` for base64 encoding utils.

## Usage:

```ts
import { random_key, encrypt, decrypt } = from '@sjc5/crypto'

const message = 'hello world'
const key = random_key()

const encrypted_message = encrypt({ message, key })
const decrypted = decrypt({ encrypted_message, key })
```
