---
"@sjc5/crypto": major
---

## Update encrypt / decrypt APIs

This updates the encrypt and decrypt APIs to take a single object as an argument.

This is:

- more flexible
- less error-prone
- more explicit

Instead of passing a message and key as arguments 0 and 1 as in version 1.0.0, you now pass an object with the message and key as properties (or encrypted_message and key as properties, in the case of the decrypt function).

### New usage:

```ts
import { random_key, encrypt, decrypt } from "@sjc5/crypto"

const message = "hello world"
const key = random_key()

const encrypted_message = encrypt({ message, key })
const decrypted = decrypt({ encrypted_message, key })
```
