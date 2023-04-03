---
"@sjc5/crypto": major
---

## update api

This updates the api to take a single object as an argument. This is
more flexible and allows for more options to be added in the future.

Instead of passing a message and key as arguments 0 and 1, you now pass
an object with the message and key as properties.

### New usage:

```ts
import { random_key, encrypt, decrypt } from "@sjc5/crypto"

const message = "hello world"
const key = random_key()

const encrypted_message = encrypt({ message, key })
const decrypted = decrypt({ encrypted_message, key })
```
