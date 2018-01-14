# KeyRing
> An AES-256 encrypted key-value store built on Firebase.

Don't _actually_ use KeyRing for anything sensitive; it's just a proof-of-concept project to demonstrate skills and experience. That said, the data is encrypted and decrypted solely on the client-side using [asmCrypto](https://github.com/vibornoff/asmcrypto.js), so as long as it's being transmitted over HTTPS it ought to be relatively safe.