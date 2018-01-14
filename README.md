# KeyRing
> An AES-256 encrypted key-value store built on Firebase.

Don't _actually_ use KeyRing for anything sensitive; it's just a proof-of-concept project to demonstrate skills and experience. That said, the data is encrypted and decrypted solely on the client-side using [asmCrypto](https://github.com/vibornoff/asmcrypto.js), so as long as it's being transmitted over HTTPS it ought to be relatively safe.


## Usage

1. Clone the project source
2. Create a new Firebase project
3. Swap out the API keys in the source
4. Enable the most basic email/password authentication mode


### Sample data
```json
{
  "Passwords": {
    "Email": "password"
  }
}
```


### AES-256 encrypted data
```json
"{\"0\":54,\"1\":137,\"2\":34,\"3\":11,\"4\":10,\"5\":190,\"6\":119,\"7\":115,\"8\":195,\"9\":120,\"10\":193,\"11\":253,\"12\":201,\"13\":113,\"14\":206,\"15\":189,\"16\":243,\"17\":168,\"18\":255,\"19\":181,\"20\":86,\"21\":238,\"22\":105,\"23\":3,\"24\":219,\"25\":130,\"26\":177,\"27\":180,\"28\":7,\"29\":131,\"30\":170,\"31\":184,\"32\":244,\"33\":102,\"34\":93,\"35\":102,\"36\":222,\"37\":170,\"38\":46,\"39\":122,\"40\":158,\"41\":204,\"42\":91,\"43\":224,\"44\":213,\"45\":26,\"46\":155,\"47\":74,\"48\":139,\"49\":80}"
```
