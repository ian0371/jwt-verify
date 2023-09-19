# jwt-verify

## How to run

```bash
pip install -r requirements.txt
python verify.py
```

Output

```
* JWT token decoded
  * header: {"alg":"RS256","typ":"JWT"}
  * payload: {"iss":"http://server.example.com","sub":"248289761001","aud":"s6BhdRkqt3","nonce":"0x8d9abb9b140bd3c63db2ce7ee3171ab1c2284fd905ad13156df1069a1918b2b3","iat":1311281970,"exp":1726640433,"name":"Jane Doe","given_name":"Jane","family_name":"Doe","gender":"female","birthdate":"0000-10-31","email":"janedoe@example.com","picture":"http://example.com/janedoe/me.jpg"}
  * signature: b'6\xaf\xd1\xc5\xe3[t\x85\x0f\xbaU\x8dP\x8f\x1f\xcb\xe1\xbcE\x01\xceST]x_\x08\xa5\xf3ma6\xd3\xa9\x0f\x95\x1b\x0e\x9f\x88\xf2,e*v\xe6\xfd\x01\x9bZ\xfd%5\x05C\xb0o\xe3S\xc8T\x8e\xed3\xc2\x10F?\xba \xbf\xcaB\xbe\xedG\x85\xb7\xacE\xab^\xde\xd1\xa5u\xe2\x8b\xdc@\x0e\x97\xed\xfb\xbc\xd7\xdd\xf94*Y\xeaU\xa4-\x17\xb5A\x9a\x9c\xb5_\xb3\xeb\xa3\xd7\x06\x87\xe4\xf8\xa7&\x90\x12rt\n\xd0\xa2\x9f\xfb?n\xdc\xcb\xb6\x1e\x991\x95<\x9ff`\x08A\xa5J\x13\xe6T\x0csk\xe5\xebpE&H/\x8d\x83\x88\xa3\x01\x00\x07QB|4\x81\xff^\xd7\x02\xe8\x8dv\n\x068\xfb~h\x8a\x14\x90\xda\x05Kv\xd4.\xf9d\xddZ\x05R\x18\xf1\xe0/]\xe7\xbc:\x1f\x83\xb2yW"%\xfd#3\xb9\x13}\x88\xcd\xfc\x91\xdd\xa4\xc2B\xb7\x07\xe6\xabs\x99D\xf6\x81\xc3q\x11F2\xd6?\xd79\xcf\x06\x9e\x90\x19\xab\xda\xcf'
* Masked JWT token decoded
  * header: {"alg":"RS256","typ":"JWT"}
  * masked payload: {"iss":"http://server.example.com","sub":"********","aud":"s6BhdRkqt3","nonce":"0x8d9abb9b140bd3c63db2ce7ee3171ab1c2284fd905ad13156df1069a1918b2b3","iat":1311281970,"exp":1726640433,"name":"Jane Doe","given_name":"Jane","family_name":"Doe","gender":"female","birthdate":"0000-10-31","email":"janedoe@example.com","picture":"http://example.com/janedoe/me.jpg"}
  * signature: b'6\xaf\xd1\xc5\xe3[t\x85\x0f\xbaU\x8dP\x8f\x1f\xcb\xe1\xbcE\x01\xceST]x_\x08\xa5\xf3ma6\xd3\xa9\x0f\x95\x1b\x0e\x9f\x88\xf2,e*v\xe6\xfd\x01\x9bZ\xfd%5\x05C\xb0o\xe3S\xc8T\x8e\xed3\xc2\x10F?\xba \xbf\xcaB\xbe\xedG\x85\xb7\xacE\xab^\xde\xd1\xa5u\xe2\x8b\xdc@\x0e\x97\xed\xfb\xbc\xd7\xdd\xf94*Y\xeaU\xa4-\x17\xb5A\x9a\x9c\xb5_\xb3\xeb\xa3\xd7\x06\x87\xe4\xf8\xa7&\x90\x12rt\n\xd0\xa2\x9f\xfb?n\xdc\xcb\xb6\x1e\x991\x95<\x9ff`\x08A\xa5J\x13\xe6T\x0csk\xe5\xebpE&H/\x8d\x83\x88\xa3\x01\x00\x07QB|4\x81\xff^\xd7\x02\xe8\x8dv\n\x068\xfb~h\x8a\x14\x90\xda\x05Kv\xd4.\xf9d\xddZ\x05R\x18\xf1\xe0/]\xe7\xbc:\x1f\x83\xb2yW"%\xfd#3\xb9\x13}\x88\xcd\xfc\x91\xdd\xa4\xc2B\xb7\x07\xe6\xabs\x99D\xf6\x81\xc3q\x11F2\xd6?\xd79\xcf\x06\x9e\x90\x19\xab\xda\xcf'
*********************************************************
* ZK private input
  * sub: 248289761001
* ZK public input
  * header: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
  * masked_decoded_payload: {"iss":"http://server.example.com","sub":"********","aud":"s6BhdRkqt3","nonce":"0x8d9abb9b140bd3c63db2ce7ee3171ab1c2284fd905ad13156df1069a1918b2b3","iat":1311281970,"exp":1726640433,"name":"Jane Doe","given_name":"Jane","family_name":"Doe","gender":"female","birthdate":"0000-10-31","email":"janedoe@example.com","picture":"http://example.com/janedoe/me.jpg"}
  * msg_hash: dfb92c059c97e04892f6513cc9859798a5c04b1cae1ec9a384e6ff1d9d6581e2
  * sub_hash: 4ace913314955c59729619db3eb77a3269cbfadb9f60e878c222d1e18f0e8c0f
*********************************************************
verify_zk: Pass
```
