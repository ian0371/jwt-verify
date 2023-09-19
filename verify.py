import json, jwt, re, time
from typing import TypedDict, OrderedDict
from Crypto.Hash import SHA256
from base64 import urlsafe_b64decode, urlsafe_b64encode
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

ISSUER = "http://server.example.com"
AUD = "s6BhdRkqt3"
key = RSA.import_key(open("test_key.pem").read())
PUBLIC_KEY = key.publickey()
USER_OP_HASH = "0x8d9abb9b140bd3c63db2ce7ee3171ab1c2284fd905ad13156df1069a1918b2b3"
MASK_FIELD_LENGTH = 8


class PrivateInput(TypedDict):
    sub: bytes


class PublicInput(TypedDict):
    header: bytes
    masked_decoded_payload: bytes
    msg_hash: SHA256.SHA256Hash
    sub_hash: SHA256.SHA256Hash


def mask_jwt_token(jwt_token: str, mask_fields) -> str:
    header, payload, sig = jwt_token.split(".")
    id_token = b64decode(payload)
    masked_id_token = id_token
    for field in mask_fields:
        pat = '"{}":".+?",'.format(field).encode()
        replace = '"{}":"{}",'.format(field, "*" * MASK_FIELD_LENGTH).encode()
        masked_id_token = re.sub(pat, replace, id_token)
    return header + "." + urlsafe_b64encode(masked_id_token).decode() + "." + sig


def b64decode(s: str) -> bytes:
    return urlsafe_b64decode(s + "=" * divmod(len(s), 4)[1])


# def verify_jwt_decode(encoded_token: str, userOpHash):
#     id_token = jwt.decode(
#         encoded_token,
#         PUBLIC_KEY.export_key(),
#         algorithms=["RS256"],
#         audience=AUD,
#     )
#     assert id_token["nonce"] == userOpHash
#     assert id_token["iss"] == ISSUER
#     assert id_token["aud"] == AUD
#     assert id_token["iat"] < time.time() < id_token["exp"]


def verify_sig(hash: SHA256.SHA256Hash, sig: bytes):
    pkcs1_15.new(PUBLIC_KEY).verify(hash, sig)


def verify_payload(payload, userOpHash):
    id_token = eval(b64decode(payload))
    assert id_token["nonce"] == userOpHash
    assert id_token["iss"] == ISSUER
    assert id_token["aud"] == AUD
    assert id_token["iat"] < time.time() < id_token["exp"]


def verify_nonzk(jwt_token: str, userOpHash: str):
    # check sig: raises error on fail
    h = calc_msg_hash(jwt_token)
    _, payload, signature = jwt_token.split(".")
    verify_sig(h, b64decode(signature))

    # check id_token
    verify_payload(payload, userOpHash)


def verify_zk(
    jwt_masked_token: str,
    private: PrivateInput,
    public: PublicInput,
    userOpHash: str,
):
    print("*********************************************************")
    print("* ZK private input")
    print("  * sub:", private["sub"].decode())
    print("* ZK public input")
    print("  * header:", public["header"].decode())
    print("  * masked_decoded_payload:", public["masked_decoded_payload"].decode())
    print("  * msg_hash:", public["msg_hash"].hexdigest())
    print("  * sub_hash:", public["sub_hash"].hexdigest())
    print("*********************************************************")

    _, masked_payload, signature = jwt_masked_token.split(".")

    # check if sender knows "sub"
    zk_circuit(private, public)

    # check sig: raises error on fail
    verify_sig(public["msg_hash"], b64decode(signature))

    # check id_token
    verify_payload(masked_payload, userOpHash)


def zk_circuit(private: PrivateInput, public: PublicInput):
    """
    template Example () {
        signal input sub;
        signal input header, masked_decoded_payload, msg_hash, sub_hash;
        signal output out;

        // 1. check sub_hash
        // assert hash(sub) == sub_hash

        // 2. check msg_hash
        // id_token = masked_id_token.copy()
        // find "sub" field in id_token, and replace
        // payload = base64urlencode(id_token)
        // msg = concat(header, ".", payload)
        // assert hash(msg) == msg_hash
    }
    """
    assert SHA256.new(private["sub"]).digest() == public["sub_hash"].digest()

    id_token = public["masked_decoded_payload"][:]
    target_idx = id_token.find(b"*" * MASK_FIELD_LENGTH)
    id_token = (
        id_token[:target_idx]
        + private["sub"]
        + id_token[target_idx + MASK_FIELD_LENGTH :]
    )
    payload = urlsafe_b64encode(id_token)
    msg = public["header"] + b"." + payload
    assert SHA256.new(msg).digest() == public["msg_hash"].digest()


def calc_msg_hash(jwt_token: str) -> SHA256.SHA256Hash:
    header, payload, _ = jwt_token.split(".")
    msg = header.encode() + b"." + payload.encode()
    return SHA256.new(msg)


def calc_sub_hash(jwt_token: str) -> SHA256.SHA256Hash:
    _, payload, _ = jwt_token.split(".")
    decoded_payload = eval(b64decode(payload))
    return SHA256.new(decoded_payload["sub"].encode())


def main():
    id_token = eval(open("id_token.json").read())
    jwt_token = jwt.encode(id_token, key.export_key(), algorithm="RS256")
    # verify_nonzk(jwt_token, USER_OP_HASH)
    # print("verify_nonzk: Pass")

    masked_jwt_token = mask_jwt_token(jwt_token, ["sub"])
    print("* JWT token decoded")
    print("  * header:", b64decode(jwt_token.split(".")[0]).decode())
    print("  * payload:", b64decode(jwt_token.split(".")[1]).decode())
    print("  * signature:", b64decode(jwt_token.split(".")[2]))
    print("* Masked JWT token decoded")
    print("  * header:", b64decode(masked_jwt_token.split(".")[0]).decode())
    print("  * masked payload:", b64decode(masked_jwt_token.split(".")[1]).decode())
    print("  * signature:", b64decode(masked_jwt_token.split(".")[2]))

    verify_zk(
        masked_jwt_token,
        {"sub": id_token["sub"].encode()},
        {
            "header": jwt_token.split(".")[0].encode(),
            "masked_decoded_payload": b64decode(masked_jwt_token.split(".")[1]),
            "msg_hash": calc_msg_hash(jwt_token),
            "sub_hash": calc_sub_hash(jwt_token),
        },
        USER_OP_HASH,
    )
    print("verify_zk: Pass")


if __name__ == "__main__":
    main()
