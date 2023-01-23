import umbral_pre
from coincurve import PublicKey
from sha3 import keccak_256



# Key Generation (on Alice's side)
alice_sk = umbral_pre.SecretKey.random()
alice_sk_bytes = alice_sk.to_secret_bytes()

alice_pk = alice_sk.public_key()
signing_sk = umbral_pre.SecretKey.random()
signer = umbral_pre.Signer(signing_sk)
verifying_pk = signing_sk.public_key()

#convert alice pub key into address (needed for evaluation evidence)
public_key = PublicKey.from_valid_secret(alice_sk_bytes).format(compressed=False)[1:]
alice_addr = keccak_256(public_key).digest()[-20:]

# Key Generation (on Bob's side)
bob_sk = umbral_pre.SecretKey.random()
bob_pk = bob_sk.public_key()

# Now let's encrypt data with Alice's public key.

plaintext = b"peace at dawn"
capsule, ciphertext = umbral_pre.encrypt(alice_pk, plaintext)

# When Alice wants to grant Bob access to open her encrypted
# messages, she creates re-encryption key fragments,
# or "kfrags", which are then sent to `shares` proxies or Ursulas.

shares = 2 # how many fragments to create
threshold = 1 # how many should be enough to decrypt

# Split Re-Encryption Key Generation (aka Delegation)
verified_kfrags = umbral_pre.generate_kfrags(
    alice_sk, bob_pk, signer, threshold, shares,
    True, # add the delegating key (alice_pk) to the signature
    True, # add the receiving key (bob_pk) to the signature
)

# Bob asks several Ursulas to re-encrypt the capsule
# so he can open it.
# Each Ursula performs re-encryption on the capsule
# using the kfrag provided by Alice, thus obtaining
# a "capsule fragment", or cfrag.

# Bob collects the resulting cfrags from several Ursulas.
# Bob must gather at least `threshold` cfrags
# in order to open the capsule.

# Simulate network transfer
kfrag0 = umbral_pre.KeyFrag.from_bytes(bytes(verified_kfrags[0]))
# kfrag1 = umbral_pre.KeyFrag.from_bytes(bytes(verified_kfrags[1]))

# Ursulas must check that the received kfrags
# are valid and perform the reencryption.

# Ursula 0
verified_kfrag0 = kfrag0.verify(verifying_pk, alice_pk, bob_pk)
verified_cfrag0 = umbral_pre.reencrypt(capsule, verified_kfrag0)

# Ursula 1
# verified_kfrag1 = kfrag1.verify(verifying_pk, alice_pk, bob_pk)
# verified_cfrag1 = umbral_pre.reencrypt(capsule, verified_kfrag1)

# ...

# Simulate network transfer
cfrag0 = umbral_pre.CapsuleFrag.from_bytes(bytes(verified_cfrag0))
# cfrag1 = umbral_pre.CapsuleFrag.from_bytes(bytes(verified_cfrag1))

# Finally, Bob opens the capsule by using at least `threshold` cfrags,
# and then decrypts the re-encrypted ciphertext.

# Bob must check that cfrags are valid
verified_cfrag0 = cfrag0.verify(capsule, verifying_pk, alice_pk, bob_pk)
# verified_cfrag1 = cfrag1.verify(capsule, verifying_pk, alice_pk, bob_pk)

# Decryption by Bob
plaintext_bob = umbral_pre.decrypt_reencrypted(
    bob_sk, alice_pk, capsule, [verified_cfrag0], ciphertext)
assert plaintext_bob == plaintext

evidence = umbral_pre.ReencryptionEvidence(capsule, verified_cfrag0, verifying_pk, alice_pk, bob_pk)

pointEyCoord = evidence.e.coordinates[1]
pointEZxCoord = evidence.ez.coordinates[0]
pointEZyCoord = evidence.ez.coordinates[1]
pointE1yCoord = evidence.e1.coordinates[1]
pointE1HxCoord = evidence.e1h.coordinates[0]
pointE1HyCoord = evidence.e1h.coordinates[1]
pointE2yCoord = evidence.e2.coordinates[1]
pointVyCoord = evidence.v.coordinates[1]
pointVZxCoord = evidence.vz.coordinates[0]
pointVZyCoord = evidence.vz.coordinates[1]
pointV1yCoord = evidence.v1.coordinates[1]
pointV1HxCoord = evidence.v1h.coordinates[0]
pointV1HyCoord = evidence.v1h.coordinates[1]
pointV2yCoord = evidence.v2.coordinates[1]
pointUZxCoord = evidence.uz.coordinates[0]
pointUZyCoord = evidence.uz.coordinates[1]
pointU1yCoord = evidence.u1.coordinates[1]
pointU1HxCoord = evidence.u1h.coordinates[0]
pointU1HyCoord = evidence.u1h.coordinates[1]
pointU2yCoord = evidence.u2.coordinates[1]
hashedKFragValidityMessage = evidence.kfrag_validity_message_hash
alicesKeyAsAddress = alice_addr
lostBytes = evidence.kfrag_signature_v

if lostBytes == False:
    lostBytes = b'\x00'
else: 
    # is this right?
    lostBytes = b'\x01'


pieces = (
    bytes(pointEyCoord),
    bytes(pointEZxCoord),
    bytes(pointEZyCoord),
    bytes(pointE1yCoord),
    bytes(pointE1HxCoord),
    bytes(pointE1HyCoord),
    bytes(pointE2yCoord),
    bytes(pointVyCoord),
    bytes(pointVZxCoord),
    bytes(pointVZyCoord),
    bytes(pointV1yCoord),
    bytes(pointV1HxCoord),
    bytes(pointV1HyCoord),
    bytes(pointV2yCoord),
    bytes(pointUZxCoord),
    bytes(pointUZyCoord),
    bytes(pointU1yCoord),
    bytes(pointU1HxCoord),
    bytes(pointU1HyCoord),
    bytes(pointU2yCoord),
    bytes(hashedKFragValidityMessage),
    bytes(alicesKeyAsAddress),
    bytes(lostBytes),                       
    bytes(lostBytes),
    bytes(lostBytes),
    bytes(lostBytes),
    bytes(lostBytes),
)

def evaluation_arguments(capsule, cfrag, pieces):
        return (bytes(capsule),
                bytes(cfrag),
                b''.join(pieces)
                )

eval_args = evaluation_arguments(capsule, verified_cfrag0, pieces)

