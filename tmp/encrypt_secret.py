import rsa
import uuid

n_val = 8123479559960823392125995723261043942057210397861227245931071040176295378566173069424348691702143179455110171844236308505372812397760177271133901042895323  # Replace with 'n' from Postman
e_val = 65537


secret_key = str(uuid.uuid4())

pub_key = rsa.PublicKey(n=n_val, e=e_val)

cipher_bytes = rsa.encrypt(secret_key.encode("utf8"), pub_key)
hex_cipher = cipher_bytes.hex()

# 5. Print the results. You will use these in Postman.
print("--- Use these values in your next Postman request ---")
print(f"Generated JWT Secret Key (for your reference): {secret_key}")
print(f"Encrypted Hex Cipher (for the 'hex_cipher' field): {hex_cipher}")
