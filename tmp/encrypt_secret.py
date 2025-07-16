import rsa
import uuid

n_val = 7460699476552039301260554868675223056623468105139796988525642387131795988518927704077606303864632639583981842893061332566500136811626100714069053321334883  # Replace with 'n' from Postman
e_val = 65537


secret_key = str(uuid.uuid4())

pub_key = rsa.PublicKey(n=n_val, e=e_val)

cipher_bytes = rsa.encrypt(secret_key.encode("utf8"), pub_key)
hex_cipher = cipher_bytes.hex()

# 5. Print the results. You will use these in Postman.
print("--- Use these values in your next Postman request ---")
print(f"Generated JWT Secret Key (for your reference): {secret_key}")
print(f"Encrypted Hex Cipher (for the 'hex_cipher' field): {hex_cipher}")
