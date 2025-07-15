import rsa
import uuid

n_val = 8005186501273859401339992441661974480606907813508113919617996890637798184491989447874245491118254334962410075546665741190207922015778208339654413661181267  # Replace with 'n' from Postman
e_val = 65537


secret_key = str(uuid.uuid4())

pub_key = rsa.PublicKey(n=n_val, e=e_val)

cipher_bytes = rsa.encrypt(secret_key.encode('utf8'), pub_key)
hex_cipher = cipher_bytes.hex()

# 5. Print the results. You will use these in Postman.
print("--- Use these values in your next Postman request ---")
print(f"Generated JWT Secret Key (for your reference): {secret_key}")
print(f"Encrypted Hex Cipher (for the 'hex_cipher' field): {hex_cipher}")