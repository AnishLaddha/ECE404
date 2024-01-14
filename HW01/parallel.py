from BitVector import *
from multiprocessing import Pool, cpu_count
from tqdm import tqdm

bsize = 16
numbytes = bsize // 8
ciphertextFile="cipherText.txt"
file = open(ciphertextFile, "r")
cipher_hex_str = file.read()
file.close()
encrypted_bv = BitVector(hexstring = cipher_hex_str)
phrase = "Hopes and dreams of a million years"
phrase_blocks = len(phrase) // bsize #number of blocks of size bsize to be encoded into the initial ecryption
 
initial_bitvector = BitVector(bitlist = [0]* bsize) #initial bitvector, used in place of the previous for the encryption of the first block
for x in range(phrase_blocks): # 0->phrase_blocks
	temp_str = phrase[x*numbytes:(x+1)*numbytes] #block of size numbytes, will be converted to bitvector
	initial_bitvector ^= BitVector(textstring = temp_str)


msg_partial_decrypted = BitVector(size = 0)

prev_dec = initial_bitvector
for i in range(len(encrypted_bv) // bsize):
	#print("iteration:", i, "current length of msg:", msg_partial_decrypted.length())
	bv = encrypted_bv[i*bsize:(i+1)*bsize]
	temp_bv = bv.deep_copy()
	bv ^= prev_dec
	prev_dec = temp_bv
	msg_partial_decrypted += bv






#print("encrypted length:", encrypted_bv.length())
p_flag = False
g_key = 0

def decrypt(key:int):
  global p_flag
  global g_key
  if p_flag:
    return
  kv = BitVector(intVal=key, size = bsize)
  msg_decrypted = BitVector(size=0)
  for i in range(len(msg_partial_decrypted) // bsize):
    bv = msg_partial_decrypted[i*bsize:(i+1)*bsize]
    bv^=kv
    msg_decrypted+=bv
  
  msg_decrypted_text = msg_decrypted.get_bitvector_in_ascii()
  if "Ferrari" in msg_decrypted_text:
    g_key = key
    p_flag = True
    return

if __name__ == "__main__":
  keys_range = (range(65536))
  num_processes = cpu_count()
  with Pool(num_processes) as pool:

    results = tqdm(pool.imap(decrypt, keys_range), total=65536)
    tuple(results)
  
  if g_key != 0:
    print("\n\nFERRARI FOUND!!! KEY: ", g_key)


