from cryptBreak import cryptBreak
from BitVector import *


randomint = 1616
kv = BitVector(intVal=randomint, size=16)
print(kv.get_bitvector_in_hex())
out = cryptBreak("cipherText.txt", kv)
print(out)