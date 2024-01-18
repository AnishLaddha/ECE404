from cryptBreak import cryptBreak
from BitVector import *


randomint = 1616
kv = BitVector(intVal=randomint, size=16)
out = cryptBreak("cipherText.txt", kv)
with open("decrypted.txt", "w") as file:
	file.write(out)
