import sys
from BitVector import *

class AES():
    
	def __init__(self, keyfile:str) -> None:
		self.AES_modulus = BitVector(bitstring='100011011')
		with open(keyfile, "r") as f:
			key_str = f.read()
		key_bv = BitVector(textstring=key_str)
		self.byte_sub_table, self.inv_byte_sub_table = self.gen_subbytes_table()
		
		# self.byte_sub_table_2d, self.inv_byte_sub_table_id = self.state_to_2d(self.byte_sub_table), self.state_to_2d(self.inv_byte_sub_table)
		
		self.key_schedule = self.generate_key_schedule(key_bv)
		

		# for i in range(len(self.key_schedule)):
		# 	print(i, len(self.key_schedule[i]), self.key_schedule[i])

	def encrypt(self, plaintext:str, ciphertext:str) -> None:
		with open(plaintext, "r") as f:
			plaintext_bv = BitVector(textstring=f.read())
		
		cipher_bv = BitVector(size = 0)
		
		pbv_rem = (plaintext_bv.length()) % 128
		if pbv_rem > 0:
			plaintext_bv+= BitVector(bitlist= ([0]*(128-pbv_rem)))

		pbv_len = plaintext_bv.length()

		for i in range(pbv_len//128):
			plain_chunk = plaintext_bv[(i*128):(i+1)*128]
			cipher_chunk = self.encrypt_block(plain_chunk)
			cipher_bv += cipher_chunk

		with open(ciphertext, "w") as f:
			cipher_hex = cipher_bv.get_bitvector_in_hex()
			f.write(cipher_hex)
		
	def decrypt(self, ciphertext:str, decrypted:str) -> None:
		pass
	
	def pre_rounds(self, bv):
		first_four_word = self.key_schedule[0] + self.key_schedule[1] + self.key_schedule[2] + self.key_schedule[3]
		first_four_xor = first_four_word ^ bv
		return first_four_xor
	
	def subbytes(self, bv):
		subbed_bytes = BitVector(size = 0)
		for i in range(bv.length() // 8):
			byte = bv[(i*8):(i+1)*8]
			sub_byte = self.byte_sub_table[byte.intValue()]
			subbed_bytes += BitVector(size = 8, intVal = sub_byte)
		return subbed_bytes
	
	def shift_rows(self, bv):
		shifted_row = BitVector(size=0)
		for col in range(4):
			for row in range(4):
				s = (row*5 + col*4) % 16
				shifted_row += bv[s*8:(s+1)*8]
		return shifted_row
	
	def mix_cols(self, bv):
		mixed_cols = BitVector(size = 0)
		for col in range(4):
			for row in range(4):
				rows = [((row+i)%4) for i in range(4)]
				pos = [(col*4 + r) for r in rows]
				bv_pos = [bv[(i*8):(i+1)*8] for i in pos]
				bv_pos[0] = bv_pos[0].gf_multiply_modular(BitVector(intVal = 2), self.AES_modulus, 8)
				bv_pos[1] = bv_pos[1].gf_multiply_modular(BitVector(intVal = 3), self.AES_modulus, 8)

				byte = bv_pos[0] ^ bv_pos[1] ^ bv_pos[2] ^ bv_pos[3]
				mixed_cols += byte
		
		return mixed_cols
	
	def xor_round_keys(self, round, bv):
		round_key = BitVector(size = 0)
		key_arr = self.key_schedule[4*round:4*(round+1)]
		for k in key_arr:
			round_key+=k
		return bv^round_key

	def encrypt_block(self, plain_block):
		pre_xor = self.pre_rounds(plain_block)
		hold = pre_xor.deep_copy()
		for i in range(1,15):
			subbed = self.subbytes(hold)
			shift_rowed = self.shift_rows(subbed)
			mix_coled = self.mix_cols(shift_rowed)
			hold = self.xor_round_keys(i, mix_coled)
		return hold
		




	def generate_key_schedule(self,key_bv):
		key_words = [None for i in range(60)]
		round_constant = BitVector(intVal = 0x01, size=8)
		for i in range(8):
			key_words[i] = key_bv[i*32 : i*32 + 32]
		for i in range(8,60):
			if i%8 == 0:
				kwd, round_constant = self.gee(key_words[i-1], round_constant)
				key_words[i] = key_words[i-8] ^ kwd
			elif (i - (i//8)*8) < 4:
				key_words[i] = key_words[i-8] ^ key_words[i-1]
			elif (i - (i//8)*8) == 4:
				key_words[i] = BitVector(size = 0)
				for j in range(4):
					key_words[i] += BitVector(intVal = self.byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
				key_words[i] ^= key_words[i-8]
			elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
				key_words[i] = key_words[i-8] ^ key_words[i-1]
			else:
				sys.exit("error in key scheduling algo for i = %d" % i)
		return key_words
	
	def gen_subbytes_table(self):
		subBytesTable = []
		invSubBytesTable = []
		c = BitVector(bitstring='01100011')
		d = BitVector(bitstring='00000101')
		for i in range(0, 256):
			a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
			a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
			a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
			subBytesTable.append(int(a))

			b = BitVector(intVal = i, size=8)
			b1,b2,b3 = [b.deep_copy() for x in range(3)]
			b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
			check = b.gf_MI(self.AES_modulus, 8)
			b = check if isinstance(check, BitVector) else 0
			invSubBytesTable.append(int(b))

		return subBytesTable, invSubBytesTable



	def gee(self, keyword, round_constant):
		rotated_word = keyword.deep_copy()
		rotated_word << 8
		newword = BitVector(size = 0)
		for i in range(4):
			newword += BitVector(intVal = self.byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
		newword[:8] ^= round_constant
		round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
		return newword, round_constant
	
	def state_to_2d(self, state_list):
		array_2d = [[0 for _ in range(16)] for _ in range(16)]
		for i in range(16):
			for j in range(16):
				array_2d[i][j] = state_list[i * 16 + j]
		
		return array_2d


if __name__ == "__main__":
	cipher = AES(keyfile = sys.argv[3])
	if sys.argv[1] == "-e": 
		cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4]) 
	# elif sys.argv[1] == "-d":
	# 	cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4]) 
	# else:
	# 	sys.exit("Incorrect Command -Line Syntax")