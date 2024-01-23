from BitVector import *
import sys

class DES():
  def __init__(self, key):
    self.key = key
    self.key_bv = BitVector(textstring = key)
    
    
    self.expansion_permutation = [
      31, 0, 1, 2, 3, 4,
      3, 4, 5, 6, 7, 8,
      7, 8, 9, 10, 11, 12,
      11, 12, 13, 14, 15, 16,
      15, 16, 17, 18, 19, 20,
      19, 20, 21, 22, 23, 24,
      23, 24, 25, 26, 27, 28,
      27, 28, 29, 30, 31, 0
    ]
    self.key_permutation_1 = [
      56,48,40,32,24,16,8,0,57,49,41,33,25,17,
      9,1,58,50,42,34,26,18,10,2,59,51,43,35,
      62,54,46,38,30,22,14,6,61,53,45,37,29,21,
      13,5,60,52,44,36,28,20,12,4,27,19,11,3
    ]
    self.key_permutation_2 = [
      13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
      3,25,7,15,6,26,19,12,1,40,51,30,36,46,
      54,29,39,50,44,32,47,43,48,38,55,33,52,
      45,41,49,35,28,31
    ]
    self.shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]



    self.s_boxes = {i:None for i in range(8)}
    self.s_boxes[0] = [ 
      [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
      [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
      [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
      [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] 
      ]
    self.s_boxes[1] = [ 
      [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
      [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
      [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
      [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] 
      ]
    self.s_boxes[2] = [ 
      [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
      [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
      [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
      [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] 
      ]
    self.s_boxes[3] = [ 
      [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
      [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
      [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
      [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] 
      ]

    self.s_boxes[4] = [ 
      [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
      [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
      [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
      [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] 
      ]

    self.s_boxes[5] = [ 
      [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
      [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
      [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
      [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] 
      ]

    self.s_boxes[6] = [ 
      [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
      [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
      [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
      [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] 
      ]

    self.s_boxes[7] = [ 
      [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
      [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
      [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
      [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] 
      ]
    
    self.p_box = [
      15,6,19,20,28,11,27,16,
      0,14,22,25,4,17,30,9,
      1,7,23,13,31,26,2,8,
      18,12,29,5,21,10,3,24
    ]
    



  def encrypt(self, message_file, output_file):
    message_bv = BitVector(size=0)
    with open(message_file, "r") as file:
      message_bv += BitVector(textstring=file.read())
    message_bv += BitVector(bitlist = ([0] * (64 - (message_bv.length()%64))))

    enc_key = self._get_56_bit_key(self.key_bv)
    round_keys = self._generate_round_keys(enc_key)
    cipher_bv = BitVector(size = 0)
    for i in range(len(message_bv) // 64):
      bv = message_bv[i*64:(i+1)*64]
      cipher_bv += self._chunk_encrypt(bv, round_keys)

    with open(output_file, "w") as file:
      file.write(cipher_bv.get_bitvector_in_hex())

      
  def _expand_permutation(self, right):
    return right.permute(self.expansion_permutation)    

  def _get_56_bit_key(self, key):
    return key.permute(self.key_permutation_1)
  
  def _generate_round_keys(self, enc_key):
    round_keys = []
    key = enc_key.deep_copy()
    for round_count in range(16):
      [Lkey, Rkey] = key.divide_into_two()
      shift = self.shifts_for_round_key_gen[round_count]
      Lkey << shift
      Rkey << shift
      key = Lkey+Rkey
      round_key = key.permute(self.key_permutation_2)
      round_keys.append(round_key)
    return round_keys
  
  def _substitute(self, expanded_bv):
    output = BitVector(size=32)
    segments = [expanded_bv[i*6:(i+1)*6] for i in range(8)]
    for sindex in range(len(segments)):
      row = 2*segments[sindex][0] + segments[sindex][-1]
      col = int(segments[sindex][1:-1])
      output[sindex*4:(sindex+1)*4] = BitVector(intVal=(self.s_boxes[sindex][row][col]), size = 4)
    return output

  def _p_box_permute(self, sbox_out):
    return sbox_out.permute(self.p_box)
  
  def _feistel_function(self, left, right, round_key):
    new_left = right.deep_copy()
    new_right = self._expand_permutation(right)
    new_right = new_right ^ round_key
    new_right = self._substitute(new_right)
    new_right = self._p_box_permute(new_right)
    new_right = new_right^left

    return [new_left, new_right]
  
  def _chunk_encrypt(self, bv, keys):
    [left, right] = bv.divide_into_two()
    new_left, new_right = left.deep_copy(), right.deep_copy()
    for i in range(16):
      [new_left, new_right] = self._feistel_function(new_left, new_right, keys[i])
    enc_bv = new_right + new_left
    return enc_bv
  
  def _chunk_decrypt(self, bv, keys):
    [left, right] = bv.divide_into_two()

    new_left, new_right = left.deep_copy(), right.deep_copy()
    for i in range(15, -1, -1):
      [new_left, new_right] = self._feistel_function(new_left, new_right, keys[i]) 
    dec_bv = new_right + new_left
    return dec_bv


  def decrypt(self, encrypted_file, output_file):
    encrypted_bv = BitVector(size=0)
    with open(encrypted_file, "r") as file:
      encrypted_bv += BitVector(hexstring=file.read())
    encrypted_bv += BitVector(bitlist = ([0] * (64 - (encrypted_bv.length()%64))))

    enc_key = self._get_56_bit_key(self.key_bv)
    round_keys = self._generate_round_keys(enc_key)
    decrypted_bv = BitVector(size = 0)
    for i in range(len(encrypted_bv) // 64):
      bv = encrypted_bv[i*64:(i+1)*64]
      decrypted_bv += self._chunk_decrypt(bv, round_keys)

    with open(output_file, "w") as file:
      file.write(decrypted_bv.get_bitvector_in_ascii())
  






if __name__ == "__main__":
  if len(sys.argv) != 5:
    print("python3 DES.py [flag: -e, -d] [input file] [key file] [output file]")
  else:
    key = ""
    with open(sys.argv[3], "r") as file:
      key = file.read()
    des = DES(key)
    if sys.argv[1] == "-e":
      des.encrypt(sys.argv[2], sys.argv[4])
    elif sys.argv[1] == "-d":
      des.decrypt(sys.argv[2], sys.argv[4])
