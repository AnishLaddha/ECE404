# ######################################################
# Author : Anish Laddha
# email : laddhaa@purdue.edu
# Date : 01/14/2024
# ######################################################

# ######################################################
# Citation: Professor Avinash Kak
# Link: https://engineering.purdue.edu/kak/compsec/code/Lecture2Code.tar.gz
# Date : 01/14/2024
# Lines: 30-47

# ######################################################
from BitVector import *

def cryptBreak(ciphertextFile, key_bv):
    bsize = 16 #size of the bitvectors we use in the assignment for virtually everything, from block size to key size
    numbytes = bsize // 8 #number of bytes

    with open(ciphertextFile, "r") as file: # opens the file, and reads the encrypted text as a string of hex anmd dumps into a variable
        cipher_hex_str = file.read()
    encrypted_bv = BitVector(hexstring = cipher_hex_str) #bitvector representation of the cipher string.
    
    phrase = "Hopes and dreams of a million years" #our pass phrase
    phrase_blocks = len(phrase) // bsize #number of blocks of size bsize to be encoded into the initial vector.
    #  note: for the previous line, the remainders are not considered

    initial_bitvector = BitVector(bitlist = [0]* bsize) #initial bitvector, used in place of the previous for the encryption of the first block
    for i in range(phrase_blocks): # 0->phrase_blocks
        temp_str = phrase[i*numbytes:(i+1)*numbytes] #block of size numbytes, will be converted to bitvector
        initial_bitvector ^= BitVector(textstring = temp_str) #after we extract chunks of the passphrase, we convert each to a bv and xor them all together
        # this bv is now our initial_bv 
    
    decrypted = BitVector(size = 0) 
    prev = initial_bitvector
    for i in range(len(encrypted_bv)//bsize): # will operate in blocks of size bsize
        bv = encrypted_bv[i*bsize:(i+1)*bsize] # get the encrypted bit vector of size bsize
        temp = bv.deep_copy() #hold a copy, as useful as the prev for the next rounds operation
        bv ^= prev #math explained above
        prev = temp
        bv ^= key_bv
        decrypted+=bv #add decrypted to the broader thing

    outputtext = decrypted.get_text_from_bitvector() #convert bitvector to text
    return outputtext
