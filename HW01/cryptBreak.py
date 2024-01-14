from BitVector import *
def cryptBreak(ciphertextFile, key_bv):
    bsize = 16
    numbytes = bsize // 8

    file = open(ciphertextFile, "r")
    cipher_hex_str = file.read()
    file.close()
    encrypted_bv = BitVector(hexstring = cipher_hex_str)
    phrase = "Hopes and dreams of a million years"
    phrase_blocks = len(phrase) // bsize #number of blocks of size bsize to be encoded into the initial ecryption
    


    initial_bitvector = BitVector(bitlist = [0]* bsize) #initial bitvector, used in place of the previous for the encryption of the first block
    for i in range(phrase_blocks): # 0->phrase_blocks
        temp_str = phrase[i*numbytes:(i+1)*numbytes] #block of size numbytes, will be converted to bitvector
        initial_bitvector ^= BitVector(textstring = temp_str)
    
    decrypted = BitVector(size = 0)

    prev = initial_bitvector
    for i in range(len(encrypted_bv)//bsize):
        bv = encrypted_bv[i*bsize:(i+1)*bsize]
        temp = bv.deep_copy()
        bv ^= prev
        prev = temp
        bv ^= key_bv
        decrypted+=bv

    outputtext = decrypted.get_text_from_bitvector()
    return outputtext


    


    





# PassPhrase = "Hopes and dreams of a million years"                            #(C)

# BLOCKSIZE = 64                                                                #(D)
# numbytes = BLOCKSIZE // 8  

# bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)    
# for i in range(0,len(PassPhrase) // numbytes):                                #(G)
#     textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
#     bv_iv ^= BitVector( textstring = textstr )  
# print(bv_iv.length())
# print(len(PassPhrase))

if __name__ == "__main__":
    kv = BitVector(intVal=1616, size=16)
    out = cryptBreak("cipherText.txt", kv)
    if "Ferrari" in out:
        print("SUCCESS:\n", out)
    else:
        print("FAILURE: \n", out)