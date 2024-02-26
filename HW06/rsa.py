import sys
from BitVector import *
from PrimeGenerator import PrimeGenerator

class RSA():
    def __init__(self , e) -> None:
        self.e = e
        self.n = None
        self.d = None
        self.p = None
        self.q = None

    def keygen(self, pfile:str, qfile:str) -> None:
        flag = True
        pg = PrimeGenerator(bits=128)
        while flag:
            p = pg.findPrime()
            q = pg.findPrime()
            if self._good_primes(p=p, q=q) == True:
                flag = False
        
        with open(pfile, "w") as f:
            f.write(str(p))
        
        with open(qfile, "w") as f:
            f.write(str(q))

    
    def _good_primes(self, p:int, q:int) -> bool:
        if p == q:
            return False
        
        p_bv = BitVector(intVal = p)
        q_bv = BitVector(intVal = q)

        if p_bv[0] != 1 or p_bv[1] != 1:
            return False
        
        if q_bv[0] != 1 or q_bv[1] != 1:
            return False
        
        if self._are_coprime(n=p, m=self.e) == False:
            return False
        
        if self._are_coprime(n=q, m=self.e) == False:
            return False
        
        return True

    def _are_coprime(self, n:int, m:int) -> bool:
        n_bv = BitVector(intVal = n)
        m_bv = BitVector(intVal = m)

        gcd_bv = n_bv.gcd(m_bv)
        gcd = gcd_bv.intValue()

        if gcd == 1:
            return True
        return False

        

    def encrypt(self , plaintext:str , ciphertext:str) -> None:
        with open(plaintext, "r") as f:
            message_str = f.read()
        message_bv = BitVector(textstring=message_str)
        if message_bv.length()%128 != 0:
            pad_list = [0] * (128-(message_bv.length()%128))
            message_bv += BitVector(bitlist=pad_list)
        
        with open(sys.argv[3], "r") as f:
            self.p = int(f.read())
        with open(sys.argv[4], "r") as f:
            self.q = int(f.read())
        self.n = self.p*self.q
        
        f = open(ciphertext, "w")

        for i in range(message_bv.length()//128):
            msg_block = message_bv[i*128:(i+1)*128]
            msg_block = BitVector(bitlist=([0]*128)) + msg_block
            msg_int = msg_block.intValue()
            cipher_int = pow(msg_int,self.e, self.n)
            cipher_bv = BitVector(intVal=cipher_int, size=256)
            f.write(cipher_bv.get_bitvector_in_hex())
            # if i <10:
            #     print(cipher_bv)        
        f.close()


    def decrypt(self , ciphertext:str , recovered_plaintext:str)-> None:
        with open(ciphertext, "r") as f:
            cipher_str = f.read()
        cipher_bv = BitVector(hexstring=cipher_str)
        with open(sys.argv[3], "r") as f:
            self.p = int(f.read())
        with open(sys.argv[4], "r") as f:
            self.q = int(f.read())
        self.n = self.p*self.q
        totient_n = (self.p - 1) * (self.q - 1)
        totient_n_bv = BitVector(intVal=totient_n)
        e_bv = BitVector(intVal = self.e)
        d_bv = e_bv.multiplicative_inverse(totient_n_bv)
        self.d = d_bv.intValue()

        q_bv = BitVector(intVal = self.q)
        p_bv = BitVector(intVal = self.p)
        q_inv_bv = q_bv.multiplicative_inverse(p_bv)
        p_inv_bv = p_bv.multiplicative_inverse(q_bv)
        q_inv = q_inv_bv.intValue()
        p_inv = p_inv_bv.intValue()
        
        xp = self.q * q_inv
        xq = self.p * p_inv

        
        f = open(recovered_plaintext, "w")

        for i in range(cipher_bv.length() // 256):
            cipher_block = cipher_bv[i*256:(i+1)*256]
            cphr_int = cipher_block.intValue()
            vp = pow(cphr_int, self.d, self.p)
            vq = pow(cphr_int, self.d, self.q)
            
            msg_int = (vp*xp + vq*xq) % self.n
            msg_block = BitVector(intVal = msg_int, size = 128)

            f.write(msg_block.get_bitvector_in_ascii())

        f.close()









if __name__ == "__main__":
    cipher = RSA(e=65537)
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[5])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[5])
    elif sys.argv[1] == "-g":
        cipher.keygen(pfile=sys.argv[2], qfile=sys.argv[3])