import sys
from BitVector import *
from PrimeGenerator import PrimeGenerator
from solve_pRoot import solve_pRoot

class BreakRSA():
    def __init__(self , e) -> None:
        self.e = e
        self.p = None
        self.q = None

    def keygen(self):
        flag = True
        pg = PrimeGenerator(bits=128)
        while flag:
            p = pg.findPrime()
            q = pg.findPrime()
            if self._good_primes(p=p, q=q) == True:
                flag = False
        return p,q

    
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

        

    def encrypt(self , plaintext:str , enc1:str, enc2:str, enc3:str, n_file:str) -> None:
        with open(plaintext, "r") as f:
            message_str = f.read()
        message_bv = BitVector(textstring=message_str)
        if message_bv.length()%128 != 0:
            pad_list = [0] * (128-(message_bv.length()%128))
            message_bv += BitVector(bitlist=pad_list)
        
        p1,q1 = self.keygen()
        p2,q2 = self.keygen()
        p3,q3 = self.keygen()

        n1 = p1*q1
        n2 = p2*q2
        n3 = p3*q3
        
        f = open(enc1, "w")
        for i in range(message_bv.length()//128):
            msg_block = message_bv[i*128:(i+1)*128]
            msg_block = BitVector(bitlist=([0]*128)) + msg_block
            msg_int = msg_block.intValue()
            cipher_int = pow(msg_int,self.e, n1)
            cipher_bv = BitVector(intVal=cipher_int, size=256)
            f.write(cipher_bv.get_bitvector_in_hex())
        f.close()

        f = open(enc2, "w")
        for i in range(message_bv.length()//128):
            msg_block = message_bv[i*128:(i+1)*128]
            msg_block = BitVector(bitlist=([0]*128)) + msg_block
            msg_int = msg_block.intValue()
            cipher_int = pow(msg_int,self.e, n2)
            cipher_bv = BitVector(intVal=cipher_int, size=256)
            f.write(cipher_bv.get_bitvector_in_hex())
        f.close()

        f = open(enc3, "w")
        for i in range(message_bv.length()//128):
            msg_block = message_bv[i*128:(i+1)*128]
            msg_block = BitVector(bitlist=([0]*128)) + msg_block
            msg_int = msg_block.intValue()
            cipher_int = pow(msg_int,self.e, n3)
            cipher_bv = BitVector(intVal=cipher_int, size=256)
            f.write(cipher_bv.get_bitvector_in_hex())
        f.close()

        with open(n_file, "w") as f:
            f.write(str(n1) + "\n")
            f.write(str(n2) + "\n")
            f.write(str(n3) + "\n")
    
    def crack(self, enc1:str, enc2:str, enc3:str, n_file:str, crackfile:str) -> None:
        with open(n_file, "r") as f:
            n1 = int(f.readline())
            n2 = int(f.readline())
            n3 = int(f.readline())
        
        n1_bv = BitVector(intVal=n1)
        n2_bv = BitVector(intVal=n2)
        n3_bv = BitVector(intVal=n3)
        
        big_n = n1 * n2 * n3
        N1 = n2*n3
        N2 = n1*n3
        N3 = n1*n2

        N1_bv = BitVector(intVal=N1)
        N2_bv = BitVector(intVal=N2)
        N3_bv = BitVector(intVal=N3)

        N1_inv_bv = N1_bv.multiplicative_inverse(n1_bv)
        N2_inv_bv = N2_bv.multiplicative_inverse(n2_bv)
        N3_inv_bv = N3_bv.multiplicative_inverse(n3_bv)
        
        N1_inv = N1_inv_bv.intValue()
        N2_inv = N2_inv_bv.intValue()
        N3_inv = N3_inv_bv.intValue()

        


        with open(enc1, "r") as f:
            cipher1_bv = BitVector(hexstring=f.read())
        with open(enc2, "r") as f:
            cipher2_bv = BitVector(hexstring=f.read())
        with open(enc3, "r") as f:
            cipher3_bv = BitVector(hexstring=f.read())
        
        f = open(crackfile, "w")
        for i in range(cipher1_bv.length() // 256):
            c1_block = cipher1_bv[i*256:(i+1)*256]
            c2_block = cipher2_bv[i*256:(i+1)*256]
            c3_block = cipher3_bv[i*256:(i+1)*256]

            c1 = c1_block.intValue()
            c2 = c2_block.intValue()
            c3 = c3_block.intValue()
            m3 = ((c1*N1*N1_inv)+(c2*N2*N2_inv)+(c3*N3*N3_inv))%big_n
            m = solve_pRoot(3, m3)
            m_bv = BitVector(intVal = m, size=128)
            f.write(m_bv.get_bitvector_in_ascii())
        
        f.close()
        

if __name__ == "__main__":
    cipher = BreakRSA(e=3)
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], enc1=sys.argv[3], enc2=sys.argv[4], enc3=sys.argv[5], n_file=sys.argv[6])
    elif sys.argv[1] == "-c":
        cipher.crack(enc1=sys.argv[2], enc2=sys.argv[3], enc3=sys.argv[4], n_file=sys.argv[5], crackfile=sys.argv[6])