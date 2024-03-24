import sys
from BitVector import *

class hash():
    def __init__(self,  inputfile:str) ->  None:
        with open(inputfile, "r") as f:
            self.input = f.read()
            
            self.K = [
                "428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
                "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
                "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
                "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
                "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
                "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
                "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
                "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
                "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
                "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
                "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
                "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
                "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
                "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
                "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
                "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
                "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
                "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
                "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
                "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"
            ]
            self.K_bv = [BitVector(hexstring=k_cons) for k_cons in self.K]

            self.hash = [
                "6a09e667f3bcc908",
                "bb67ae8584caa73b",
                "3c6ef372fe94f82b",
                "a54ff53a5f1d36f1",
                "510e527fade682d1",
                "9b05688c2b3e6c1f",
                "1f83d9abfb41bd6b",
                "5be0cd19137e2179"
            ]
            self.hash_bv = [BitVector(hexstring=hash_cons) for hash_cons in self.hash]
            
    
    def sha512(self, outfile:str) -> None:
        input_bv = BitVector(textstring = self.input)
        padded_bv  = self._pad_input(input_bv.deep_copy())
        for i in range(padded_bv.length() // 1024):
            block = padded_bv[i*1024:(i+1)*1024]
            self._process_block(block)
        hash_str = ""
        for h in self.hash_bv:
            hash_str+=h.get_bitvector_in_hex()
        with open(outfile, "w") as f:
            f.write(hash_str)

    def _pad_input(self, inp_bv:BitVector) -> BitVector:
        m =  inp_bv.length() % 1024
        padding  = 1024-m
        if padding > 128:
            padding -=128
        elif padding < 128:
            padding += (1024-128)
        p_list = [1]
        p_list+=([0]*(padding-1))
        p_bv = BitVector(bitlist = p_list)
        last_128 = BitVector(intVal=(inp_bv.length()), size = 128)
        final_bv = inp_bv+p_bv+last_128
        return final_bv
    
    def _process_block(self, block_bv:BitVector):
        msg_schedule = self._generate_msg_schedule(block_bv=block_bv)
        a,b,c,d = self.hash_bv[0], self.hash_bv[1], self.hash_bv[2], self.hash_bv[3]
        e,f,g,h = self.hash_bv[4], self.hash_bv[5], self.hash_bv[6], self.hash_bv[7]
        for i in range(80):
            maj = (a&b)^(a&c)^(b&c)
            ch = (e&f) ^ ((~e)&g)
            sum_e = (e.deep_copy() >> 14)^(e.deep_copy() >> 18)^(e.deep_copy() >> 41)
            sum_a = (a.deep_copy() >> 28)^(a.deep_copy() >> 34)^(a.deep_copy() >> 39)
            t1 = BitVector(intVal=((int(ch) + int(sum_e) + int(h) + int(msg_schedule[i]) + int(self.K_bv[i]))&0xFFFFFFFFFFFFFFFF), size = 64)
            t2 = BitVector(intVal=((int(sum_a) + int(maj))&0xFFFFFFFFFFFFFFFF), size=64)
            h = g
            g = f
            f = e
            e = BitVector(intVal=((int(d) + int(t1)) &0xFFFFFFFFFFFFFFFF), size = 64)
            d = c
            c = b
            b = a
            a = BitVector(intVal=((int(t1) + int(t2)) & 0xFFFFFFFFFFFFFFFF), size = 64)
        
        self.hash_bv[0] = BitVector(intVal=((int(a) + int(self.hash_bv[0])) & 0xFFFFFFFFFFFFFFFF), size=64)
        self.hash_bv[1] = BitVector(intVal=((int(b) + int(self.hash_bv[1])) & 0xFFFFFFFFFFFFFFFF), size=64)
        self.hash_bv[2] = BitVector(intVal=((int(c) + int(self.hash_bv[2])) & 0xFFFFFFFFFFFFFFFF), size=64)
        self.hash_bv[3] = BitVector(intVal=((int(d) + int(self.hash_bv[3])) & 0xFFFFFFFFFFFFFFFF), size=64)
        self.hash_bv[4] = BitVector(intVal=((int(e) + int(self.hash_bv[4])) & 0xFFFFFFFFFFFFFFFF), size=64)
        self.hash_bv[5] = BitVector(intVal=((int(f) + int(self.hash_bv[5])) & 0xFFFFFFFFFFFFFFFF), size=64)
        self.hash_bv[6] = BitVector(intVal=((int(g) + int(self.hash_bv[6])) & 0xFFFFFFFFFFFFFFFF), size=64)
        self.hash_bv[7] = BitVector(intVal=((int(h) + int(self.hash_bv[7])) & 0xFFFFFFFFFFFFFFFF), size=64)


    def _generate_msg_schedule(self, block_bv: BitVector) -> list:
        m_sched = [None] * 80
        for i in range(16):
            m_sched[i] = block_bv[(i)*64:(i+1)*64]

        for i in range(16, 80):
            first = (m_sched[i-16]).intValue()
            second = (self._sig_0(m_sched[i-15])).intValue()
            third = (m_sched[i-7]).intValue()
            fourth = (self._sig_1(m_sched[i-2])).intValue()
            total = (first + second + third + fourth) & 0xFFFFFFFFFFFFFFFF
            m_sched[i] = BitVector(intVal = total, size = 64)
        
        return m_sched



    def _sig_0(self, bv: BitVector) -> BitVector:
        first = bv.deep_copy() >> 1
        second = bv.deep_copy() >> 8
        third = bv.deep_copy().shift_right(7)
        return first^second^third
    
    def _sig_1(self, bv: BitVector) -> BitVector:
        first = bv.deep_copy() >> 19
        second = bv.deep_copy() >> 61
        third = bv.deep_copy().shift_right(6)

        return first^second^third

    

if __name__ == "__main__":
    h  = hash(sys.argv[1])
    h.sha512(sys.argv[2])
