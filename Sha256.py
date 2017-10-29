"""
Sha256.py
A straightforward implementation of the SHA256 algorithm.
The focus of the code is on clarity and not performance.
"""
W = 32          #Number of bits in word
M = 1 << W
FF = M - 1      #0xFFFFFFFF

#Constants from SHA256 definition
K = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

#Initial values for compression function
I = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

def RR(x, b):
    '''
    32-bit bitwise rotate right
    '''
    return ((x >> b) | (x << (W - b))) & FF

def Pad(W):
	'''
	Pads the string according to SHA256 standard.
	'''
    mdi = len(W) % 64           
    L = (len(W) << 3).to_bytes(8, 'big')        #Binary of len(W) in bits
    npad = 55 - mdi if mdi < 56 else 119 - mdi  #Pad so 64 | len; add 1 block if needed
    return bytes(W, 'ascii') + b'\x80' + (b'\x00' * npad) + L   #64 | 1 + npad + 8 + len(W)

def Sha256CF(Wt, Kt, A, B, C, D, E, F, G, H):
    '''
    SHA256 Compression Function
    '''
    Ch = (E & F) ^ (~E & G)
    Ma = (A & B) ^ (A & C) ^ (B & C)
    S0 = RR(A, 2) ^ RR(A, 13) ^ RR(A, 22)
    S1 = RR(E, 6) ^ RR(E, 11) ^ RR(E, 25)
    T1 = H + S1 + Ch + Wt + Kt
    return (T1 + S0 + Ma) & FF, A, B, C, (D + T1) & FF, E, F, G

def Sha256(M):
    M = Pad(M)          #Pad message so that length is divisible by 64
    DG = list(I)        #Digest as 8 32-bit words
    for j in range(0, len(M), 64):
        S = M[j:j + 64]
        W = [0] * 64
        W[0:16] = [int.from_bytes(S[i:i + 4], 'big') for i in range(0, 64, 4)]  
        for i in range(16, 64):
            s0 = RR(W[i - 15], 7) ^ RR(W[i - 15], 18) ^ (W[i - 15] >> 3)
            s1 = RR(W[i - 2], 17) ^ RR(W[i - 2], 19) ^ (W[i - 2] >> 10)
            W[i] = (W[i - 16] + s0 + W[i-7] + s1) & FF
        A, B, C, D, E, F, G, H = DG
        for i in range(64):
            A, B, C, D, E, F, G, H = Sha256CF(W[i], K[i], A, B, C, D, E, F, G, H)
        DG = [(X + Y) & FF for X, Y in zip(DG, (A, B, C, D, E, F, G, H))]
    return b''.join(Di.to_bytes(4, 'big') for Di in DG)  #Convert to byte array

def ISha256CF(Wt, Kt, A, B, C, D, E, F, G, H, ei = 0, hi = 0):
    Ch = (F & G) ^ (~F & H)
    Ma = (B & C) ^ (B & D) ^ (C & D)
    S0 = RR(B, 2) ^ RR(B, 13) ^ RR(B, 22)
    S1 = RR(F, 6) ^ RR(F, 11) ^ RR(F, 25)
    SH = A - (Wt + Kt + Ch + S1 + Ma + S0) + ei * M
    SE = E - A + S0 + Ma + hi * M
    print((Ch, Ma, S0, S1))
    return B, C, D, SE, F, G, H, SH
    
if __name__ == "__main__":
	#Unit test for the SHA256 function
    import random, hashlib, time
    nt = 4000
    ps = [chr(i) for i in range(32, 128)]
    l1, l2 = [], []
    for i in range(nt):
        s = ''.join(random.choice(ps) for _ in range(random.randint(0, 512)))
        s256 = hashlib.sha256()
        s256.update(bytes(s, 'ascii'))
        d1 = s256.digest()
        d2 = Sha256(s)
        if d1 != d2:
            print('!= ' + s)
    print('Done')
