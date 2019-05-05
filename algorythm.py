from datetime import datetime
from Crypto.Cipher import DES3, AES, CAST, Blowfish, ARC2
from Crypto import Random
from Crypto.Util.strxor import strxor
import time
from twofish import Twofish
import binascii
from rc5 import RC5
from idea import IDEA

ROUNDS = 18
BLOCKSIZE = 32

class ANSIX917:
    '''
    Class that implements the ANSI X9.17 cryptographic PRNG
    '''
    def __init__(self, keylen, time_str, state, algorythm):  
        if keylen != 16 and keylen != 24 and keylen != 32:
            keylen = 16 # Either keying 1 or 2, resp.
        IV = Random.new().read(state) #Init vector 
        key = Random.new().read(keylen)
        self.__state = Random.new().read(state)
        self.__time_format = time_str
        if algorythm == 'DES':                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           
            self.cipher = DES3.new(key, DES3.MODE_CBC, IV)
        if algorythm == 'AES':
            self.cipher = AES.new(key, AES.MODE_CBC, IV)
        if algorythm == 'CAST':
            self.cipher = CAST.new(key, CAST.MODE_CBC, IV)
        if algorythm == 'BLOWFISH':
            self.cipher = Blowfish.new(key, Blowfish.MODE_CBC, IV)
        if algorythm == 'Twofish':
            self.cipher = Twofish(key)
        if algorythm == "RC2":
            self.cipher = ARC2.new(key, ARC2.MODE_CBC, IV)
        if algorythm == "IDEA":
            self.cipher = IDEA(key)
        if algorythm == "RC5":
            self.cipher = RC5(key, BLOCKSIZE, ROUNDS)

    def __iter__(self):
        return self
    
    def __next__(self):
        start = int(datetime.now().strftime('%f'))
        ts = datetime.now().strftime(self.__time_format)
        T = self.cipher.encrypt(bytes(ts, 'utf-8'))
        out = self.cipher.encrypt(strxor(T, self.__state))
        self.__state = self.cipher.encrypt(strxor(T, out))
        return out.hex(), (int(datetime.now().strftime('%f'))- start)
