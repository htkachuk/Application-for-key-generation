from datetime import datetime
from Crypto.Cipher import DES3, AES, CAST, Blowfish, ARC2
from Crypto import Random
from Crypto.Util.strxor import strxor
import time
from twofish import Twofish
import binascii
from rc5 import RC5
from idea import IDEA
from pygost.gost28147 import cfb_encrypt

ROUNDS = 18
BLOCKSIZE = 32

class ANSIX917:
    '''
    Class that implements the ANSI X9.17 cryptographic PRNG
    '''
    def __init__(self, keylen, time_str, state, algorythm):  
        if keylen != 16 and keylen != 24 and keylen != 32:
            keylen = 16 # Either keying 1 or 2, resp.
        self.IV = Random.new().read(state) #Init vector 
        self.key = Random.new().read(keylen)
        self.__state = Random.new().read(state)
        self.__time_format = time_str
        if algorythm == 'DES':                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           
            self.cipher = DES3.new(self.key, DES3.MODE_CBC, self.IV)
        if algorythm == 'AES':
            self.cipher = AES.new(self.key, AES.MODE_CBC, self.IV)
        if algorythm == 'CAST':
            self.cipher = CAST.new(self.key, CAST.MODE_CBC, self.IV)
        if algorythm == 'BLOWFISH':
            self.cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, self.IV)
        if algorythm == 'Twofish':
            self.cipher = Twofish(self.key)
        if algorythm == "RC2":
            self.cipher = ARC2.new(self.key, ARC2.MODE_CBC, self.IV)
        if algorythm == "IDEA":
            self.cipher = IDEA(self.key)
        if algorythm == "RC5":
            self.cipher = RC5(self.key, BLOCKSIZE, ROUNDS)
        if algorythm == "GOST28147":
            self.IV = Random.new().read(8)
            self.cipher = "gost"

    def __iter__(self):
        return self
    
    def __next__(self):
        start = int(datetime.now().strftime('%f'))
        ts = datetime.now().strftime(self.__time_format)
        if self.cipher != "gost":
            T = self.cipher.encrypt(bytes(ts, 'utf-8'))
            out = self.cipher.encrypt(strxor(T, self.__state))
            self.__state = self.cipher.encrypt(strxor(T, out))
        else:
            T = cfb_encrypt(self.key, data=bytes(ts, 'utf-8'), iv=self.IV)
            out = cfb_encrypt(self.key, data=strxor(T, self.__state), iv=self.IV)
            self.__state = cfb_encrypt(self.key, data=strxor(T, out), iv=self.IV)
        return out.hex(), (int(datetime.now().strftime('%f'))- start)
