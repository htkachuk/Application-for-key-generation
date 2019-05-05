import algorythm as ag
import cmd

SHORT_TIME = '%S%f'
SHORT_KEYLEN = 16
SHORT_STATE = 8
MEDIUM_KEYLEN = 24
LARGE_KEYLEN = 32
LARGE_TIME = '%m%d%H%M%S%f'
LARGE_STATE = 16
BLOWFISH_KEYLEN = 32
BLOWFISH_TIME = '%S%f'
BLOWFISH_STATE = 8

#gost28147


class Cli(cmd.Cmd):
	def __init__(self):
		cmd.Cmd.__init__(self)
		self.intro  = "\t\tWelcome to CLI for key generation by ANSIX917.\n How to use? 'help'!!"
		self.doc_header ="For detail information use 'help _command_')"

	def do_des(self, args):
		"""'des' Triple DES symmetric cipher
		Triple DES (or TDES or TDEA or 3DES) is a symmetric block cipher standardized by NIST.
		It has a fixed data block size of 8 bytes. Its keys are 128 (Option 1) or 192 bits (Option 2) long.
		However, 1 out of 8 bits is used for redundancy and do not contribute to security.
		The effective key length is respectively 112 or 168 bits.
		TDES consists of the concatenation of 3 simple DES ciphers.
		The plaintext is first DES encrypted with K1, then decrypted with K2, and finally encrypted again with K3.
		The ciphertext is decrypted in the reverse manner.
		It is important that all subkeys are different, otherwise TDES would degrade to single DES.
		TDES is cryptographically secure, even though it is neither as secure nor as fast as AES."""
		obj = ag.ANSIX917(SHORT_KEYLEN, SHORT_TIME, SHORT_STATE, 'DES')
		key, time = obj.__next__()
		print("Key with DES algorithm: ", key)
		print("Time for generation: ", time, "ms")

	def do_aes128(self, args):
		"""'aes128' AES symmetric cipher
		AES (Advanced Encryption Standard) is a symmetric block cipher standardized by NIST.
		It has a fixed data block size of 16 bytes. Its keys can be 128, 192, or 256 bits long.
		AES is very fast and secure, and it is the de facto standard for symmetric encryption."""
		obj = ag.ANSIX917(SHORT_KEYLEN, LARGE_TIME, LARGE_STATE, 'AES')
		key, time = obj.__next__()
		print("Key with AES128 algorithm: ", key)
		print("Time for generation: ", time, "ms")

	def do_aes192(self, args):
		"""'aes192' AES symmetric cipher
		AES (Advanced Encryption Standard) is a symmetric block cipher standardized by NIST.
		It has a fixed data block size of 16 bytes. Its keys can be 128, 192, or 256 bits long.
		AES is very fast and secure, and it is the de facto standard for symmetric encryption."""
		obj = ag.ANSIX917(MEDIUM_KEYLEN, LARGE_TIME, LARGE_STATE, 'AES')
		key, time = obj.__next__()
		print("Key with AES192 algorithm: ", key)
		print("Time for generation: ", time, "ms")

	def do_aes256(self, args):
		"""'aes256'AES symmetric cipher
		AES (Advanced Encryption Standard) is a symmetric block cipher standardized by NIST.
		It has a fixed data block size of 16 bytes. Its keys can be 128, 192, or 256 bits long.
		AES is very fast and secure, and it is the de facto standard for symmetric encryption."""
		obj = ag.ANSIX917(LARGE_KEYLEN, LARGE_TIME, LARGE_STATE, 'AES')
		key, time = obj.__next__()
		print("Key with AES256 algorithm: ", key)
		print("Time for generation: ", time, "ms")

	def do_cast(self, args):
		"""'cast' CAST-128 symmetric cipher
		CAST-128 (or CAST5) is a symmetric block cipher specified in RFC2144.
		It has a fixed data block size of 8 bytes. Its key can vary in length
		 from 40 to 128 bits.
		CAST is deemed to be cryptographically secure, but its usage is not widespread.
		Keys of sufficient length should be used to prevent brute force attacks
		(128 bits are recommended)."""
		obj = ag.ANSIX917(SHORT_KEYLEN, SHORT_TIME, SHORT_STATE, 'CAST')
		key, time = obj.__next__()
		print("Key with CAST algorithm: ", key)
		print("Time for generation: ", time, "ms")

	def do_blowfish(self, args):
		"""'blowfish' 
		 Blowfish is a symmetric block cipher designed by Bruce Schneier. It
		 has a fixed data block size of 8 bytes and its keys can vary in length from 32
		 to 448 bits (4 to 56 bytes).
		 Blowfish is deemed secure and it is fast. However,
		 its keys should be chosen to be big enough to withstand a brute force attack
		 (e.g. at least 16 bytes)."""
		obj = ag.ANSIX917(LARGE_KEYLEN, SHORT_TIME, SHORT_STATE, 'BLOWFISH')
		key, time = obj.__next__()
		print("Key with Blowfish algorithm: ", key)
		print("Time for generation: ", time, "ms")

	def do_twofish(self, args):
		obj = ag.ANSIX917(LARGE_KEYLEN, LARGE_TIME, LARGE_STATE, 'Twofish')
		key, time = obj.__next__()
		print("Key with Twofish algorithm: ", key)
		print("Time for generation: ", time, "ms")

	def do_rc5(self, args):
		obj = ag.ANSIX917(SHORT_KEYLEN, LARGE_TIME, LARGE_STATE, 'RC5')
		key, time = obj.__next__()
		print("Key with RC5 algorithm: ", key)
		print("Time for generation: ", time, "ms")	

	def do_idea(self, args):
		obj = ag.ANSIX917(SHORT_KEYLEN, LARGE_TIME, SHORT_STATE, 'IDEA')
		key, time = obj.__next__()
		print("Key with idea algorithm: ", key)
		print("Time for generation: ", time, "ms")	

	def do_exit(self, args):
		"""command for exit of CMD CLI"""
		print("\nBye, have a nice day!")
		exit(0)


def main():
	cli = Cli()
	try:
		cli.cmdloop()
	except KeyboardInterrupt:
		print("Bye, have a nice day!")


if __name__ == '__main__':
	main()
