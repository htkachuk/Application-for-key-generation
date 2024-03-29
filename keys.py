import algorythm as ag

SHORT_TIME = '%S%f'
SHORT_KEYLEN = 16
SHORT_STATE = 8
MEDIUM_KEYLEN = 24
LARGE_KEYLEN = 32
LARGE_TIME = '%m%d%H%M%S%f'
LARGE_STATE = 16

def des():
	obj = ag.ANSIX917(SHORT_KEYLEN, SHORT_TIME, SHORT_STATE, 'DES')
	return obj.__next__()

def aes(t):
	if t == 128:
		obj = ag.ANSIX917(SHORT_KEYLEN, LARGE_TIME, LARGE_STATE, 'AES')
	elif t == 192:
		obj = ag.ANSIX917(MEDIUM_KEYLEN, LARGE_TIME, LARGE_STATE, 'AES')
	else:
		obj = ag.ANSIX917(LARGE_KEYLEN, LARGE_TIME, LARGE_STATE, 'AES')
	return obj.__next__()

def cast():
	obj = ag.ANSIX917(SHORT_KEYLEN, SHORT_TIME, SHORT_STATE, 'CAST')
	return obj.__next__()

def blowfish():
	obj = ag.ANSIX917(LARGE_KEYLEN, SHORT_TIME, SHORT_STATE, 'BLOWFISH')
	return obj.__next__()

def twofish():
	obj = ag.ANSIX917(LARGE_KEYLEN, LARGE_TIME, LARGE_STATE, 'Twofish')
	return obj.__next__()
	
def rc2():
	obj = ag.ANSIX917(SHORT_KEYLEN, SHORT_TIME, SHORT_STATE, 'RC2')
	return obj.__next__()

def rc5():
	obj = ag.ANSIX917(SHORT_KEYLEN, LARGE_TIME, LARGE_STATE, 'RC5')
	return obj.__next__()

def idea():
	obj = ag.ANSIX917(SHORT_KEYLEN, LARGE_TIME, SHORT_STATE, 'IDEA')
	return obj.__next__()

def gost28147():
	obj = ag.ANSIX917(LARGE_KEYLEN, LARGE_TIME, LARGE_STATE, 'GOST28147')
	return obj.__next__()