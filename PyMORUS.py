__doc__ = """
    A Python3 implementation of the MORUS AEAD encryption scheme (v_X_.0) 
    As released per the CAESAR competition (Honorable Mention Finalist)
    This implementation by Dustin J. Sparks (SparkDustJoe@gmail.com, https://github.com/sparkdustjoe)
    Copyright (c) 2019 under a CC0 License
    """

__all__ = [
    "__title__", "__summary__", "__uri__", "__version__", "__author__",
    "__email__", "__license__", "__copyright__",
]
__title__ = "PyMorus";
__summary__ = "A Python3 library implementation of the MORUS AEAD encryption scheme (v_X_.0)";
__version__ = "0.1";
__uri__ = "https://github.com/sparkdustjoe"
__author__ = "Dustin J. Sparks (based on the original C++ code for spec v_X_.0)";
__email__ = "SparkDustJoe@gmail.com (see repository in GitHub.com/sparkdustjoe for submitting bugs/issues)";
__license__ = "CC0";
__copyright__ = "(c) 2019 Dustin J. Sparks (CC0 License)";

import array;
import sys;

class PyMorus(object):
    """
    A Python3 implementation of the MORUS AEAD encryption scheme (v_X_.0) 
    As released per the CAESAR competition (Honorable Mention Finalist)
    This implementation by Dustin J. Sparks (SparkDustJoe@gmail.com, https://github.com/sparkdustjoe)
    Copyright (c) 2019 under a CC0 License
    """

    def __init__(self, Word_Size_Bits=64):
        """
        Set internal constants and options based on 32-bit or 64-bit architectures
        """
        assert Word_Size_Bits in [32, 64];
        self.MORUS_W_BITS = Word_Size_Bits;
        self.BYTES_WORD = Word_Size_Bits // 8 # integer division
        self.TAG_SIZE_BITS = 128; # constant per spec v2
        self.TAG_SIZE_BYTES = 16; # constant per spec v2
        self.NONCE_SIZE_BITS = 128; # constant per spec v2
        self.NONCE_SIZE_BYTES = 16; # constant per sec v2

        if (self.MORUS_W_BITS == 32):
            self.__rot_const__ = (5,31,7,22,13);
            self.MORUS_W_BITMASK = 0xFFFFFFFF
        else:
            self.__rot_const__ = (13,46,38,7,4);
            self.MORUS_W_BITMASK = 0xFFFFFFFFFFFFFFFF

    def __load__(self, x):
        return int.from_bytes(x, byteorder = 'little', signed = False);
    
    def __load_from__(self, buffer, index, word_size_bytes):
        return self.__load__(buffer[index:index+word_size_bytes]);

    def __store__(self, x):
        return x.to_bytes(length = self.BYTES_WORD, byteorder = 'little');
 
    def __store_into__(self, buffer, index, x):
        the_bytes = self.__store__(x);
        for i in range(0, len(the_bytes)):
            buffer[i + index] = the_bytes[i];
        del the_bytes;

    def __ROTL__(self, a, n):
        return ((a << n) | (a >> (self.MORUS_W_BITS - n))) & self.MORUS_W_BITMASK;

    def __m_funct__(self, a, b, c, m):
        return a ^ (b & c) ^ m;

    def __update__(self, state, msgblk):
        temp = 0;
		# ROUND 1, Row0 ^= Row3 ^ (Row1 BITWISE-AND Row2)
        state[0] ^= self.__m_funct__(state[12], state[4], state[8], 0);
        state[1] ^= self.__m_funct__(state[13], state[5], state[9], 0);
        state[2] ^= self.__m_funct__(state[14], state[6], state[10], 0);
        state[3] ^= self.__m_funct__(state[15], state[7], state[11], 0);

        state[0] = self.__ROTL__(state[0], self.__rot_const__[0]); # Rotl_xxx_yy(S0, b0)
        state[1] = self.__ROTL__(state[1], self.__rot_const__[0]);
        state[2] = self.__ROTL__(state[2], self.__rot_const__[0]);
        state[3] = self.__ROTL__(state[3], self.__rot_const__[0]);

        temp = state[15]; # rotate whole state row 32/64 bits right
        state[15] = state[14];
        state[14] = state[13];
        state[13] = state[12];
        state[12] = temp;

        # ROUND 2, Row1 ^= Row4 ^ (Row2 BITWISE-AND Row3) ^ MSG
        state[4] ^= self.__m_funct__(state[16], state[8], state[12], msgblk[0]);
        state[5] ^= self.__m_funct__(state[17], state[9], state[13], msgblk[1]);
        state[6] ^= self.__m_funct__(state[18], state[10], state[14], msgblk[2]);
        state[7] ^= self.__m_funct__(state[19], state[11], state[15], msgblk[3]);

        state[4] = self.__ROTL__(state[4], self.__rot_const__[1]); # Rotl_xxx_yy(S1, b1)
        state[5] = self.__ROTL__(state[5], self.__rot_const__[1]);
        state[6] = self.__ROTL__(state[6], self.__rot_const__[1]);
        state[7] = self.__ROTL__(state[7], self.__rot_const__[1]);

        temp = state[19] + 0; # rotate whole state row 64/128 bits
        state[19] = state[17];
        state[17] = temp + 0;
        temp = state[18];
        state[18] = state[16];
        state[16] = temp + 0;

        # ROUND 3, Row2 ^= Row0 ^ (Row3 BITWISE-AND Row4) ^ MSG
        state[8] ^= self.__m_funct__(state[0], state[12], state[16], msgblk[0]);
        state[9] ^= self.__m_funct__(state[1], state[13], state[17], msgblk[1]);
        state[10] ^= self.__m_funct__(state[2], state[14], state[18], msgblk[2]);
        state[11] ^= self.__m_funct__(state[3], state[15], state[19], msgblk[3]);

        state[8] = self.__ROTL__(state[8], self.__rot_const__[2]); # Rotl_xxx_yy(S2, b2)
        state[9] = self.__ROTL__(state[9], self.__rot_const__[2]);
        state[10] = self.__ROTL__(state[10], self.__rot_const__[2]);
        state[11] = self.__ROTL__(state[11], self.__rot_const__[2]);

        temp = state[0] + 0; # rotate whole state row 32/64 bits left
        state[0] = state[1];
        state[1] = state[2];
        state[2] = state[3];
        state[3] = temp + 0;

        # ROUND 4, Row3 ^= Row1 ^ (Row4 BITWISE-AND Row0) ^ MSG
        state[12] ^= self.__m_funct__(state[4], state[16], state[0], msgblk[0]);
        state[13] ^= self.__m_funct__(state[5], state[17], state[1], msgblk[1]);
        state[14] ^= self.__m_funct__(state[6], state[18], state[2], msgblk[2]);
        state[15] ^= self.__m_funct__(state[7], state[19], state[3], msgblk[3]);

        state[12] = self.__ROTL__(state[12], self.__rot_const__[3]); # Rotl_xxx_yy(S3, b3)
        state[13] = self.__ROTL__(state[13], self.__rot_const__[3]);
        state[14] = self.__ROTL__(state[14], self.__rot_const__[3]);
        state[15] = self.__ROTL__(state[15], self.__rot_const__[3]);

        temp = state[7] + 0; # rotate whole state row 64/128 bits
        state[7] = state[5];
        state[5] = temp + 0;
        temp = state[6] + 0;
        state[6] = state[4];
        state[4] = temp + 0;

        # ROUND 5, Row4 ^= Row2 ^ (Row0 BITWISE-AND Row1) ^ MSG
        state[16] ^= self.__m_funct__(state[8], state[0], state[4], msgblk[0]);
        state[17] ^= self.__m_funct__(state[9], state[1], state[5], msgblk[1]);
        state[18] ^= self.__m_funct__(state[10], state[2], state[6], msgblk[2]);
        state[19] ^= self.__m_funct__(state[11], state[3], state[7], msgblk[3]);

        state[16] = self.__ROTL__(state[16], self.__rot_const__[4]); # Rotl_xxx_yy(S4, b4)
        state[17] = self.__ROTL__(state[17], self.__rot_const__[4]);
        state[18] = self.__ROTL__(state[18], self.__rot_const__[4]);
        state[19] = self.__ROTL__(state[19], self.__rot_const__[4]);

        temp = state[11] + 0; # rotate whole state row 32/64 bits right
        state[11] = state[10];
        state[10] = state[9];
        state[9] = state[8];
        state[8] = temp + 0;

    def init(self, n, k):
        """
        Initialize the instance of the class to update the state with the Key and Nonce (both are required).
        """
        assert len(n) == self.NONCE_SIZE_BYTES;
        if (self.BYTES_WORD == 4):
            assert len(k) == 16 
        elif (self.BYTES_WORD == 8):
            assert len(k) in (16,32);
        
        state = [ # 5 rows * 4 words
                0,0,0,0, # iv goes here (in 64-bit architecture, indices 2 and 3 are zeros)
			    0,0,0,0, # key goes here
			    self.MORUS_W_BITMASK, self.MORUS_W_BITMASK, self.MORUS_W_BITMASK, self.MORUS_W_BITMASK, # all 1's
			    0,0,0,0, # all 0's if 64-bit architecture, else some 32-bit constants go here
                0,0,0,0]; # constants also go here (either 64-bit or 32-bit)
		#Nonce and Key are processed here
        #32-bit is done differently than 64-bit
        if (self.MORUS_W_BITS == 32):
            #32-bit
            state[0] = self.__load__(n[:4]);
            state[1] = self.__load__(n[4:8]);
            state[2] = self.__load__(n[8:12]);
            state[3] = self.__load__(n[12:16]);
            state[4] = self.__load__(k[:4]);
            state[5] = self.__load__(k[4:8]);
            state[6] = self.__load__(k[8:12]);
            state[7] = self.__load__(k[12:16]);

            state[12] = 0x02010100; #Fibonacci sequence, Little Endian, modulo 256
            state[13] = 0x0d080503;
            state[14] = 0x59372215;
            state[15] = 0x6279e990;
            state[16] = 0x55183ddb;
            state[17] = 0xf12fc26d;
            state[18] = 0x42311120;
            state[19] = 0xdd28b573;
        else:
            #64-bit
            state[0] = self.__load__(n[:8]);
            state[1] = self.__load__(n[8:16]);
            state[4] = self.__load__(k[:8]);
            state[5] = self.__load__(k[8:16]);
            state[16] = 0x0d08050302010100; # same sequence but in 64-bit words
            state[17] = 0x6279e99059372215;
            state[18] = 0xf12fc26d55183ddb;
            state[19] = 0xdd28b57342311120;
            if (len(k) == 16):
                #key is copied twice
                state[6] = self.__load__(k[:8]);
                state[7] = self.__load__(k[8:16]);
            else:
                #full 32-byte key is applied
                state[6] = self.__load__(k[16:24]);
                state[7] = self.__load__(k[24:32]);

        tempKey = state[4:8]; # need temp key down below
        for i in range(0, 16):
            self.__update__(state, (0,0,0,0) ); # update state 16 times with no message block
        for i in range(0, 4):
            state[i + 4] ^= tempKey[i]; # XOR key in a second time after mixing state
            tempKey[i] = 0; # clear tempkey
        del tempKey;
        return state;

    def __finalize__(self, state, adlen, msglen):
        # XOR the first row into the fifth
        state[16] ^= state[0]; 
        state[17] ^= state[1]; 
        state[18] ^= state[2]; 
        state[19] ^= state[3];

		# help prevent forgeries/extension attacks by incorporating plaintext attributes
        # adlen and msglen are provided to this function as byte-counts, but are used in the algorithm as bit-counts,
        #  hence they are multiplied by 8 (left shifted 3 place). they are ALWAYS used as 64-bit numbers in either
        #  architecure of Morus
        
        if (self.MORUS_W_BITS == 32):
            #convert 2 64-bit values into 4 32-bit values
            value = bytearray(self.__store__(adlen << 3));
            while len(value) < 8: #make sure we have a 64-bit number as a byte array 
                value.append(0); # little endigan, so appending zeros is fine
            values = [value];
            value = bytearray(self.__store__(msglen << 3));
            while len(value) < 8:
                value.append(0); # little endigan, so appending zeros is fine
            values.append(value);
            for i in range(0, 10): # update state 10 times
                self.__update__(state, [ 
                    self.__load__(values[0][0:4]), 
                    self.__load__(values[0][4:8]), 
                    self.__load__(values[1][0:4]), 
                    self.__load__(values[1][4:8])
                    ]); 
        else:
            #use 64-bit as is
            for i in range(0, 10): # update state 10 times
                self.__update__(state, (adlen << 3, msglen << 3, 0, 0)); 
        # Row0 ^= (Row1 >>> 64 bits) ^ (Row2 BITWISE-AND Row3), this is output as the tag after this step
        state[0] ^= state[5] ^ (state[8] & state[12]);
        state[1] ^= state[6] ^ (state[9] & state[13]);
        state[2] ^= state[7] ^ (state[10] & state[14]); 
        state[3] ^= state[4] ^ (state[11] & state[15]);

    def aead_encrypt(self, ad, m, n, k):
        """
        Encrypt a message 'm,' incorporating additional data 'ad,' using nonce 'n' and key 'k'
        """
        assert len(n) == self.NONCE_SIZE_BYTES;
        assert self.BYTES_WORD in (4,8);
        wrd_bytes = self.BYTES_WORD
        blk_bytes = 4 * wrd_bytes; 
        if (wrd_bytes == 4):
            assert len(k) == 16 
        elif (wrd_bytes == 8):
            assert len(k) in (16,32);
        state = self.init(n, k);
        ADLen = 0;
        c = None; # defined better later
        if (ad):
            ADLen = len(ad); # byte length of additional data
            for i in range(0, ADLen, blk_bytes):
                if (i + blk_bytes <= ADLen):
                    self.__update__(state, [
                        self.__load_from__(ad, i, wrd_bytes), 
                        self.__load_from__(ad, i + wrd_bytes, wrd_bytes),
                        self.__load_from__(ad, i + (wrd_bytes*2), wrd_bytes),
                        self.__load_from__(ad, i + (wrd_bytes*3), wrd_bytes)
                        ]);
                else:
                    partial = ADLen % blk_bytes;
                    buffer = ad[i:i + partial]; #create a buffer with the partial data 
                    while (len(buffer) < blk_bytes):
                        buffer.append(0); #(zero padding only)
                    self.__update__(state, [ 
                        self.__load_from__(buffer, 0, wrd_bytes), 
                        self.__load_from__(buffer, wrd_bytes, wrd_bytes),
                        self.__load_from__(buffer, wrd_bytes*2, wrd_bytes),
                        self.__load_from__(buffer, wrd_bytes*3, wrd_bytes)
                        ]);
        MSGLen = 0;
        c = bytearray(0);
        if (m):
            MSGLen = len(m);
            c = bytearray(MSGLen);
            partial = MSGLen % blk_bytes;
            for i in range(0, MSGLen, blk_bytes):
                if (i + blk_bytes <= MSGLen):
                    input = [self.__load_from__(m, i, wrd_bytes), 
                        self.__load_from__(m, i + wrd_bytes, wrd_bytes),
                        self.__load_from__(m, i + (2 * wrd_bytes), wrd_bytes),
                        self.__load_from__(m, i + (3 * wrd_bytes), wrd_bytes)];
                    # output = Row0 ^ (Row1 >>> 64 bits) ^ (Row2 BITWISE-AND Row3)
                    output = [input[0] ^ state[0] ^ state[5] ^ (state[8] & state[12]),
                        input[1] ^ state[1] ^ state[6] ^ (state[9] & state[13]),
                        input[2] ^ state[2] ^ state[7] ^ (state[10] & state[14]),
                        input[3] ^ state[3] ^ state[4] ^ (state[11] & state[15])];
                    for j in range(0, 4):
                        self.__store_into__(c, i + (wrd_bytes * j), output[j]);
                    self.__update__(state, input);
            if(partial != 0):
                buffer = m[MSGLen - partial:]; #create a buffer with the partial data
                while (len(buffer) < blk_bytes):
                    buffer.append(0); #(zero padding only)
                input = [self.__load_from__(buffer, 0, wrd_bytes), 
                    self.__load_from__(buffer, wrd_bytes, wrd_bytes),
                    self.__load_from__(buffer, (2 * wrd_bytes), wrd_bytes),
                    self.__load_from__(buffer, (3 * wrd_bytes), wrd_bytes)];
                # output = Row0 ^ (Row1 >>> 64 bits) ^ (Row2 BITWISE-AND Row3)
                output = [input[0] ^ state[0] ^ state[5] ^ (state[8] & state[12]),
                    input[1] ^ state[1] ^ state[6] ^ (state[9] & state[13]),
                    input[2] ^ state[2] ^ state[7] ^ (state[10] & state[14]),
                    input[3] ^ state[3] ^ state[4] ^ (state[11] & state[15])];
                for j in range(0, 4):
                    self.__store_into__(buffer, wrd_bytes * j, output[j]);
                for j in range(0, partial):
                    c[MSGLen - partial + j] = buffer[j];
                self.__update__(state, input);
        self.__finalize__(state, ADLen, MSGLen);
        if (self.BYTES_WORD == 4):
            c.extend(self.__store__(state[0]));
            c.extend(self.__store__(state[1]));
            c.extend(self.__store__(state[2]));
            c.extend(self.__store__(state[3]));
        elif(self.BYTES_WORD == 8):
            c.extend(self.__store__(state[0]));
            c.extend(self.__store__(state[1]));

        return c;


    def aead_decrypt(self, ad, c, n, k):
        """
        Decrypt a ciphertext 'c,' incorporating additional data 'ad,' using nonce 'n' and key 'k'
        """
        assert len(n) == self.NONCE_SIZE_BYTES;
        assert self.BYTES_WORD in (4,8);
        wrd_bytes = self.BYTES_WORD
        blk_bytes = 4 * wrd_bytes; 
        if (wrd_bytes == 4):
            assert len(k) == 16 
        elif (wrd_bytes == 8):
            assert len(k) in (16,32);
        assert c; # must have ciphertext
        assert len(c) >= self.TAG_SIZE_BYTES; # must have at least the tag
        state = self.init(n, k);
        ADLen = 0;
        if (ad):
            ADLen = len(ad); # byte length of additional data
            for i in range(0, ADLen, blk_bytes):
                if (i + blk_bytes <= ADLen):
                    self.__update__(state, [
                        self.__load_from__(ad, i, wrd_bytes), 
                        self.__load_from__(ad, i + wrd_bytes, wrd_bytes),
                        self.__load_from__(ad, i + (wrd_bytes*2), wrd_bytes),
                        self.__load_from__(ad, i + (wrd_bytes*3), wrd_bytes)
                        ]);
                else:
                    partial = ADLen % blk_bytes;
                    buffer = ad[i:i + partial]; #create a buffer with the partial data
                    while (len(buffer) < blk_bytes):
                        buffer.append(0); #(zero padding only)
                    self.__update__(state, [ 
                        self.__load_from__(buffer, 0, wrd_bytes), 
                        self.__load_from__(buffer, wrd_bytes, wrd_bytes),
                        self.__load_from__(buffer, wrd_bytes*2, wrd_bytes),
                        self.__load_from__(buffer, wrd_bytes*3, wrd_bytes)
                        ]);
        MSGLen = 0;
        m = bytearray(0);
        if (c):
            MSGLen = len(c) - self.TAG_SIZE_BYTES;
            m = bytearray(MSGLen);
            partial = MSGLen % blk_bytes;
            for i in range(0, MSGLen, blk_bytes):
                if (i + blk_bytes <= MSGLen):
                    input = [self.__load_from__(c, i, wrd_bytes), 
                        self.__load_from__(c, i + wrd_bytes, wrd_bytes),
                        self.__load_from__(c, i + (2 * wrd_bytes), wrd_bytes),
                        self.__load_from__(c, i + (3 * wrd_bytes), wrd_bytes)];
                    # input ^= Row0 ^ (Row1 >>> 64 bits) ^ (Row2 BITWISE-AND Row3)
                    input[0] ^= state[0] ^ state[5] ^ (state[8] & state[12]);
                    input[1] ^= state[1] ^ state[6] ^ (state[9] & state[13]);
                    input[2] ^= state[2] ^ state[7] ^ (state[10] & state[14]);
                    input[3] ^= state[3] ^ state[4] ^ (state[11] & state[15]);
                    for j in range(0, 4):
                        self.__store_into__(m, i + (wrd_bytes * j), input[j]);
                    self.__update__(state, input);
            if(partial):
                buffer = c[MSGLen - partial:MSGLen]; #create a buffer with the partial data
                while (len(buffer) < blk_bytes):
                    buffer.append(0); #(zero padding only)
                input = [self.__load_from__(buffer, 0, wrd_bytes), 
                    self.__load_from__(buffer, wrd_bytes, wrd_bytes),
                    self.__load_from__(buffer, (2 * wrd_bytes), wrd_bytes),
                    self.__load_from__(buffer, (3 * wrd_bytes), wrd_bytes)];
                # input ^= Row0 ^ (Row1 >>> 64 bits) ^ (Row2 BITWISE-AND Row3)
                input[0] ^= state[0] ^ state[5] ^ (state[8] & state[12]);
                input[1] ^= state[1] ^ state[6] ^ (state[9] & state[13]);
                input[2] ^= state[2] ^ state[7] ^ (state[10] & state[14]);
                input[3] ^= state[3] ^ state[4] ^ (state[11] & state[15]);
                for j in range(0, 4):
                    self.__store_into__(buffer, (wrd_bytes * j), input[j]);
                for j in range(0, blk_bytes):
                    if (j < partial):
                        m[MSGLen - partial + j] = buffer[j];
                    else:
                        buffer[j] = 0; # recreate original whitespace at the end of the plaintext
                input = [self.__load_from__(buffer, 0, wrd_bytes),  
                    self.__load_from__(buffer, wrd_bytes, wrd_bytes),
                    self.__load_from__(buffer, (2 * wrd_bytes), wrd_bytes),
                    self.__load_from__(buffer, (3 * wrd_bytes), wrd_bytes)];            
                self.__update__(state, input);
        tag = bytearray(0);
        self.__finalize__(state, ADLen, MSGLen);
        if (self.BYTES_WORD == 4):
            tag.extend(self.__store__(state[0]));
            tag.extend(self.__store__(state[1]));
            tag.extend(self.__store__(state[2]));
            tag.extend(self.__store__(state[3]));
        else:
            tag.extend(self.__store__(state[0]));
            tag.extend(self.__store__(state[1]));
        if (tag == c[-self.TAG_SIZE_BYTES:]):
            if (m):
                return (True, m);
            else: return (True, None); # don't return empty byte arrays
        else:
            del m;
            return (False, None);
            #if (m): # FOR TESTING PURPOSES ONLY
            #    return (False, m); # FOR TESTING PURPOSES ONLY
            #else: return (False, None); # FOR TESTING PURPOSES ONLY

if (__name__ == "__main__"):
    import PyMorusTESTS;
    import PyMorusTESTCASES;
    PyMorusTESTS.RUN_TESTS();
