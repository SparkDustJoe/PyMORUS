import hashlib;
from collections import namedtuple;
from PyMorus import PyMorus;
from PyMorusTESTCASES import PyMorusCases;
import colorama;
from termcolor import cprint;
def RUN_TESTS():
    """
    All internal testing of Morus using Known Answer Tests
    """
    colorama.init();
    cprint("PyMorus Self-Test:", 'cyan');
    #TestCase = namedtuple('TestCase', 'P AD K IV C T');
    
    #32-bit====================================================================================================
    cprint("=== 32-bit-words ===", 'yellow');
    test = PyMorus(32);
    #internals
    S = test.init(bytes(16), bytes(16));
    expected = [ 
        0x25f778b0, 0x38e7705a, 0x65aa5ed2, 0x06fa6389, 
        0x5435e2a1, 0x50b7bd9d, 0xb39b9c7a, 0x298d03b3,
        0x2afa835a, 0xde377d62, 0x7e0ed4af, 0x12391949, 
        0x6f9120af, 0xdfefc159, 0xea4e1691, 0x11c32678,
        0xecdcecbb, 0x106f90bb, 0x946d7ef3, 0x6f05a4bb];
    result = 0;
    for i in range(0,20):
        result |= S[i] ^ expected[i];
        if (result != 0):
            cprint("*FAIL AT" + str(i), 'red');
    if (result != 0): cprint("*32 INIT FAIL!*",'red');
    else: cprint("32 INIT PASS!", 'green');

    #encryption
    cases = PyMorusCases(32);
    for i in range(0,len(cases)):
        expectedHash = 'NO EXPECTATION';
        resultHash = 'NO HASH';
        cprint("--" +  str(i) + "--", 'yellow');
        result = test.aead_encrypt(cases[i].AD, cases[i].P, cases[i].IV, cases[i].K);
        if (cases[i].C): # did the ciphertext (via a Blake2 hash) meet expectations?
            resultHash = result[:]; # hashlib.blake2s(result).digest();
            expectedHash = bytearray(cases[i].C); #bytearray(cases[i].C[:]).extend(cases[i].T);
            expectedHash.extend(cases[i].T);
            #expectedHash = hashlib.blake2s(expectedHash).digest();
        else:
            resultHash = result[:]; # no expected ciphertext, just compare the output tag to the result directly
            expectedHash = cases[i].T[:];
        if (resultHash != expectedHash):
            cprint("*PyMorus 32 Test #" + str(i) + " ENCRYPT FAIL!*", 'red');
            #for j in range(0, len(result)):
            #    if (j < len(expectedHash)):
            #        if (resultHash[j] != expectedHash[j]):
            #            cprint("Mismatch at index " + str(j), 'yellow');
            #        else:
            #            cprint("Match at index    " + str(j), 'cyan');
            print(resultHash);
            print(expectedHash);
        else: cprint("PyMorus 32 Test #" + str(i) + " ENCRYPT Pass!", 'green');
        result = test.aead_decrypt(cases[i].AD, result, cases[i].IV, cases[i].K); # tuple result = (bool, array or None)
        if (result[0] == False): 
            cprint("*PyMorus 32 Test #" + str(i) + " DECRYPT VALIDATION FAIL!*", 'red');
        else: 
            cprint("PyMorus 32 Test #" + str(i) + " DECRYPT Validation Pass!", 'green');
        if (result[1]):
            resultHash = result[1][:]; #hashlib.blake2s(result[1]).digest();
        else:
            resultHash = 'NONE';
        if (cases[i].P):
            expectedHash = cases[i].P[:]; #hashlib.blake2s(cases[i].P).digest();    
        else:
            expectedHash = 'NONE';
        if (resultHash != expectedHash):
            cprint("*PyMorus 32 Test #" + str(i) + " DECRYPT FAIL!*", 'red');
        else: cprint("PyMorus 32 Test #" + str(i) + " DECRYPT Pass!", 'green');

    #64-bit=====================================================================================================
    cprint("=== 64-bit-words ===", 'yellow');
    test = PyMorus(64);
    #internals
    S = test.init(bytes(16), bytes(32));
    expected = [ 
        0x7f8da5df6e440bf1, 0x5e6457e02b2fce24, 0x965d91c4d6662d35, 0x76bd73202dfefd37,
        0x3630785740fc7d91, 0xb2550c5e0baf2b0a, 0x1300f193ea1def45, 0xb96762b275886d9e,
        0x08a2a78a82d39a66, 0x4c5f0c8b0accecd4, 0x6342296b7bc01f87, 0x87bd1730ec7f9176,
        0x5e2955dbdbf605c8, 0x3266b3aac135b5ef, 0xca71599ebb733c1d, 0xb76f385db0a8dc87,
        0x8e68bdb42c6066b4, 0xf503b8ff323da78b, 0x775592526d8f74fc, 0x995f0c86a7676c2a
        ];
    result = 0;
    for i in range(0,20):
        result |= S[i] ^ expected[i];
        if (result != 0):
            cprint("*FAIL AT" + str(i));
    if (result != 0): cprint("*64 INIT FAIL!*", 'red');
    else: cprint("64 INIT PASS!", 'green');
    #encryption
    cases = PyMorusCases(64);
    for i in range(0, len(cases)):
        if (cases[i].P):
            cprint("--" +  str(i) + "--P=" + str(len(cases[i].P)), 'yellow');
        else: cprint("--" +  str(i) + "--P=0", 'yellow');
        result = test.aead_encrypt(cases[i].AD, cases[i].P, cases[i].IV, cases[i].K);
        resultHash = hashlib.blake2s(result).digest();
        if (cases[i].C):
            resultHash = result[:]; 
            expectedHash = bytearray(cases[i].C);
            expectedHash.extend(cases[i].T);
        else:
            expectedHash = hashlib.blake2s(cases[i].T).digest();
        if (resultHash != expectedHash):
            cprint("*PyMorus 64 Test #" + str(i) + " ENCRYPT FAIL!*", 'red');
        else: cprint("PyMorus 64 Test #" + str(i) + " ENCRYPT Pass!", 'green');
        result = test.aead_decrypt(cases[i].AD, result, cases[i].IV, cases[i].K); # tuple result = (bool, array or None)
        if (result[0] == False): 
            cprint("*PyMorus 64 Test #" + str(i) + " DECRYPT VALIDATION FAIL!*", 'red');
        else: 
            cprint("PyMorus 64 Test #" + str(i) + " DECRYPT Validation Pass!", 'green');
        if (result[1]):
            resultHash = hashlib.blake2s(result[1]).digest();
        else:
            resultHash = 'NONE';
        if (cases[i].P):
            expectedHash = hashlib.blake2s(cases[i].P).digest();    
        else:
            expectedHash = 'NONE';
        if (resultHash != expectedHash):
            cprint("*PyMorus 64 Test #" + str(i) + " DECRYPT FAIL!*", 'red');
        else: cprint("PyMorus 64 Test #" + str(i) + " DECRYPT Pass!", 'green');
    cprint("...TESTS COMPLETE.", 'cyan');

if (__name__ == "__main__"):
    RUN_TESTS();
