import unittest
from rijndael import AES, encrypt, decrypt
import ctypes

rijndael = ctypes.CDLL('./rijndael.so')


# Unit tests for C implementation of AES between lines 9-68
class TestAESEncrypt(unittest.TestCase):
    def test_aes_encrypt(self):
        """Test the aes_encrypt function."""
        plaintext = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        expected_ciphertext = b'\n\x94\x0b\xb5An\xf0E\xf1\xc3\x94X\xc6S\xeaZ'

        # Define the argument types and return type of the function
        rijndael.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

        # Convert the plaintext and key to ctypes arrays
        plaintext_arr = (ctypes.c_ubyte * len(plaintext))(*plaintext)
        key_arr = (ctypes.c_ubyte * len(key))(*key)

        # Call the function and convert the result to a bytes object
        ciphertext_ptr = rijndael.aes_encrypt_block(plaintext_arr, key_arr)
        ciphertext = bytes(ciphertext_ptr[:16])

        self.assertEqual(ciphertext, expected_ciphertext)
        

class TestAES(unittest.TestCase):
    def setUp(self):
        self.lib = ctypes.CDLL('./rijndael.so')
        self.lib.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)
        self.lib.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)
        self.lib.free.argtypes = [ctypes.c_void_p]


    # unit test 1
    def test_sub_bytes(self):
        """ Test the sub_bytes function. """
        buffer = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        buffer += b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        block = ctypes.create_string_buffer(buffer)
        rijndael.sub_bytes(block)
        expected = b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5'  # First 8 bytes
        expected += b'\x30\x01\x67\x2b\xfe\xd7\xab\x76'  # Next 8 bytes
        expected += b'\x00'  # Trailing null byte
        self.assertEqual(block.raw, expected)
        
    # unit test 2
    def test_shift_rows(self):
        """Test the shift_rows function."""
        buffer = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        block = ctypes.create_string_buffer(buffer)
        rijndael.shift_rows(block)
        expected = b'\x00\x05\n\x0f\x04\t\x0e\x03\x08\r\x02\x07\x0c\x01\x06\x0b'
        self.assertEqual(block.raw[:16], expected)

    
    # unit test 3
    def test_mix_columns(self):
        """Test the mix_columns function."""
        buffer = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        block = ctypes.create_string_buffer(buffer)
        rijndael.mix_columns(block)
        expected = b'\x02\x07\x00\x05\x06\x03\x04\x01\n\x0f\x08\r\x0e\x0b\x0c\t'
        self.assertEqual(block.raw[:16], expected)
        

class TestBlock(unittest.TestCase):
    """
    Tests raw AES-128 block operations.
    """
    def setUp(self):
        self.aes = AES(b'\x00' * 16)

    def test_success(self):
        """ Should be able to encrypt and decrypt block messages. """
        message = b'\x01' * 16
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)

        message = b'a secret message'
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)

    def test_bad_key(self):
        """ Raw AES requires keys of an exact size. """
        with self.assertRaises(AssertionError):
            AES(b'short key')

        with self.assertRaises(AssertionError):
            AES(b'long key' * 10)

    def test_expected_value(self):
        """
        Tests taken from the NIST document, Appendix B:
        http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
        """
        message = b'\x32\x43\xF6\xA8\x88\x5A\x30\x8D\x31\x31\x98\xA2\xE0\x37\x07\x34'
        key     = b'\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C'
        ciphertext = AES(bytes(key)).encrypt_block(bytes(message))
        self.assertEqual(ciphertext, b'\x39\x25\x84\x1D\x02\xDC\x09\xFB\xDC\x11\x85\x97\x19\x6A\x0B\x32')




class TestKeySizes(unittest.TestCase):
    """
    Tests encrypt and decryption using 192- and 256-bit keys.
    """
    def test_192(self):
        aes = AES(b'P' * 24)
        message = b'M' * 16
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(aes.decrypt_block(ciphertext), message)

    def test_256(self):
        aes = AES(b'P' * 32)
        message = b'M' * 16
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(aes.decrypt_block(ciphertext), message)

    def test_expected_values192(self):
        message = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
        aes = AES(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17')
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(ciphertext, b'\xdd\xa9\x7c\xa4\x86\x4c\xdf\xe0\x6e\xaf\x70\xa0\xec\x0d\x71\x91')
        self.assertEqual(aes.decrypt_block(ciphertext), message)

    def test_expected_values256(self):
        message = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
        aes = AES(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f')
        ciphertext = aes.encrypt_block(message)
        self.assertEqual(ciphertext, b'\x8e\xa2\xb7\xca\x51\x67\x45\xbf\xea\xfc\x49\x90\x4b\x49\x60\x89')
        self.assertEqual(aes.decrypt_block(ciphertext), message)


class TestCbc(unittest.TestCase):
    """
    Tests AES-128 in CBC mode.
    """
    def setUp(self):
        self.aes = AES(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'

    def test_single_block(self):
        """ Should be able to encrypt and decrypt single block messages. """
        ciphertext = self.aes.encrypt_cbc(self.message, self.iv)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), self.message)

        # Since len(message) < block size, padding won't create a new block.
        self.assertEqual(len(ciphertext), 16)

    def test_wrong_iv(self):
        """ CBC mode should verify the IVs are of correct length."""
        with self.assertRaises(AssertionError):
            self.aes.encrypt_cbc(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.encrypt_cbc(self.message, b'long iv' * 16)

        with self.assertRaises(AssertionError):
            self.aes.decrypt_cbc(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.decrypt_cbc(self.message, b'long iv' * 16)

    def test_different_iv(self):
        """ Different IVs should generate different ciphertexts. """
        iv2 = b'\x02' * 16

        ciphertext1 = self.aes.encrypt_cbc(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_cbc(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

        plaintext1 = self.aes.decrypt_cbc(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_cbc(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)

    def test_whole_block_padding(self):
        """ When len(message) == block size, padding will add a block. """
        block_message = b'M' * 16
        ciphertext = self.aes.encrypt_cbc(block_message, self.iv)
        self.assertEqual(len(ciphertext), 32)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), block_message)

    def test_long_message(self):
        """ CBC should allow for messages longer than a single block. """
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_cbc(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), long_message)

class TestPcbc(unittest.TestCase):
    """
    Tests AES-128 in CBC mode.
    """
    def setUp(self):
        self.aes = AES(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'

    def test_single_block(self):
        """ Should be able to encrypt and decrypt single block messages. """
        ciphertext = self.aes.encrypt_pcbc(self.message, self.iv)
        self.assertEqual(self.aes.decrypt_pcbc(ciphertext, self.iv), self.message)

        # Since len(message) < block size, padding won't create a new block.
        self.assertEqual(len(ciphertext), 16)

    def test_wrong_iv(self):
        """ CBC mode should verify the IVs are of correct length."""
        with self.assertRaises(AssertionError):
            self.aes.encrypt_pcbc(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.encrypt_pcbc(self.message, b'long iv' * 16)

        with self.assertRaises(AssertionError):
            self.aes.decrypt_pcbc(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.decrypt_pcbc(self.message, b'long iv' * 16)

    def test_different_iv(self):
        """ Different IVs should generate different ciphertexts. """
        iv2 = b'\x02' * 16

        ciphertext1 = self.aes.encrypt_pcbc(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_pcbc(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

        plaintext1 = self.aes.decrypt_pcbc(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_pcbc(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)

    def test_whole_block_padding(self):
        """ When len(message) == block size, padding will add a block. """
        block_message = b'M' * 16
        ciphertext = self.aes.encrypt_pcbc(block_message, self.iv)
        self.assertEqual(len(ciphertext), 32)
        self.assertEqual(self.aes.decrypt_pcbc(ciphertext, self.iv), block_message)

    def test_long_message(self):
        """ CBC should allow for messages longer than a single block. """
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_pcbc(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_pcbc(ciphertext, self.iv), long_message)

class TestCfb(unittest.TestCase):
    """
    Tests AES-128 in CBC mode.
    """
    def setUp(self):
        self.aes = AES(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'

    def test_single_block(self):
        """ Should be able to encrypt and decrypt single block messages. """
        ciphertext = self.aes.encrypt_cfb(self.message, self.iv)
        self.assertEqual(self.aes.decrypt_cfb(ciphertext, self.iv), self.message)

        self.assertEqual(len(ciphertext), len(self.message))

    def test_wrong_iv(self):
        """ CBC mode should verify the IVs are of correct length."""
        with self.assertRaises(AssertionError):
            self.aes.encrypt_cfb(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.encrypt_cfb(self.message, b'long iv' * 16)

        with self.assertRaises(AssertionError):
            self.aes.decrypt_cfb(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.decrypt_cfb(self.message, b'long iv' * 16)

    def test_different_iv(self):
        """ Different IVs should generate different ciphertexts. """
        iv2 = b'\x02' * 16

        ciphertext1 = self.aes.encrypt_cfb(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_cfb(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

        plaintext1 = self.aes.decrypt_cfb(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_cfb(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)

    def test_whole_block_padding(self):
        """ When len(message) == block size, padding will add a block. """
        block_message = b'M' * 16
        ciphertext = self.aes.encrypt_cfb(block_message, self.iv)
        self.assertEqual(len(ciphertext), len(block_message))
        self.assertEqual(self.aes.decrypt_cfb(ciphertext, self.iv), block_message)

    def test_long_message(self):
        """ CBC should allow for messages longer than a single block. """
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_cfb(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_cfb(ciphertext, self.iv), long_message)

class TestOfb(unittest.TestCase):
    """
    Tests AES-128 in CBC mode.
    """
    def setUp(self):
        self.aes = AES(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'

    def test_single_block(self):
        """ Should be able to encrypt and decrypt single block messages. """
        ciphertext = self.aes.encrypt_ofb(self.message, self.iv)
        self.assertEqual(self.aes.decrypt_ofb(ciphertext, self.iv), self.message)

        self.assertEqual(len(ciphertext), len(self.message))

    def test_wrong_iv(self):
        """ CBC mode should verify the IVs are of correct length."""
        with self.assertRaises(AssertionError):
            self.aes.encrypt_ofb(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.encrypt_ofb(self.message, b'long iv' * 16)

        with self.assertRaises(AssertionError):
            self.aes.decrypt_ofb(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.decrypt_ofb(self.message, b'long iv' * 16)

    def test_different_iv(self):
        """ Different IVs should generate different ciphertexts. """
        iv2 = b'\x02' * 16

        ciphertext1 = self.aes.encrypt_ofb(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_ofb(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

        plaintext1 = self.aes.decrypt_ofb(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_ofb(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)

    def test_whole_block_padding(self):
        """ When len(message) == block size, padding will add a block. """
        block_message = b'M' * 16
        ciphertext = self.aes.encrypt_ofb(block_message, self.iv)
        self.assertEqual(len(ciphertext), len(block_message))
        self.assertEqual(self.aes.decrypt_ofb(ciphertext, self.iv), block_message)

    def test_long_message(self):
        """ CBC should allow for messages longer than a single block. """
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_ofb(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_ofb(ciphertext, self.iv), long_message)

class TestCtr(unittest.TestCase):
    """
    Tests AES-128 in CBC mode.
    """
    def setUp(self):
        self.aes = AES(b'\x00' * 16)
        self.iv = b'\x01' * 16
        self.message = b'my message'

    def test_single_block(self):
        """ Should be able to encrypt and decrypt single block messages. """
        ciphertext = self.aes.encrypt_ctr(self.message, self.iv)
        self.assertEqual(self.aes.decrypt_ctr(ciphertext, self.iv), self.message)

        # Stream mode ciphers don't increase message size.
        self.assertEqual(len(ciphertext), len(self.message))

    def test_wrong_iv(self):
        """ CBC mode should verify the IVs are of correct length."""
        with self.assertRaises(AssertionError):
            self.aes.encrypt_ctr(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.encrypt_ctr(self.message, b'long iv' * 16)

        with self.assertRaises(AssertionError):
            self.aes.decrypt_ctr(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.decrypt_ctr(self.message, b'long iv' * 16)

    def test_different_iv(self):
        """ Different IVs should generate different ciphertexts. """
        iv2 = b'\x02' * 16

        ciphertext1 = self.aes.encrypt_ctr(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_ctr(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

        plaintext1 = self.aes.decrypt_ctr(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_ctr(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)

    def test_whole_block_padding(self):
        block_message = b'M' * 16
        ciphertext = self.aes.encrypt_ctr(block_message, self.iv)
        self.assertEqual(len(ciphertext), len(block_message))
        self.assertEqual(self.aes.decrypt_ctr(ciphertext, self.iv), block_message)

    def test_long_message(self):
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_ctr(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_ctr(ciphertext, self.iv), long_message)

class TestFunctions(unittest.TestCase):
    """
    Tests the module functions `encrypt` and `decrypt`, as well as basic
    security features like randomization and integrity.
    """
    def setUp(self):
        self.key = b'master key'
        self.message = b'secret message'
        # Lower workload then default to speed up tests.
        self.encrypt = lambda key, ciphertext: encrypt(key, ciphertext, 10000)
        self.decrypt = lambda key, ciphertext: decrypt(key, ciphertext, 10000)

    def test_success(self):
        """ Should be able to encrypt and decrypt simple messages. """
        ciphertext = self.encrypt(self.key, self.message)
        self.assertEqual(self.decrypt(self.key, ciphertext), self.message)

    def test_long_message(self):
        """ Should be able to encrypt and decrypt longer messages. """
        ciphertext = self.encrypt(self.key, self.message * 100)
        self.assertEqual(self.decrypt(self.key, ciphertext), self.message * 100)

    def test_sanity(self):
        """
        Ensures we are not doing anything blatantly stupid in the
        ciphertext.
        """
        ciphertext = self.encrypt(self.key, self.message)
        self.assertNotIn(self.key, ciphertext)
        self.assertNotIn(self.message, ciphertext)

    def test_randomization(self):
        """ Tests salt randomization.  """
        ciphertext1 = self.encrypt(self.key, self.message)
        ciphertext2 = self.encrypt(self.key, self.message)
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_integrity(self):
        """ Tests integrity verifications. """
        with self.assertRaises(AssertionError):
            ciphertext = self.encrypt(self.key, self.message)
            ciphertext += b'a'
            self.decrypt(self.key, ciphertext)

        with self.assertRaises(AssertionError):
            ciphertext = self.encrypt(self.key, self.message)
            ciphertext = ciphertext[:-1]
            self.decrypt(self.key, ciphertext)

        with self.assertRaises(AssertionError):
            ciphertext = self.encrypt(self.key, self.message)
            ciphertext = ciphertext[:-1] + b'a'
            self.decrypt(self.key, ciphertext)
            
            
       




if __name__ == '__main__':
    unittest.main()

