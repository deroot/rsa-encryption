package com.example.demo.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Helper class for RSA encryption and decryption, signing and verifying signatures.
 * It can also deal with data longer then the given RSA block size.
 *
 * @author Luis Michaelis <luismichaelis@web.de>
 *     https://gist.github.com/LuisMichaelis/53c40a1681607e758d4e65b85f210117
 */
public class RSA {

    /**
     * The RSA key size.
     */
    public static final int RSA_KEY_SIZE = 2048;

    /**
     * The length the encrypted data will have depending on the key size.
     * Do not change this!
     */
    public static final int RSA_ENCRYPTION_LENGTH = RSA_KEY_SIZE / 8;

    /**
     * The maximum length of bytes which can be encrypted by the Java RSA implementation
     * depending on the key size. Do not change this!
     */
    public static final int RSA_BLOCK_SIZE = RSA_ENCRYPTION_LENGTH - 11;

    /**
     * Generates a new RSA key pair with a length of {@link #RSA_KEY_SIZE}
     *
     * @return The newly generated key pair
     */
    public static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(RSA_KEY_SIZE);

            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected: No RSA algorithm found!", e);
        }
    }

    /**
     * Encrypts the given bytes into a byte array. Do not use this method, if you have
     * data longer than {@link #RSA_BLOCK_SIZE}. Use {@link #encryptLong(PublicKey, byte[])} or
     * {@link #encryptString(PublicKey, String)} instead.
     *
     * @param key   The public key to encrypt the data with
     * @param plain The data to encrypt
     * @return The encrypted data
     */
    public static byte[] encrypt(PublicKey key, byte[] plain) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            return cipher.doFinal(plain);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected: No RSA algorithm found!", e);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            throw new RuntimeException("Error encrypting some data!", e);
        }
    }

    /**
     * Encrypts data longer than {@link #RSA_BLOCK_SIZE} into an array of encrypted
     * byte arrays
     *
     * @param key   The public key to encrypt the data with
     * @param plain The data to encrypt
     * @return The encrypted data chunks.
     */
    public static byte[][] encryptLong(PublicKey key, byte[] plain) {
        byte[][] chunks = splitIntoChunks(plain, RSA.RSA_BLOCK_SIZE);
        byte[][] encryptedChunks = new byte[chunks.length][RSA.RSA_ENCRYPTION_LENGTH];

        for (int i = 0; i < chunks.length; i++) {
            encryptedChunks[i] = RSA.encrypt(key, chunks[i]);
        }

        return encryptedChunks;
    }

    /**
     * Encrypts a string using {@link #encryptLong(PublicKey, byte[])}, generates a single array out of the chunk
     * array using {@link #joinFromChunks(byte[][])} and encodes this array using Base64.
     *
     * @param key   The key to encrypt the string with
     * @param plain The plain text string to encrypt
     * @return The encrypted bytes encoded using Base64
     */
    public static String encryptString(PublicKey key, String plain) {
        byte[][] encrypted = encryptLong(key, plain.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(joinFromChunks(encrypted));
    }

    /**
     * Decrypts the given bytes into a byte array. Do not use this method, if you have
     * data longer than {@link #RSA_BLOCK_SIZE}. Use {@link #decryptLong(PrivateKey, byte[][])} or
     * {@link #decryptString(PrivateKey, String)} instead.
     *
     * @param key       The private key to decrypt the data with
     * @param encrypted The data to decrypt
     * @return The decrypted data
     */
    public static byte[] decrypt(PrivateKey key, byte[] encrypted) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);

            return cipher.doFinal(encrypted);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected: No RSA algorithm found!", e);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            throw new RuntimeException("Error decrypting some data!", e);
        }
    }

    /**
     * Decrypts data longer than {@link #RSA_BLOCK_SIZE} from an array of encrypted byte arrays.
     *
     * @param key             The private key to decrypt the data with
     * @param encryptedChunks The data to decrypt
     * @return The decrypted data.
     */
    public static byte[] decryptLong(PrivateKey key, byte[][] encryptedChunks) {
        byte[][] decryptedChunks = new byte[encryptedChunks.length][RSA.RSA_BLOCK_SIZE];

        for (int i = 0; i < encryptedChunks.length; i++) {
            decryptedChunks[i] = RSA.decrypt(key, encryptedChunks[i]);
        }

        return joinFromChunks(decryptedChunks);
    }

    /**
     * Decrypts a string from Base64 encoded, joined byte arrays using {@link #decryptLong(PrivateKey, byte[][])}.
     *
     * @param key       The key to decrypt the string with
     * @param encrypted The encrypted text string to decrypt
     * @return The decrypted string
     */
    public static String decryptString(PrivateKey key, String encrypted) {
        byte[] encoded = Base64.getDecoder().decode(encrypted);
        byte[][] decoded = splitIntoChunks(encoded, RSA_ENCRYPTION_LENGTH);

        return new String(decryptLong(key, decoded), UTF_8);
    }

    /**
     * Signs the given data and returns the signature
     *
     * @param key  The key to sign with
     * @param data The data to sign
     * @return The signature as a byte array
     */
    public static byte[] sign(PrivateKey key, byte[] data) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(data);

            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected: No RSA algorithm found!", e);
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException("Error signing some data!", e);
        }
    }

    /**
     * Signs the given string and returns the signature
     *
     * @param key  The key to sign with
     * @param data The data to sign
     * @return The signature encoded as Base64
     */
    public static String sign(PrivateKey key, String data) {
        return Base64.getEncoder().encodeToString(sign(key, data.getBytes(UTF_8)));
    }

    /**
     * Verifies a signature.
     *
     * @param key  The key to verify with
     * @param data The plain data to test against
     * @param sig  The signature
     * @return <code>true</code> if the signature could be verified, <code>false</code> if not.
     */
    public static boolean verify(PublicKey key, byte[] data, byte[] sig) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(key);
            signature.update(data);

            return signature.verify(sig);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected: No RSA algorithm found!", e);
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException("Error verifying some data!", e);
        }
    }

    /**
     * Verifies a signature.
     *
     * @param key  The key to verify with
     * @param data The plain text data to test against
     * @param sig  The Base64 encoded signature
     * @return <code>true</code> if the signature could be verified, <code>false</code> if not.
     */
    public static boolean verify(PublicKey key, String data, String sig) {
        return verify(key, data.getBytes(UTF_8), Base64.getDecoder().decode(sig));
    }

    /**
     * Converts a key into a Base64 encoded string
     *
     * @param key The key to convert
     * @return The key encoded in Base64
     */
    public static String asString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Converts a Base64 encoded string into a private key.
     *
     * @param s The encoded key
     * @return The generated private key
     */
    public static PrivateKey privateFromString(String s) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(s)));
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Unexpected: Wrong key spec!", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected: No RSA algorithm found!", e);
        }
    }

    /**
     * Converts a Base64 encoded string into a public key.
     *
     * @param s The encoded key
     * @return The generated public key
     */
    public static PublicKey publicFromString(String s) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(s)));
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Unexpected: Wrong key spec!", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected: No RSA algorithm found!", e);
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // Array Utilities
    ///////////////////////////////////////////////////////////////////////////


    /**
     * Splits the given data bytes into an array of chunks with the given length
     *
     * @param dataBytes The bytes to split
     * @param length    The desirec chunk length
     * @return The split-up byte array
     */
    private static byte[][] splitIntoChunks(byte[] dataBytes, int length) {
        int chunkCount = (int) Math.ceil((double) dataBytes.length / (double) length);
        byte[][] chunks = new byte[chunkCount][length];

        for (int i = 0; i < chunkCount; i++) {
            System.arraycopy(Arrays.copyOfRange(dataBytes, length * i, length * i + length), 0, chunks[i], 0, length);
        }

        return chunks;
    }

    /**
     * Joins a given array of byte arrays into a single byte array.
     * All trailing zeroes however are removed to deal with text input.
     * If you don't want the trailing zeroes to be removed, please use
     * {@link #joinFromChunksPreserved(byte[][])}.
     *
     * @param chunks The array of arrays to join
     * @return The joined byte array
     */
    private static byte[] joinFromChunks(byte[][] chunks) {
        byte[] joined = new byte[chunks.length * chunks[0].length];

        for (int i = 0; i < chunks.length; i++) {
            System.arraycopy(chunks[i], 0, joined, chunks[i].length * i, chunks[i].length);
        }

        return removeTrailingZeroes(joined);
    }

    /**
     * Joins a given array of byte arrays into a single byte array while keeping all leading and trailing zeroes.
     *
     * @param chunks The array of arrays to join
     * @return The joined byte array
     */
    private static byte[] joinFromChunksPreserved(byte[][] chunks) {
        byte[] joined = new byte[chunks.length * chunks[0].length];

        for (int i = 0; i < chunks.length; i++) {
            System.arraycopy(chunks[i], 0, joined, chunks[i].length * i, chunks[i].length);
        }

        return joined;
    }

    /**
     * Removes all trailing zeroes from a byte array.
     *
     * @param bytes The array to remove the trailing zeroes from
     * @return The new, trimmed array
     */
    private static byte[] removeTrailingZeroes(byte[] bytes) {
        int idx = bytes.length;

        for (int i = bytes.length - 1; i >= 0; i--) {
            if (bytes[i] != 0) {
                idx = i;
                break;
            }
        }

        return Arrays.copyOfRange(bytes, 0, idx + 1);
    }

}