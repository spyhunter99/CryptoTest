/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.miloss.cryptotest;

import android.util.Base64;
import android.util.Log;

import javax.crypto.*;
import javax.crypto.spec.*;
/**
 * Created by alex on 3/12/16.
 */
public class Tooling {

    public static final String TAG="Tooling";
    /**
     * generates an AES based off of the selected key size
     *
     * @param keysize
     * @return may return null if the key is not of a supported size by the
     * current jdk
     */
    public static String GEN(int keysize) {
        KeyGenerator kgen;
        try {
            kgen = KeyGenerator.getInstance("AES");
            kgen.init(keysize);
            SecretKey skey = kgen.generateKey();
            byte[] raw = skey.getEncoded();
            return Base64.encodeToString(raw, Base64.DEFAULT);
        } catch (Exception ex) {
            Log.e(TAG, "error generating key", ex);
        }
        return null;
    }

    /**
     * Generate a new AES 256 bit encryption key. Once generated, this key
     * can be used to replace the default key.
     *
     * @return a new key
     */
    public static String GEN() {
        return GEN(256);
    }

    static String EN(String cleartext, String key) throws Exception {
        byte[] raw =//skey.getEncoded();
                Base64.decode(key, Base64.DEFAULT); //
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        // Instantiate the cipher
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(cleartext.getBytes());
        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    static String DE(String ciphertext, String key) throws Exception {
        byte[] raw =//skey.getEncoded();
                Base64.decode(key,Base64.DEFAULT); //
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] original = cipher.doFinal(Base64.decode(ciphertext,Base64.DEFAULT));
        return new String(original);
    }

    /**
     * return true is the supplied key is a valid aes key
     *
     * @param key
     * @return true if the key is valid
     */
    public static boolean ValidateKey(String key) {
        try {
            String src = "abcdefghijklmopqrstuvwxyz123567890!@#$%^&*()_+{}|:\">?<,";
            String x = EN(src, key);
            String y = DE(x, key);
            //if the sample text is encryptable and decryptable, and it was actually encrypted
            if (y.equals(src) && !x.equals(y)) {
                return true;
            }
            return false;
        } catch (Exception ex) {
            Log.e(TAG,"Key validation failed! "+ ex.getMessage());
            Log.e(TAG,"Key validation failed! "+ ex.getMessage(), ex);
            return false;
        }
    }

    /**
     * encrypts a password using AES Requires the Unlimited Strength Crypto
     * Extensions
     *
     * @param clear
     * @param key
     * @return encrypted base64 text
     */
    public static String Encrypt(String clear, String key) throws Exception {
        if ((clear == null || clear.length() == 0)) {
            return "";
        }
        if (key == null || key.length() == 0) {
            Log.e(TAG,"The generated encryption key was null or emtpy!");
        }
        try {
            return EN(clear, key);
        } catch (Exception ex) {
            Log.e(TAG,"Cannot encrypt sensitive information! Check to make sure the unlimited strength JCE is installed " + ex.getMessage(), ex);
            throw new Exception("Internal Configuration Error, See Log for details. ");
        }
        // return "";
    }

    /**
     * Decrypts a password or other sensitive data If the parameter is null
     * or empty, an empty string is returned. If the parameter is not
     * encrypted or was encrypted using a different key or it fails to
     * decrypt, the original text is returned.
     *
     * @param cipher encrypted text
     * @param key
     * @return encrypted text
     */
    public static String Decrypt(String cipher, String key) {
        if ((cipher == null || cipher.length() == 0)) {
            return "";
        }
        if (key == null || key.length() == 0) {
            Log.e(TAG,"The generated encryption key was null or emtpy!");
        }
        try {
            return DE(cipher, key);
        } catch (Exception ex) {
            Log.e(TAG,"trouble decrypting data, check to make sure the unlimited strength JCE is installed. If this error occured during deployment, I'll automatically try a smaller key size. " + ex.getMessage(), ex);
        }
        return cipher;

    }
}
