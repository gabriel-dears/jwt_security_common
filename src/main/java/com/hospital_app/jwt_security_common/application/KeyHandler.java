package com.hospital_app.jwt_security_common.application;


import org.springframework.core.io.Resource;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyHandler {

    public static RSAPublicKey getPublicKey(Resource key) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(getFileBytes(key));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static RSAPrivateKey getPrivateKey(Resource key) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(getFileBytes(key));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }

    private static byte[] getFileBytes(Resource key) throws IOException {
        String keyContent = new String(key.getInputStream().readAllBytes())
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(keyContent);
    }

}
