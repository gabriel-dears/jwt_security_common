package com.hospital_app.jwt_security_common.application;


import org.springframework.core.io.Resource;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyHandler {

    public static RSAPublicKey getPublicKey(Resource key) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(getFileBytes(key));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static byte[] getFileBytes(Resource key) throws IOException {
        String keyContent = new String(key.getInputStream().readAllBytes())
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(keyContent);
    }


}
