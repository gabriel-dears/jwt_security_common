package com.hospital_app.jwt_security_common.infra.utils;

import com.hospital_app.jwt_security_common.application.KeyHandler;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class JwtUtils {

    @Value("classpath:private.key")
    private Resource privateKeyResource;

    public String generateToken(String username, String role) throws JOSEException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(username)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(TimeUnit.HOURS.toSeconds(1))))
                .claim("role", role)
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
        SignedJWT signedJWT = new SignedJWT(header, claims);

        JWSSigner signer = new RSASSASigner(KeyHandler.getPrivateKey(privateKeyResource));
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

}
