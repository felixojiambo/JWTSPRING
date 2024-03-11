package com.zep.jwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTService {

    @Value("${encryption.secretKey}")
    private String secretKey;
    public String extractUsername(String token) {
        return  extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver)
    {
        final  Claims claims=extractAllClaims(token);
        return  claimsResolver.apply(claims);

    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .setSigningKey(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
    public  String generateToken(
            Map<String, Object> extractClaims,
            UserDetails userDetails
    ){
        return  Jwts
                .builder()
                .setClaims(extractClaims)
                .subject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() +1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }
    private Key getSignInKey(){
        byte[] keyBytes= Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
