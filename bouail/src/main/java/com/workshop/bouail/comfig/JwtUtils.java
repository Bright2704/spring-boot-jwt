package com.workshop.bouail.comfig;

import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    
    private String jwtSigningKey = "secret";
    
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

   public Date extractExpiration(String token) {return extractClaim(token, Claims::getExpiration);}

    public boolean hasClaim(String token, String claimName) {
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName) != null;
    }
}
