package tutorialsecurityV2.securityV2.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    )   {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 *24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}

//    คลาสJwtServiceนี้เป็นบริการสำหรับจัดการ JSON Web Tokens (JWTs) JWT ใช้เพื่อวัตถุประสงค์ในการตรวจสอบสิทธิ์และอนุญาตให้เซิร์ฟเวอร์ตรวจสอบสิทธิ์ผู้ใช้ตามโทเค็น
//
//    คลาสมีหลายวิธีในการสร้าง ดึงข้อมูล และตรวจสอบความถูกต้องของ JWTs:
//
//        extractUsername: แยกชื่อผู้ใช้จาก JWT
//        extractClaim: แยกการอ้างสิทธิ์จาก JWT โดยใช้ฟังก์ชันตัวแก้ไขการอ้างสิทธิ์
//        generateToken: สร้าง JWT พร้อมรายละเอียดผู้ใช้ที่กำหนด
//        isTokenValid: ตรวจสอบความถูกต้องของ JWT โดยตรวจสอบว่าชื่อผู้ใช้ในโทเค็นเหมือนกับรายละเอียดผู้ใช้ที่กำหนดหรือไม่ และโทเค็นยังไม่หมดอายุหรือไม่
//        isTokenExpired: ตรวจสอบว่า JWT หมดอายุหรือไม่
//        extractExpiration: แยกวันหมดอายุจาก JWT
//        extractAllClaims: แยกการอ้างสิทธิ์ทั้งหมดจาก JWT
//        getSignInKey: รับรหัสสำหรับการลงนาม JWT
//        ค่าSECRET_KEYคงที่ใช้เพื่อลงชื่อ JWT และควรเก็บเป็นความลับ วิธี การgenerateTokenสร้าง JWT โดยการตั้งค่าการอ้างสิทธิ์ หัวเรื่อง (ชื่อผู้ใช้) วันที่ออก วันหมดอายุ และการลงนาม JWT ด้วยSECRET_KEYอัลกอริทึมลายเซ็น HS256 และ
//
//        และ วิธี extractClaimการextractAllClaimsใช้ตัวแยกวิเคราะห์ JWT เพื่อแยกวิเคราะห์ JWT และแยกการอ้างสิทธิ์ ในการตรวจสอบ JWT isTokenValidเมธอดจะแยกชื่อผู้ใช้จาก JWT และเปรียบเทียบกับรายละเอียดผู้ใช้ที่กำหนด และตรวจสอบว่าโทเค็นยังไม่หมดอายุหรือไม่
