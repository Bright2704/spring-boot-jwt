package tutorialsecurityV2.securityV2.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}

//    นี่คือตัวกรองที่ใช้OncePerRequestFilterจาก Spring Security ใช้เพื่อตรวจสอบสิทธิ์สำหรับคำขอ HTTP ที่เข้ามา
//
//    ตัวกรองจะตรวจสอบAuthorizationส่วนหัวในคำขอ และหากมีอยู่ จะแยกโทเค็น JWT ออกจากส่วนหัว จากนั้นจะใช้ the JwtServiceเพื่อแยกชื่อผู้ใช้ (อีเมล) จาก JWT และเพื่อตรวจสอบความถูกต้องของโทเค็น
//
//    หากโทเค็นถูกต้อง ตัวกรองจะสร้าง a พร้อมUsernamePasswordAuthenticationTokenรายละเอียดผู้ใช้และสิทธิ์ที่โหลดโดย UserDetailsServiceโทเค็นนี้จะถูกตั้งค่าในบริบทความปลอดภัย
//
//        สุดท้าย ตัวกรองจะดำเนินการต่อกับตัวกรองถัดไปในห่วงโซ่ตัวกรองโดยการfilterChain.doFilter(request, response)เรียก