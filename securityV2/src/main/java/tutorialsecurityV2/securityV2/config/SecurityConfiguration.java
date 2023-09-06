package tutorialsecurityV2.securityV2.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        

        return http.build();
    }
}

//    นี่คือคลาสการกำหนดค่าในแอปพลิเคชัน Spring Security ตั้งค่าความปลอดภัยสำหรับแอปพลิเคชันโดยใช้เฟรมเวิร์ก Spring Security คลาส นี้SecurityConfigurationมีคำอธิบายประกอบด้วย@Configurationและ@EnableWebSecurityเพื่อระบุว่าเป็นคลาสคอนฟิกูเรชันเพื่อความปลอดภัยของแอ็พพลิเคชัน
//
//ชั้นเรียนมีสองฟิลด์: jwtAuthFilterและ authenticationProviderเป็นjwtAuthFilterตัวกรองที่ใช้ในการตรวจสอบความถูกต้องของโทเค็น JWT เป็นการauthenticationProviderดำเนินการAuthenticationProviderที่ให้ตรรกะการรับรองความถูกต้อง
//
//        ในsecurityFilterChainวิธีการ นี้ HttpSecurityวัตถุจะถูกใช้เพื่อกำหนดค่าความปลอดภัยของแอปพลิเคชัน วิธีการ นี้csrf()เรียกว่าเพื่อปิดใช้งานการป้องกันการปลอมแปลงคำขอข้ามไซต์ (CSRF) เมธอด นี้authorizeHttpRequests()ถูกเรียกเพื่อระบุกฎการอนุญาตสำหรับแอ็พพลิเคชัน ในกรณีนี้ คำขอทั้งหมดจะ/api/v1/auth/**ได้รับอนุญาตโดยไม่ต้องมีการรับรองความถูกต้อง ในขณะที่คำขออื่นๆ ทั้งหมดจะต้องได้รับการตรวจสอบความถูกต้อง
//
// เมธอด นี้sessionManagement()เรียกเพื่อตั้งค่านโยบายการสร้างเซสชันเป็นSessionCreationPolicy.STATELESSซึ่งหมายความว่าแอปพลิเคชันจะไม่สร้างเซสชัน จากauthenticationProviderนั้นตั้งค่าโดยใช้authenticationProviderวิธีการ สุดท้าย the jwtAuthFilterจะถูกเพิ่มเข้าไปในห่วงโซ่ตัวกรองโดยใช้addFilterBeforeเมธอด โดยมีUsernamePasswordAuthenticationFilter.classเป็นตัวกรองอ้างอิง securityFilterChainเมธอดส่งคืนอ็HttpSecurityอบเจกต์หลังจากคอนฟิกูเรชันเสร็จสิ้น
