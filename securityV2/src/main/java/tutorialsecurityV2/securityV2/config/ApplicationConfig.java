package tutorialsecurityV2.securityV2.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import tutorialsecurityV2.securityV2.user.UserRepository;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
    
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

//    รหัสนี้กำหนดคอนฟิกูเรชันความปลอดภัยสำหรับเว็บแอปพลิเคชัน Java
//
//    ฟิลด์ นี้UserRepositoryเป็นอินสแตนซ์ของคลาสที่เก็บซึ่งใช้เพื่อเข้าถึงข้อมูลผู้ใช้ที่จัดเก็บไว้ในฐานข้อมูล
//
//    userDetailsServiceเมธอดส่งคืนอินUserDetailsServiceสแตนซ์ที่ใช้ในการโหลดรายละเอียดของผู้ใช้ตามชื่อผู้ใช้ การดำเนินการUserDetailsServiceดึงข้อมูลผู้ใช้จากการUserRepositoryโทรrepository.findByEmail(username)
//
//        เมธอดauthenticationProviderส่งคืนอินสแตนซ์ของDaoAuthenticationProviderซึ่งเป็นการใช้งานAuthenticationProviderอินเทอร์เฟซ อินสแตนซ์นี้ใช้เพื่อรับรองความถูกต้องของผู้ใช้โดยการเปรียบเทียบข้อมูลรับรองกับรายละเอียดผู้ใช้ที่จัดเก็บไว้ในฐานข้อมูล มีDaoAuthenticationProviderการกำหนดค่าให้ใช้userDetailsServiceand passwordEncoderbean
//
//        authenticationManagerเมธอดส่งคืนอินสแตนซ์ของคลาสAuthenticationManagerซึ่งเป็นอินเทอร์เฟซส่วนกลางในกลไกการพิสูจน์ตัวตนของ Spring Security อินสแตนซ์นี้ได้มาจากการconfig.getAuthenticationManager()โทร
//
//        เมธอดpasswordEncoderส่งคืนอินสแตนซ์ของBCryptPasswordEncoderซึ่งใช้ในการเข้ารหัสและตรวจสอบรหัสผ่านอย่างปลอดภัย รหัสผ่านที่เข้ารหัสจะถูกจัดเก็บไว้ในฐานข้อมูล และรหัสผ่านดิบที่ผู้ใช้ป้อนจะถูกเปรียบเทียบกับรหัสผ่านที่เข้ารหัสสำหรับการรับรองความถูกต้อง