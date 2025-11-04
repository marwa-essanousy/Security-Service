package org.example.securityservicee.web;



import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class API {

    private AuthenticationManager authenticationManager;
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    UserDetailsService userDetailsService;

    public API(AuthenticationManager authenticationManager, JwtEncoder jwtEncoder , JwtDecoder jwtDecoder , UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;

    }

    @PostMapping("/login")
    Map<String , String> login(String username , String password){



        Map<String , String> ID_token = new HashMap<>();

        Instant instant = Instant.now();

        // verifier  l'authentification
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // get scope
        String scope = authenticate.getAuthorities().stream().map(auth-> auth.getAuthority()).collect(Collectors.joining(" "));

        // creation des ID Token
        //1 -Access token
        JwtClaimsSet jwtClaimsSet_access = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security-Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("scope", scope)
                .build();

        String Access_token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_access)).getTokenValue();


        //2 -refrech token
        JwtClaimsSet jwtClaimsSet_refrech = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security-Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(15, ChronoUnit.MINUTES))
                .build();

        String Refrech_token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_access)).getTokenValue();

        ID_token.put("access_token", Access_token);
        ID_token.put("refresh_token", Refrech_token);

        return ID_token;
    }

    @PostMapping("/refresh")
    public Map<String,String> refresh(String refresh_token){
        Map<String , String> ID_token = new HashMap<>();
        Instant instant = Instant.now();


        if(refresh_token == null){
            ID_token.put("Error", "Refresh token is null" + HttpStatus.UNAUTHORIZED);
            return ID_token;
        }

        // verifier signature
        Jwt decoded = jwtDecoder.decode(refresh_token);

        String username = decoded.getSubject();

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        // creation de l'access token

        // get scope
        String scope = userDetails.getAuthorities().stream().map(auth-> auth.getAuthority()).collect(Collectors.joining(" "));

        //1 -Access token
        JwtClaimsSet jwtClaimsSet_access = JwtClaimsSet.builder()
                .subject(userDetails.getUsername())
                .issuer("Security-Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("scope", scope)
                .build();

        String Access_token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_access)).getTokenValue();

        ID_token.put("access_token", Access_token);
        ID_token.put("refresh_token", refresh_token);

        return ID_token;
    }
}
