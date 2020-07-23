package com.diablo.auth.server.grant.password;

import com.diablo.auth.server.bean.OauthUser;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class PassWordAuthenticationProvider implements AuthenticationProvider {


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PassWordAuthenticationToken authenticationToken = (PassWordAuthenticationToken) authentication;
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        if (!authenticationToken.getUserName().equals("admin") || !authenticationToken.getPassword().equals("123456")){
            throw new InvalidGrantException("账号或密码错误");
        }
        OauthUser user = new OauthUser("1", "admin", "", "name"
                , "depart", "id", authorities);
        PassWordAuthenticationToken authenticationResult = new PassWordAuthenticationToken(user, user.getAuthorities());
        authenticationResult.setDetails(authenticationToken.getDetails());
        return authenticationResult;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PassWordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
