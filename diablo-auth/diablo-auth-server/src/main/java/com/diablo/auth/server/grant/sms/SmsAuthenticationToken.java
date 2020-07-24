package com.diablo.auth.server.grant.sms;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;

public class SmsAuthenticationToken extends AbstractAuthenticationToken {

    private Object principal;
    private Object credentials;

    @Getter
    private String userName;
    @Getter
    private String password;


    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }

    public SmsAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setAuthenticated(true);
    }

    public SmsAuthenticationToken(String userName, String password) {
        super(null);
        this.password = password;
        this.userName = userName;
        setAuthenticated(false);
    }
}
