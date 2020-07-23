package com.diablo.auth.server.grant.password;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;

public class PassWordAuthenticationToken extends AbstractAuthenticationToken {

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

    public PassWordAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setAuthenticated(true);
    }

    public PassWordAuthenticationToken(String userName, String password) {
        super(null);
        this.password = password;
        this.userName = userName;
        setAuthenticated(false);
    }
}
