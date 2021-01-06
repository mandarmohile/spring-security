package me.amigoscode.springboothelper.security;

import com.google.common.collect.Sets;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static me.amigoscode.springboothelper.security.ApplicationUserPermission.*;

/**
 * 
 * @author Mandar
 * 
 * Its always better to add permissions to Roles.
 *
 */
public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }
    
    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
    
    /*
     
    private final Set<GrantedAuthority> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
    	this.permissions = new HashSet<>();
        permissions.stream().forEach(item -> this.permissions.add(new SimpleGrantedAuthority(item.name())));
    }

    public Set<GrantedAuthority> getPermissions() {
        return permissions;
    }
     */
}
