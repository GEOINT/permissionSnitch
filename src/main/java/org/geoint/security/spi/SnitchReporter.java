package org.geoint.security.spi;

import java.security.Permission;
import org.geoint.security.SnitchSecurityManager;

/**
 * SPI interface that logs/reports which operations were requested through the
 * {@link SnitchSecurityManager}.
 */
public abstract class SnitchReporter {

    public abstract void permission(Permission perm, Object context);
    
    protected String policyFormat(Permission p) {
        StringBuilder sb = new StringBuilder();
        sb.append(p.getClass().getName())
                .append(" \"")
                .append(p.getName())
                .append("\" \"")
                .append(p.getActions())
                .append("\";\n");
        return sb.toString();
    }
}
