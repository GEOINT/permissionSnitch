package org.geoint.security.spi;

import java.security.Permission;
import org.geoint.security.SnitchSecurityManager;

/**
 * SPI interface that logs/reports which operations were requested through the
 * {@link SnitchSecurityManager}.
 */
public interface SnitchReporter {

    void permission(Permission p);

    public void permission(Permission perm, Object context);
}
