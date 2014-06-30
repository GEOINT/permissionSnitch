package org.geoint.security.reporter;

import java.security.Permission;
import org.geoint.security.spi.SnitchReporter;

/**
 * Snitch reporter which logs the permission to the standard out console.
 */
public class ConsoleSnitchReporter extends SnitchReporter {

    @Override
    public void permission(Permission p, Object context) {
        System.out.println("[" + context + "] " + p.toString());
    }

}
