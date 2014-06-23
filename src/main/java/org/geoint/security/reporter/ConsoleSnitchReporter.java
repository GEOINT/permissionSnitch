package org.geoint.security.reporter;

import java.security.Permission;
import org.geoint.security.spi.SnitchReporter;

/**
 * Snitch reporter which logs the permission to the standard out console.
 */
public class ConsoleSnitchReporter implements SnitchReporter {

    @Override
    public void permission(Permission p) {
        log(p);
    }

    @Override
    public void permission(Permission p, Object context) {
        log(p);
    }

    private void log(Permission p) {
        System.out.println(p.toString());
    }
}
