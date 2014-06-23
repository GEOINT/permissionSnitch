package org.geoint.security.reporter;

import java.security.Permission;
import java.util.ArrayList;
import java.util.List;
import org.geoint.security.spi.SnitchReporter;

/**
 * Stores the operation checks in memory.
 * <p>
 * Useful for unit testing.
 */
public class MemorySnitchReporter extends SnitchReporter {

    private final List<Permission> permissions = new ArrayList<>();

    public Permission[] getPermissions() {
        return permissions.toArray(new Permission[permissions.size()]);
    }

    public void clear() {
        permissions.clear();
    }

    @Override
    public void permission(Permission p) {
        permissions.add(p);
    }

    @Override
    public void permission(Permission p, Object context) {
        permissions.add(p);
    }

}
