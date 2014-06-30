package org.geoint.security.formatter;

import java.security.Permission;

/**
 * Formats one or more permissions.
 *
 * The formatter is designed to accept multiple permissions prior to formatting,
 * allowing for multiple permissions to be added to a single context (ie
 * PermissionDomain).
 */
public interface PermissionFormatter {

    PermissionFormatter add(Permission permission);

    String format();
}
