package org.geoint.security;

import java.security.Permission;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.HashSet;
import java.util.Set;
import org.geoint.security.reporter.ConsoleSnitchReporter;
import org.geoint.security.spi.SnitchReporter;

/**
 * {@link SecurityManager} implementation which approves all requested
 * permissions, logging the requested permission in the processes.
 * <p>
 * <b>WARNING: </b>
 * <p>
 * This SecurityManager implementation <b>should not</b> be used in production.
 * The purpose of this class is to figure out which permissions an application
 * needs, useful in debugging, documenting, and preparing to deploy a 3rd party
 * application in a security managed environment. Again, this implementation is
 * <b>not</b> secure for production use.
 * <h1>How to use the SnitchSecurityManager</h1>
 * <h2>JVM Property</h2>
 * Most of the time, you'll want to use the SnitchSecurityManager in a similar
 * environment the target application will be running. For example, if the
 * application in question is a war, you'll want to run it within an application
 * server that can run that war. The most portable way to make use of the
 * SnitchSecurityManager is to set the {@code java.security.manager } JVM
 * property with the fully qualified class name:
 * <p>
 * {@code -Djava.security.manager=org.geoint.security.SnitchSecurityManager }
 * <h2>Programmatic</h2>
 * Another option is to set the SecurityManager using the 
 * {@link System#setSecurityManager(java.lang.SecurityManager) } method. You'll
 * probably want to do this at/near startup of the application, to ensure you
 * get everything.
 *
 *
 */
public class SnitchSecurityManager extends SecurityManager {

    /**
     * JVM property that defines which {@link SnitchReporter} to use.
     * <p>
     * By default, the {@link ConsoleSnitchReporter} is used.
     */
    public final static String PROPERTY_SM_SNITCH_REPORTER
            = "org.geoint.security.snitch.reporter";
    private final SnitchReporter reporter;
    private final String thisJar = this.getClass().getProtectionDomain().getCodeSource().getLocation().toString();
    private final static String thisClass = SnitchSecurityManager.class.getName();
    private final Set<String> permsCache = new HashSet<>();

    public SnitchSecurityManager() {
        reporter = loadReporter();
    }

    public SnitchSecurityManager(SnitchReporter reporter) {
        this.reporter = reporter;
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        checkPermission(perm);
    }

    @Override
    public void checkPermission(Permission perm) {
        final String p = perm.toString();
        if (permsCache.contains(perm.toString())) {
            return;
        }
        permsCache.add(p);

        try {
            String className = getOriginatingClass(perm);
            ProtectionDomain pd = getProductionDomain(className);
            if (pd.getCodeSource() != null) {
                reporter.permission(perm, pd);
            }
        } catch (RecursivePermissionException ex) {
            //do nothing
        }
    }

    private SnitchReporter loadReporter() {
        final String reporterType
                = System.getProperty(PROPERTY_SM_SNITCH_REPORTER,
                        ConsoleSnitchReporter.class.getName());
        try {
            return (SnitchReporter) Class.forName(reporterType).newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException ex) {
            StringBuilder sb = new StringBuilder();
            sb.append("Unable to load snitch reporter '")
                    .append(reporterType)
                    .append("', using the JulSnitchReporter instead.")
                    .append(ex.toString());
            System.err.println(sb.toString());
            return new ConsoleSnitchReporter();
        }
    }

    private ProtectionDomain getProductionDomain(String clazz) {
        Class c = null;
        try {
            c = Class.forName(clazz);
        } catch (ClassNotFoundException ex) {
            //we know this is fine, we get the class name from a StackTrace
        }
        PrivilegedAction<ProtectionDomain> papd = getProtectionDomainAction(c);
        return papd.run();
    }

    private PrivilegedAction<ProtectionDomain> getProtectionDomainAction(
            final Class<?> clazz) {
        return new PrivilegedAction<ProtectionDomain>() {
            @Override
            public ProtectionDomain run() {
                return clazz.getProtectionDomain();
            }
        };
    }

    /**
     * returns the originating class name from the current stack trace.
     *
     * @param p
     * @return
     */
    private String getOriginatingClass(Permission p)
            throws RecursivePermissionException {
        final Throwable t = new Throwable();
        final StackTraceElement[] ste = t.getStackTrace();
        for (StackTraceElement s : ste) {
            if (s.getClassName().contentEquals(thisClass)
                    && s.getMethodName().contentEquals("getProductionDomain")) {
                throw new RecursivePermissionException();
            }
        }
        return ste[ste.length - 1].getClassName();
    }

    /**
     * Thrown when the permission request was made by the permission snitch
     * application itself
     */
    private class RecursivePermissionException extends Exception {

    }
}
