package org.geoint.security.spi;

import java.net.URL;
import java.security.CodeSource;
import java.security.Permission;
import java.security.ProtectionDomain;
import org.geoint.security.SnitchSecurityManager;

/**
 * SPI interface that logs/reports which operations were requested through the
 * {@link SnitchSecurityManager}.
 */
public abstract class SnitchReporter {

    public abstract void permission(Permission perm, ProtectionDomain pd);
    
//    protected String format(Permission p, Object context) {
//        StringBuilder sb = new StringBuilder();
//        sb.append(p.getClass().getName())
//                .append(" \"")
//                .append(p.getName())
//                .append("\" \"")
//                .append(p.getActions())
//                .append("\";\n");
//        return sb.toString();
//    }
    
    protected String format (Permission p, ProtectionDomain pd) {
        final CodeSource cs = pd.getCodeSource();

        if ( null == cs ) {
            return null;
        }
        final URL url = cs.getLocation();
        if( null == url ) {
           return null;
        }
        
        final StringBuilder sb = new StringBuilder();
        sb.append("grant codeBase \"");
        sb.append(url.toString());
        sb.append("\" {");
        sb.append("permission ");
        sb.append(" ");
        sb.append(p.getClass().getName());
        sb.append(" ");
        sb.append("\"");

        /* Some complex permissions have quoted strings embedded or
        literal carriage returns that must be escaped.  */

        final String permissionName = p.getName();
        final String escapedPermissionName = permissionName.replace("\"","\\\"").replace("\r","\\\r");

        sb.append(escapedPermissionName);
        sb.append("\", ");
        sb.append("\"");
        sb.append(p.getActions());
        sb.append("\";");
        sb.append("};");
        return sb.toString();
    }
}
