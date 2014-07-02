package org.geoint.security.reporter;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilePermission;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Permission;
import java.security.ProtectionDomain;
import org.geoint.security.spi.SnitchReporter;

/**
 * Append the checked permissions directly to a file.
 * <p>
 * By default, the file the FileSnitchReporter lists the permissions to is a
 * file named "permissions.snitch" in the default temp directory (java.io.tmpdir
 * system permission). The location of the file can be changed by setting the
 * JVM property {@code org.geoint.snitch.reporter.file} to the desired file
 * location.
 * <p>
 * If there are problems writing to the specified file location, the reporter
 * will save the permissions in the default location (after logging the
 * exception).
 * <p>
 * <b>NOTE:</b>Permission requests for file operations from the
 * FileSnitchReporter if filtered out.
 *
 */
public class FileSnitchReporter extends SnitchReporter {

    private final File outfile;
    private final PrintWriter writer;
    private volatile boolean started = false;

    public static final String PROPERTY_FILE_LOCATION = "org.geoint.snitch.reporter.file";
    private static final String DEFAULT_FILE_NAME = "permissions.snitch";

    public FileSnitchReporter() {
        outfile = determineOutfile();

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                if (writer != null) {
                    writer.flush();
                    writer.close();
                }
            }
        });

        try {
            writer = new PrintWriter(new BufferedOutputStream(new FileOutputStream(outfile, true)));
        } catch (Throwable ex) {
            throw new RuntimeException("Unable to snitch permissions to file", ex);
        }
//        writeHeader(outfile);
        started = true;
    }

    public File getFile() {
        return outfile;
    }

    @Override
    public void permission(Permission p, ProtectionDomain pd) {
        if (filter(p)) {
            //filter out file operation checks for this class
            return;
        }

        writer.append(format(p, pd));
    }


    /**
     * Filters out checks for operations explicitly used by this reporter
     *
     * @param p
     * @return
     */
    private boolean filter(Permission p) {
        if (!started) {
            //snitch reporter isn't started yet...everything before can't 
            //be logged
            return true;
        }

        if (p instanceof FilePermission) {
            FilePermission fp = (FilePermission) p;
            //if request is for the log file, return true (do filter)
            return (fp.getName().contentEquals(outfile.getPath()));
        }

        return false;
    }

    private File determineOutfile() {
        File file;
        final String fn = System.getProperty(PROPERTY_FILE_LOCATION);
        if (fn != null) {
            file = new File(fn);
            if (file.exists()) {
                file.delete();
            }
            try {
                file.createNewFile();
                return file;
            } catch (IOException ex) {
                throw new RuntimeException("Unable to create snitch file", ex);
            }
        }

        file = new File(System.getProperty("java.io.tmpdir")
                + File.separator + DEFAULT_FILE_NAME);
        try {
            file.createNewFile();
        } catch (IOException ex) {
            final String error = "Problem creating snitch out file in tmp "
                    + "directory";
            throw new RuntimeException(error, ex);
        }
        return file;
    }

}
