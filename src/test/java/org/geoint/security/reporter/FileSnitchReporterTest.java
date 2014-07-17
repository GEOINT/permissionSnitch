package org.geoint.security.reporter;

import java.io.File;
import org.geoint.security.SnitchSecurityManager;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 */
public class FileSnitchReporterTest {

    private static final String FILE_PERMISSION_WRITE = "write";
    private static final String FILE_PERMISSION_READ = "read";
    private static final String FILE_PERMISSION_DELETE = "delete";

    @After
    public void afterMethod() {
        System.out.flush();
    }

    /**
     * test that explicit file definition works
     *
     * @throws Exception
     */
    @Test
    public void testExplicitFile() throws Exception {
        System.out.println("Test explicit snitch file reporting");

        final String testFileName
                = System.getProperty("java.io.tmpdir") + File.separator + "testSnitchFile";
        System.setProperty(FileSnitchReporter.PROPERTY_FILE_LOCATION, testFileName);
        File f = new File(testFileName);
        f.deleteOnExit();

        FileSnitchReporter reporter = new FileSnitchReporter();
        SecurityManager sm = new SnitchSecurityManager(reporter);
        System.setSecurityManager(sm);

        assertTrue(f.exists());

    }

    @Test
    public void testImplicitTempFile() throws Exception {
        System.out.println("Test implict (tmpdir) snitch file reporting");

        FileSnitchReporter reporter = new FileSnitchReporter();
        reporter.getFile().deleteOnExit();
        SecurityManager sm = new SnitchSecurityManager(reporter);
        System.setSecurityManager(sm);

        assertTrue(reporter.getFile().exists());
    }
}
