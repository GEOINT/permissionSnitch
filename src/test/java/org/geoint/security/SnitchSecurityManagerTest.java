package org.geoint.security;

import java.io.File;
import java.security.Permission;
import org.geoint.security.reporter.MemorySnitchReporter;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 */
public class SnitchSecurityManagerTest {

    private static SecurityManager sm;
    private static MemorySnitchReporter reporter;
    private static File testFile;
    private static final String TEST_FILE_PREFIX = "securitySnitch";
    private static final String TEST_FILE_SUFFIX = "test";
    private static final String FILE_PERMISSION_WRITE = "write";
    private static final String FILE_PERMISSION_READ = "read";
    private static final String FILE_PERMISSION_DELETE = "delete";

    @BeforeClass
    public static void init() throws Exception {
        reporter = new MemorySnitchReporter();
        sm = new SnitchSecurityManager(reporter);

        testFile = File.createTempFile(TEST_FILE_PREFIX, TEST_FILE_SUFFIX);
        System.setSecurityManager(sm);
    }

    @Before
    public void beforeMethod() {
        reporter.clear();
    }

    @Test
    public void testFileReadPermissionCheck() throws Exception {
        System.out.println("Test file read permission...");
        final String EXPECTED_ACTION = FILE_PERMISSION_READ;
        final String EXPECTED_PATH = testFile.getPath();
        testFile.canRead();

        assertEquals(1, reporter.getPermissions().length);

        //test permission
        Permission p = reporter.getPermissions()[0];
        assertEquals(EXPECTED_PATH, p.getName());
        assertEquals(EXPECTED_ACTION, p.getActions());
    }

    @Test
    public void testFileWritePermission() throws Exception {
        System.out.println("Test file write permission...");
        final String EXPECTED_ACTION = FILE_PERMISSION_WRITE;
        final String EXPECTED_PATH = testFile.getPath();
        testFile.canWrite();

        assertEquals(1, reporter.getPermissions().length);

        //test permission
        Permission p = reporter.getPermissions()[0];
        assertEquals(EXPECTED_PATH, p.getName());
        assertEquals(EXPECTED_ACTION, p.getActions());
    }

    @Test
    public void testFileDeletePermission() throws Exception {
        System.out.println("Test file delete permission...");
        final String EXPECTED_ACTION = FILE_PERMISSION_DELETE;
        final String EXPECTED_PATH = testFile.getPath();
        testFile.deleteOnExit();

        assertEquals(1, reporter.getPermissions().length);

        //test permission
        Permission p = reporter.getPermissions()[0];
        assertEquals(EXPECTED_PATH, p.getName());
        assertEquals(EXPECTED_ACTION, p.getActions());
    }

}
