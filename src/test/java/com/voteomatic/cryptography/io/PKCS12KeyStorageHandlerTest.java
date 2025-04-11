package com.voteomatic.cryptography.io;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

// Requires setting an environment variable for the password.
// We can use a library like System Rules or Testcontainers for better env var management in tests,
// but for simplicity, we'll assume manual setup or skip if not set.
// Example: export TEST_KEYSTORE_PASSWORD='testpassword'
// Example: export TEST_KEYSTORE_WRONG_PASSWORD='wrongpassword'
@DisabledIfEnvironmentVariable(named = "TEST_KEYSTORE_PASSWORD", matches = ".*", disabledReason = "TEST_KEYSTORE_PASSWORD environment variable not set")
@DisabledIfEnvironmentVariable(named = "TEST_KEYSTORE_WRONG_PASSWORD", matches = ".*", disabledReason = "TEST_KEYSTORE_WRONG_PASSWORD environment variable not set for incorrect password test")
class PKCS12KeyStorageHandlerTest {

    private static final String TEST_PASSWORD_ENV_VAR = "TEST_KEYSTORE_PASSWORD";
    private static final String TEST_WRONG_PASSWORD_ENV_VAR = "TEST_KEYSTORE_WRONG_PASSWORD";
    private static final String PASSWORD_SOURCE = "env:" + TEST_PASSWORD_ENV_VAR;
    private static final String WRONG_PASSWORD_SOURCE = "env:" + TEST_WRONG_PASSWORD_ENV_VAR;

    @TempDir
    Path tempDir;

    private Path keystorePath;
    private PKCS12KeyStorageHandler handler;

    @BeforeEach
    void setUp() throws DataHandlingException {
        // Use assumptions to skip setup and tests if environment variables are not set
        String password = System.getenv(TEST_PASSWORD_ENV_VAR);
        Assumptions.assumeTrue(password != null && !password.isEmpty(),
                "Skipping tests: Environment variable " + TEST_PASSWORD_ENV_VAR + " is not set or is empty.");

        String wrongPassword = System.getenv(TEST_WRONG_PASSWORD_ENV_VAR);
         Assumptions.assumeTrue(wrongPassword != null && !wrongPassword.isEmpty(),
                 "Skipping tests: Environment variable " + TEST_WRONG_PASSWORD_ENV_VAR + " is not set or is empty.");
         Assumptions.assumeTrue(!password.equals(wrongPassword),
                 "Skipping tests: Environment variables " + TEST_PASSWORD_ENV_VAR + " and " + TEST_WRONG_PASSWORD_ENV_VAR + " must have different values.");

        keystorePath = tempDir.resolve("testkeystore.p12");
        handler = new PKCS12KeyStorageHandler(keystorePath.toString(), PASSWORD_SOURCE);
    }

    @Test
    void testWriteAndReadData() throws DataHandlingException {
        String alias = "testAlias";
        byte[] originalData = "This is secret test data".getBytes();

        // Write data
        handler.writeData(alias, originalData);

        // Verify file exists
        assertTrue(Files.exists(keystorePath), "Keystore file should be created after write.");

        // Read data back
        byte[] retrievedData = handler.readData(alias);

        assertArrayEquals(originalData, retrievedData, "Retrieved data should match original data.");
    }

    @Test
    void testReadNonExistentAlias() {
        String alias = "nonExistentAlias";

        // Attempt to read non-existent alias
        DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
            handler.readData(alias);
        });

        assertTrue(exception.getMessage().contains("Alias not found"), "Exception message should indicate alias not found.");
    }

    @Test
    void testOverwriteExistingData() throws DataHandlingException {
        String alias = "overwriteAlias";
        byte[] initialData = "Initial data".getBytes();
        byte[] updatedData = "Updated data".getBytes();

        // Write initial data
        handler.writeData(alias, initialData);
        byte[] retrievedInitial = handler.readData(alias);
        assertArrayEquals(initialData, retrievedInitial, "Initial retrieved data should match.");

        // Write updated data (overwrite)
        handler.writeData(alias, updatedData);
        byte[] retrievedUpdated = handler.readData(alias);
        assertArrayEquals(updatedData, retrievedUpdated, "Updated retrieved data should match.");
    }

    @Test
    void testInitializationCreatesDirectory() throws IOException, DataHandlingException {
        Path deepPath = tempDir.resolve("subdir1/subdir2/deepkeystore.p12");
        // Ensure parent directories do not exist initially
        Files.deleteIfExists(deepPath);
        if (deepPath.getParent() != null) {
             Files.deleteIfExists(deepPath.getParent());
             if (deepPath.getParent().getParent() != null) {
                 Files.deleteIfExists(deepPath.getParent().getParent());
             }
        }

        assertFalse(Files.exists(deepPath.getParent()), "Parent directory should not exist before initialization.");

        // Initialize handler with a path requiring directory creation
        new PKCS12KeyStorageHandler(deepPath.toString(), PASSWORD_SOURCE);

        assertTrue(Files.exists(deepPath.getParent()), "Parent directory should be created during initialization.");
    }

    @Test
    void testLoadWithIncorrectPassword() throws DataHandlingException, IOException {
         String alias = "testAlias";
         byte[] originalData = "Some data".getBytes();
         handler.writeData(alias, originalData); // Write with correct password first

         // Ensure the wrong password env var is actually different
         String correctPassword = System.getenv(TEST_PASSWORD_ENV_VAR);
         String wrongPassword = System.getenv(TEST_WRONG_PASSWORD_ENV_VAR);
         assertNotNull(wrongPassword, TEST_WRONG_PASSWORD_ENV_VAR + " must be set.");
         assertNotEquals(correctPassword, wrongPassword,
                         TEST_PASSWORD_ENV_VAR + " and " + TEST_WRONG_PASSWORD_ENV_VAR + " must have different values.");


         // Create a handler instance using the environment variable containing the incorrect password
         PKCS12KeyStorageHandler handlerWithWrongPassword = new PKCS12KeyStorageHandler(keystorePath.toString(), WRONG_PASSWORD_SOURCE);

         // Attempt to read should fail due to incorrect password during load
         DataHandlingException exception = assertThrows(DataHandlingException.class, () -> {
             handlerWithWrongPassword.readData(alias);
         }, "Reading with incorrect password should throw DataHandlingException.");

         assertTrue(exception.getMessage().contains("Incorrect password") || exception.getCause().getMessage().contains("mac check failed"),
                    "Exception message should indicate incorrect password or MAC failure.");
    }

    @Test
    void testWriteMultipleEntries() throws DataHandlingException {
        String alias1 = "entry1";
        byte[] data1 = "Data for entry 1".getBytes();
        String alias2 = "entry2";
        byte[] data2 = "Data for entry 2".getBytes();

        handler.writeData(alias1, data1);
        handler.writeData(alias2, data2);

        byte[] retrieved1 = handler.readData(alias1);
        byte[] retrieved2 = handler.readData(alias2);

        assertArrayEquals(data1, retrieved1);
        assertArrayEquals(data2, retrieved2);
    }

    // Basic thread safety check - multiple threads writing different aliases
    // Note: This is a basic check; more rigorous concurrency testing might be needed.
    @Test
    void testConcurrentWrites() throws InterruptedException {
        int numThreads = 5;
        Thread[] threads = new Thread[numThreads];
        final boolean[] failures = new boolean[numThreads];

        for (int i = 0; i < numThreads; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    String alias = "concurrentAlias_" + index;
                    byte[] data = ("Concurrent data " + index).getBytes();
                    handler.writeData(alias, data);
                    // Optional: Add a read check immediately after write
                    byte[] retrieved = handler.readData(alias);
                    assertArrayEquals(data, retrieved, "Data mismatch in thread " + index);
                } catch (DataHandlingException | AssertionError e) {
                    failures[index] = true;
                    System.err.println("Error in thread " + index + ": " + e.getMessage());
                    e.printStackTrace();
                }
            });
        }

        for (Thread t : threads) {
            t.start();
        }

        for (Thread t : threads) {
            t.join();
        }

        for (int i = 0; i < numThreads; i++) {
            assertFalse(failures[i], "Thread " + i + " encountered an error.");
            // Verify final state after all threads complete
            try {
                 String alias = "concurrentAlias_" + i;
                 byte[] expectedData = ("Concurrent data " + i).getBytes();
                 byte[] finalData = handler.readData(alias);
                 assertArrayEquals(expectedData, finalData, "Final data check failed for alias " + alias);
            } catch (DataHandlingException e) {
                 fail("Failed to read data written by thread " + i + ": " + e.getMessage());
            }
        }
    }
}