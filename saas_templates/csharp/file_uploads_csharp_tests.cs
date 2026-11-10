using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using FileUploads;

namespace FileUploadsTests
{
    public static class Tests
    {
        private static readonly byte[] HmacKey = Encoding.UTF8.GetBytes("test-secret-key-123456-7890-abcdef");

        private static void Assert(bool condition, string message)
        {
            if (!condition) throw new Exception("Assertion failed: " + message);
        }

        private static void AssertThrows<T>(Action action, string message) where T : Exception
        {
            try
            {
                action();
                throw new Exception("Expected exception not thrown: " + message);
            }
            catch (T) { }
            catch (Exception ex)
            {
                throw new Exception($"Unexpected exception type: {ex.GetType()}, message: {ex.Message}");
            }
        }

        /// <summary>The test clock; tests move it forward instead of sleeping (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).</summary>
        private static DateTimeOffset _now = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

        /// <summary>
        /// Builds a service over an in-memory store and a fresh temporary directory, with the test clock.
        /// Out: the service, the store, the directory and the membership set ("user:org").
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: passes the injectable clock. Touches: a temp directory.
        /// </summary>
        private static FileUploadService CreateService(out InMemoryFileStore store, out string storageDir, out HashSet<string> members, long sizeLimitBytes = 10 * 1024 * 1024)
        {
            store = new InMemoryFileStore();
            storageDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            HashSet<string> membersSet = new HashSet<string>();
            members = membersSet;
            Func<Guid, Guid, bool> isMember = (u, o) => membersSet.Contains($"{u}:{o}");
            return new FileUploadService(store, storageDir, HmacKey, isMember, sizeLimitBytes, () => _now);
        }

        private static void CleanupDirectory(string dir)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    Directory.Delete(dir, true);
                }
            }
            catch { }
        }

        // UPLOAD-01
        public static void TestExeRejection()
        {
            var user = Guid.NewGuid();
            var org = Guid.NewGuid();
            var svc = CreateService(out var store, out var dir, out var members);
            try
            {
                members.Add($"{user}:{org}");

                byte[] exeBytes = new byte[] { 0x4D, 0x5A, 0x90, 0x00 }; // MZ header
                AssertThrows<FileUploadException>(() => svc.Upload(user, org, "malware.exe", exeBytes, "application/octet-stream"),
                    "exe should be rejected");
                // rename to .png but still exe bytes
                AssertThrows<FileUploadException>(() => svc.Upload(user, org, "malware.png", exeBytes, "image/png"),
                    "png with exe bytes should be rejected");
            }
            finally
            {
                CleanupDirectory(dir);
            }
        }

        // UPLOAD-02
        public static void TestPngAccepted()
        {
            var user = Guid.NewGuid();
            var org = Guid.NewGuid();
            var svc = CreateService(out var store, out var dir, out var members);
            try
            {
                members.Add($"{user}:{org}");

                byte[] pngBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
                Guid fileId = svc.Upload(user, org, "image.png", pngBytes, "image/png");
                var record = store.GetFile(fileId);
                Assert(record != null, "Record should exist");
                Assert(record.StoredName != "image.png", "Stored name should be generated");
                Assert(record.OriginalName == "image.png", "Original name preserved");
            }
            finally
            {
                CleanupDirectory(dir);
            }
        }

        // UPLOAD-03
        public static void TestPathSanitization()
        {
            var user = Guid.NewGuid();
            var org = Guid.NewGuid();
            var svc = CreateService(out var store, out var dir, out var members);
            try
            {
                members.Add($"{user}:{org}");

                byte[] pngBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
                Guid fileId = svc.Upload(user, org, "../../etc/passwd.png", pngBytes, "image/png");
                var record = store.GetFile(fileId);
                Assert(record != null, "Record should exist");
                Assert(!record.OriginalName.Contains(".."), "Original name should not contain path parts");
                Assert(!record.OriginalName.Contains("/"), "Original name should not contain slashes");
                Assert(!record.OriginalName.Contains("\\"), "Original name should not contain backslashes");
            }
            finally
            {
                CleanupDirectory(dir);
            }
        }

        // UPLOAD-04
        public static void TestSizeLimit()
        {
            var user = Guid.NewGuid();
            var org = Guid.NewGuid();
            var svc = CreateService(out var store, out var dir, out var members, sizeLimitBytes: 100);
            try
            {
                members.Add($"{user}:{org}");

                byte[] big = new byte[101];
                AssertThrows<FileUploadException>(() => svc.Upload(user, org, "big.png", big, "image/png"),
                    "File over size limit should be rejected");
            }
            finally
            {
                CleanupDirectory(dir);
            }
        }

        // UPLOAD-05
        public static void TestNonMemberAccess()
        {
            var user = Guid.NewGuid();
            var org = Guid.NewGuid();
            var svc = CreateService(out var store, out var dir, out var members);
            try
            {
                members.Add($"{user}:{org}");

                byte[] pngBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
                Guid fileId = svc.Upload(user, org, "image.png", pngBytes, "image/png");

                var otherUser = Guid.NewGuid();
                AssertThrows<FileUploadException>(() => svc.Upload(otherUser, org, "image.png", pngBytes, "image/png"),
                    "Non-member should not upload");

                AssertThrows<FileUploadException>(() => svc.CreateDownloadLink(otherUser, fileId),
                    "Non-member should not get link");

                AssertThrows<FileUploadException>(() => svc.DeleteFile(otherUser, fileId),
                    "Non-member should not delete");

                string token = svc.CreateDownloadLink(user, fileId);
                // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: download() takes the caller (spec), so a
                // member's link forwarded to a non-member must fail, and the member can still use it.
                AssertThrows<FileUploadException>(() => svc.Download(otherUser, token),
                    "Non-member should not download with a member's link");
                Assert(svc.Download(user, token).Length == pngBytes.Length, "Member downloads with the link");
                members.Remove($"{user}:{org}");
                AssertThrows<FileUploadException>(() => svc.Download(user, token),
                    "Removed member should not download");
            }
            finally
            {
                CleanupDirectory(dir);
            }
        }

        // UPLOAD-06
        public static void TestExpiredLink()
        {
            var user = Guid.NewGuid();
            var org = Guid.NewGuid();
            var svc = CreateService(out var store, out var dir, out var members);
            try
            {
                members.Add($"{user}:{org}");

                byte[] pngBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
                Guid fileId = svc.Upload(user, org, "image.png", pngBytes, "image/png");
                string token = svc.CreateDownloadLink(user, fileId, ttlSeconds: 1);
                // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the clock is moved 2 s instead of a real
                // 2 s sleep (deterministic tests); download() now takes the caller.
                Assert(svc.Download(user, token).Length == pngBytes.Length, "Fresh link works");
                _now = _now.AddSeconds(2);
                AssertThrows<FileUploadException>(() => svc.Download(user, token),
                    "Expired link should be rejected");

                string validToken = svc.CreateDownloadLink(user, fileId, ttlSeconds: 300);
                Assert(svc.Download(user, validToken).Length == pngBytes.Length, "Valid link works");
                // change one character in the payload and one in the signature
                int dot = validToken.IndexOf('.');
                string tamperedPayload = validToken.Substring(0, dot - 1) + (validToken[dot - 1] == 'A' ? "B" : "A") + validToken.Substring(dot);
                string tampered = validToken.Substring(0, validToken.Length - 1) + (validToken.EndsWith("A") ? "B" : "A");
                AssertThrows<FileUploadException>(() => svc.Download(user, tampered),
                    "Tampered link should be rejected");
                AssertThrows<FileUploadException>(() => svc.Download(user, tamperedPayload),
                    "Link with a changed payload character should be rejected");
                AssertThrows<FileUploadException>(() => svc.Download(user, "not-a-token"),
                    "Malformed link is an ordinary invalid-link error");
            }
            finally
            {
                CleanupDirectory(dir);
            }
        }

        // UPLOAD-07
        public static void TestDeletePreventsAccess()
        {
            var user = Guid.NewGuid();
            var org = Guid.NewGuid();
            var svc = CreateService(out var store, out var dir, out var members);
            try
            {
                members.Add($"{user}:{org}");

                byte[] pngBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
                Guid fileId = svc.Upload(user, org, "image.png", pngBytes, "image/png");
                string token = svc.CreateDownloadLink(user, fileId);
                svc.DeleteFile(user, fileId);

                AssertThrows<FileUploadException>(() => svc.CreateDownloadLink(user, fileId),
                    "Link creation after delete should fail");
                AssertThrows<FileUploadException>(() => svc.Download(user, token),
                    "Download after delete should fail");
            }
            finally
            {
                CleanupDirectory(dir);
            }
        }

        public static int Main()
        {
            int failures = 0;
            Action[] tests = new Action[]
            {
                TestExeRejection,
                TestPngAccepted,
                TestPathSanitization,
                TestSizeLimit,
                TestNonMemberAccess,
                TestExpiredLink,
                TestDeletePreventsAccess
            };

            foreach (var test in tests)
            {
                try
                {
                    test();
                    Console.WriteLine($"{test.Method.Name}: PASS");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{test.Method.Name}: FAIL - {ex.Message}");
                    failures++;
                }
            }

            return failures > 0 ? 1 : 0;
        }
    }
}