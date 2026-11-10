using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Data.Common;

namespace FileUploads
{
    public class FileUploadService
    {
        private readonly IFileStore _store;
        private readonly string _storageDir;
        private readonly byte[] _hmacKey;
        private readonly Func<Guid, Guid, bool> _isMember;
        private readonly long _sizeLimitBytes;
        private readonly HashSet<string> _allowlistExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "pdf", "png", "jpg", "jpeg", "gif", "txt", "csv", "docx", "xlsx"
        };

        private readonly Func<DateTimeOffset> _clock;

        /// <summary>
        /// Builds the service.
        /// In: the file store, the storage directory (outside the webroot), the HMAC key for download links,
        /// isMember(user, org), the size limit (default 10 MB) and an optional clock (default UTC now).
        /// Why the clock: link expiry (UPLOAD-06) is tested without sleeping, so no test depends on wall time
        /// (docs/specs/README.md "Deterministic"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: creates the storage directory on disk.
        /// </summary>
        public FileUploadService(IFileStore store, string storageDir, byte[] hmacKey,
            Func<Guid, Guid, bool> isMember, long sizeLimitBytes = 10 * 1024 * 1024, Func<DateTimeOffset> clock = null)
        {
            _store = store;
            _storageDir = storageDir;
            _hmacKey = hmacKey;
            _isMember = isMember;
            _sizeLimitBytes = sizeLimitBytes;
            _clock = clock ?? (() => DateTimeOffset.UtcNow);
            Directory.CreateDirectory(_storageDir);
        }

        public Guid Upload(Guid userId, Guid orgId, string originalFilename, byte[] bytes, string declaredContentType)
        {
            if (!_isMember(userId, orgId))
                throw new FileUploadException("User not authorized to upload to this org.");

            if (bytes == null || bytes.Length > _sizeLimitBytes)
                throw new FileUploadException("File size exceeds limit.");

            if (string.IsNullOrEmpty(originalFilename) || originalFilename.Length > 255)
                throw new FileUploadException("Invalid filename length.");

            string extension = Path.GetExtension(originalFilename);
            if (string.IsNullOrEmpty(extension))
                throw new FileUploadException("File must have an extension.");

            extension = extension.TrimStart('.').ToLowerInvariant();
            if (!_allowlistExtensions.Contains(extension))
                throw new FileUploadException("Extension not allowed.");

            if (!CheckMagicBytes(extension, bytes))
                throw new FileUploadException("File content does not match extension.");

            string sanitizedOriginal = SanitizeFilename(originalFilename);
            string storedName = Guid.NewGuid().ToString("N");
            string mimeType = GetMimeType(extension);

            string storedPath = Path.Combine(_storageDir, storedName);
            File.WriteAllBytes(storedPath, bytes);

            FileRecord record = new FileRecord
            {
                Id = Guid.NewGuid(),
                OrgId = orgId,
                OwnerUserId = userId,
                StoredName = storedName,
                OriginalName = sanitizedOriginal,
                Extension = extension,
                MimeType = mimeType,
                SizeBytes = bytes.Length,
                Sha256 = ComputeSha256(bytes),
                CreatedAt = _clock(),
                DeletedAt = null
            };

            _store.AddFile(record);
            return record.Id;
        }

        /// <summary>
        /// Makes an expiring signed download link.
        /// In: the caller, the file id and the lifetime in seconds (default 300). Out: "payload.signature", where
        /// payload = base64url("file_id:expires_at") and signature = base64url(HMAC-SHA256(key, payload)).
        /// Errors: FileUploadException for a missing or deleted file (not found) or a caller outside the file's org.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the link no longer carries the creator's id; the
        /// spec signs (file_id, expires_at) and download() checks the CALLER instead. Touches: reads the store.
        /// </summary>
        public string CreateDownloadLink(Guid userId, Guid fileId, int ttlSeconds = 300)
        {
            FileRecord record = _store.GetFile(fileId);
            if (record == null || record.DeletedAt != null)
                throw new FileUploadException("File not found.");

            if (!_isMember(userId, record.OrgId))
                throw new FileUploadException("User not authorized to download this file.");

            long expiresAt = _clock().ToUnixTimeSeconds() + ttlSeconds;
            string payload = $"{fileId}:{expiresAt}";
            string payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
            string signature = Base64UrlEncode(HmacSha256(payloadB64));
            return $"{payloadB64}.{signature}";
        }

        /// <summary>
        /// Returns a file's bytes for a valid link.
        /// In: the verified caller and the link token. Out: the file's bytes.
        /// Errors (FileUploadException, never a parse exception): malformed token, bad signature (constant-time
        /// compare), expired link, deleted or missing file (not found), and a caller who is not a member of the
        /// file's org. Why: file_uploads spec "download(user, token) ... the caller is needed to re-check access";
        /// before 2026-11-10 the C# version took only the token and trusted the user id inside it, so a forwarded
        /// link worked for anyone. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, reads a file on disk.
        /// </summary>
        public byte[] Download(Guid userId, string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new FileUploadException("Invalid token.");

            string[] parts = token.Split('.');
            if (parts.Length != 2)
                throw new FileUploadException("Invalid link format.");

            string payloadB64 = parts[0];
            string signatureB64 = parts[1];

            byte[] payloadBytes;
            byte[] signatureBytes;
            try
            {
                payloadBytes = Base64UrlDecode(payloadB64);
                signatureBytes = Base64UrlDecode(signatureB64);
            }
            catch (FormatException)
            {
                throw new FileUploadException("Invalid link encoding.");
            }

            if (!ConstantTimeEquals(HmacSha256(payloadB64), signatureBytes))
                throw new FileUploadException("Invalid link signature.");

            string payload = Encoding.UTF8.GetString(payloadBytes);
            string[] payloadParts = payload.Split(':');
            if (payloadParts.Length != 2)
                throw new FileUploadException("Invalid link payload.");

            if (!Guid.TryParse(payloadParts[0], out Guid fileId))
                throw new FileUploadException("Invalid file id in link.");

            if (!long.TryParse(payloadParts[1], out long expiresAt))
                throw new FileUploadException("Invalid expiry in link.");

            if (_clock().ToUnixTimeSeconds() > expiresAt)
                throw new FileUploadException("Link expired.");

            FileRecord record = _store.GetFile(fileId);
            if (record == null || record.DeletedAt != null)
                throw new FileUploadException("File not found.");

            if (!_isMember(userId, record.OrgId))
                throw new FileUploadException("User not authorized to download this file.");

            string storedPath = Path.Combine(_storageDir, record.StoredName);
            if (!File.Exists(storedPath))
                throw new FileUploadException("File missing on disk.");

            return File.ReadAllBytes(storedPath);
        }

        public void DeleteFile(Guid userId, Guid fileId)
        {
            FileRecord record = _store.GetFile(fileId);
            if (record == null || record.DeletedAt != null)
                throw new FileUploadException("File not found.");

            if (!_isMember(userId, record.OrgId))
                throw new FileUploadException("User not authorized to delete this file.");

            record.DeletedAt = _clock();
            _store.UpdateFile(record);
        }

        private bool CheckMagicBytes(string extension, byte[] bytes)
        {
            if (extension == "png")
            {
                byte[] pngMagic = { 0x89, 0x50, 0x4E, 0x47 };
                return bytes.Length >= pngMagic.Length && bytes.Take(pngMagic.Length).SequenceEqual(pngMagic);
            }
            if (extension == "jpg" || extension == "jpeg")
            {
                byte[] jpegMagic = { 0xFF, 0xD8, 0xFF };
                return bytes.Length >= jpegMagic.Length && bytes.Take(jpegMagic.Length).SequenceEqual(jpegMagic);
            }
            if (extension == "gif")
            {
                byte[] gifMagic = { 0x47, 0x49, 0x46, 0x38 };
                return bytes.Length >= gifMagic.Length && bytes.Take(gifMagic.Length).SequenceEqual(gifMagic);
            }
            if (extension == "pdf")
            {
                byte[] pdfMagic = { 0x25, 0x50, 0x44, 0x46 };
                return bytes.Length >= pdfMagic.Length && bytes.Take(pdfMagic.Length).SequenceEqual(pdfMagic);
            }
            if (extension == "docx" || extension == "xlsx")
            {
                byte[] zipMagic = { 0x50, 0x4B, 0x03, 0x04 };
                return bytes.Length >= zipMagic.Length && bytes.Take(zipMagic.Length).SequenceEqual(zipMagic);
            }
            if (extension == "txt" || extension == "csv")
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    if (bytes[i] == 0x00) return false;
                }
                return true;
            }
            return false;
        }

        private string SanitizeFilename(string filename)
        {
            string name = Path.GetFileName(filename);
            int lastSlash = name.LastIndexOfAny(new char[] { '/', '\\' });
            if (lastSlash >= 0)
            {
                name = name.Substring(lastSlash + 1);
            }
            name = name.Replace("..", "");

            StringBuilder sb = new StringBuilder();
            foreach (char c in name)
            {
                if (char.IsControl(c)) continue;
                sb.Append(c);
            }
            string sanitized = sb.ToString();
            if (sanitized.Length > 255)
            {
                sanitized = sanitized.Substring(0, 255);
            }
            return sanitized;
        }

        private string GetMimeType(string extension)
        {
            switch (extension.ToLowerInvariant())
            {
                case "pdf": return "application/pdf";
                case "png": return "image/png";
                case "jpg":
                case "jpeg": return "image/jpeg";
                case "gif": return "image/gif";
                case "txt": return "text/plain";
                case "csv": return "text/csv";
                case "docx": return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
                case "xlsx": return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
                default: return "application/octet-stream";
            }
        }

        private string ComputeSha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hash.Length; i++)
                {
                    sb.Append(hash[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        private byte[] HmacSha256(string data)
        {
            using (HMACSHA256 hmac = new HMACSHA256(_hmacKey))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            }
        }

        private static string Base64UrlEncode(byte[] input)
        {
            string base64 = Convert.ToBase64String(input);
            return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static byte[] Base64UrlDecode(string input)
        {
            string padded = input.Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4)
            {
                case 2: padded += "=="; break;
                case 3: padded += "="; break;
            }
            return Convert.FromBase64String(padded);
        }

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }

    public interface IFileStore
    {
        void AddFile(FileRecord record);
        FileRecord GetFile(Guid id);
        void UpdateFile(FileRecord record);
    }

    public class InMemoryFileStore : IFileStore
    {
        private readonly Dictionary<Guid, FileRecord> _records = new Dictionary<Guid, FileRecord>();
        private readonly object _lock = new object();

        public void AddFile(FileRecord record)
        {
            lock (_lock)
            {
                _records[record.Id] = CloneRecord(record);
            }
        }

        public FileRecord GetFile(Guid id)
        {
            lock (_lock)
            {
                return _records.TryGetValue(id, out var rec) ? CloneRecord(rec) : null;
            }
        }

        public void UpdateFile(FileRecord record)
        {
            lock (_lock)
            {
                _records[record.Id] = CloneRecord(record);
            }
        }

        private FileRecord CloneRecord(FileRecord r)
        {
            return new FileRecord
            {
                Id = r.Id,
                OrgId = r.OrgId,
                OwnerUserId = r.OwnerUserId,
                StoredName = r.StoredName,
                OriginalName = r.OriginalName,
                Extension = r.Extension,
                MimeType = r.MimeType,
                SizeBytes = r.SizeBytes,
                Sha256 = r.Sha256,
                CreatedAt = r.CreatedAt,
                DeletedAt = r.DeletedAt
            };
        }
    }

    public class SqlFileStore : IFileStore
    {
        private readonly Func<DbConnection> _connectionFactory;

        public SqlFileStore(Func<DbConnection> connectionFactory)
        {
            _connectionFactory = connectionFactory;
        }

        public static string GetSchemaDdl()
        {
            return @"
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    owner_user_id TEXT NOT NULL,
                    stored_name TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    extension TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    deleted_at TEXT
                );
            ";
        }

        public void AddFile(FileRecord record)
        {
            using (DbConnection conn = _connectionFactory())
            {
                conn.Open();
                using (DbCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
                        INSERT INTO files (id, org_id, owner_user_id, stored_name, original_name, extension, mime_type, size_bytes, sha256, created_at, deleted_at)
                        VALUES (@id, @org_id, @owner_user_id, @stored_name, @original_name, @extension, @mime_type, @size_bytes, @sha256, @created_at, @deleted_at);
                    ";
                    AddParameter(cmd, "@id", record.Id.ToString());
                    AddParameter(cmd, "@org_id", record.OrgId.ToString());
                    AddParameter(cmd, "@owner_user_id", record.OwnerUserId.ToString());
                    AddParameter(cmd, "@stored_name", record.StoredName);
                    AddParameter(cmd, "@original_name", record.OriginalName);
                    AddParameter(cmd, "@extension", record.Extension);
                    AddParameter(cmd, "@mime_type", record.MimeType);
                    AddParameter(cmd, "@size_bytes", record.SizeBytes);
                    AddParameter(cmd, "@sha256", record.Sha256);
                    AddParameter(cmd, "@created_at", record.CreatedAt.ToString("o"));
                    AddParameter(cmd, "@deleted_at", record.DeletedAt?.ToString("o") ?? (object)DBNull.Value);
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public FileRecord GetFile(Guid id)
        {
            using (DbConnection conn = _connectionFactory())
            {
                conn.Open();
                using (DbCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT id, org_id, owner_user_id, stored_name, original_name, extension, mime_type, size_bytes, sha256, created_at, deleted_at FROM files WHERE id = @id;";
                    AddParameter(cmd, "@id", id.ToString());
                    using (DbDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return new FileRecord
                            {
                                Id = Guid.Parse(reader.GetString(0)),
                                OrgId = Guid.Parse(reader.GetString(1)),
                                OwnerUserId = Guid.Parse(reader.GetString(2)),
                                StoredName = reader.GetString(3),
                                OriginalName = reader.GetString(4),
                                Extension = reader.GetString(5),
                                MimeType = reader.GetString(6),
                                SizeBytes = reader.GetInt64(7),
                                Sha256 = reader.GetString(8),
                                CreatedAt = DateTimeOffset.Parse(reader.GetString(9)),
                                DeletedAt = reader.IsDBNull(10) ? (DateTimeOffset?)null : DateTimeOffset.Parse(reader.GetString(10))
                            };
                        }
                    }
                }
            }
            return null;
        }

        public void UpdateFile(FileRecord record)
        {
            using (DbConnection conn = _connectionFactory())
            {
                conn.Open();
                using (DbCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
                        UPDATE files
                        SET org_id = @org_id,
                            owner_user_id = @owner_user_id,
                            stored_name = @stored_name,
                            original_name = @original_name,
                            extension = @extension,
                            mime_type = @mime_type,
                            size_bytes = @size_bytes,
                            sha256 = @sha256,
                            created_at = @created_at,
                            deleted_at = @deleted_at
                        WHERE id = @id;
                    ";
                    AddParameter(cmd, "@id", record.Id.ToString());
                    AddParameter(cmd, "@org_id", record.OrgId.ToString());
                    AddParameter(cmd, "@owner_user_id", record.OwnerUserId.ToString());
                    AddParameter(cmd, "@stored_name", record.StoredName);
                    AddParameter(cmd, "@original_name", record.OriginalName);
                    AddParameter(cmd, "@extension", record.Extension);
                    AddParameter(cmd, "@mime_type", record.MimeType);
                    AddParameter(cmd, "@size_bytes", record.SizeBytes);
                    AddParameter(cmd, "@sha256", record.Sha256);
                    AddParameter(cmd, "@created_at", record.CreatedAt.ToString("o"));
                    AddParameter(cmd, "@deleted_at", record.DeletedAt?.ToString("o") ?? (object)DBNull.Value);
                    cmd.ExecuteNonQuery();
                }
            }
        }

        private void AddParameter(DbCommand cmd, string name, object value)
        {
            DbParameter param = cmd.CreateParameter();
            param.ParameterName = name;
            param.Value = value ?? DBNull.Value;
            cmd.Parameters.Add(param);
        }
    }

    public class FileRecord
    {
        public Guid Id { get; set; }
        public Guid OrgId { get; set; }
        public Guid OwnerUserId { get; set; }
        public string StoredName { get; set; }
        public string OriginalName { get; set; }
        public string Extension { get; set; }
        public string MimeType { get; set; }
        public long SizeBytes { get; set; }
        public string Sha256 { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset? DeletedAt { get; set; }
    }

    public class FileUploadException : Exception
    {
        public FileUploadException(string message) : base(message) { }
    }
}