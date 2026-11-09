import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as sqlite from 'node:sqlite';

// ---------- Storage Interface ----------
export interface FileRecord {
  id: string;
  org_id: string;
  owner_user_id: string;
  stored_name: string;
  original_name: string;
  extension: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  created_at: number;
  deleted_at: number | null;
}

export interface FileStore {
  save(record: FileRecord, bytes: Uint8Array): void;
  get(file_id: string): FileRecord | null;
  update(record: FileRecord): void;
  list(): FileRecord[];
}

// ---------- In-Memory Store ----------
export class InMemoryFileStore implements FileStore {
  private records: Map<string, FileRecord> = new Map();
  private bytes: Map<string, Uint8Array> = new Map();

  save(record: FileRecord, fileBytes: Uint8Array): void {
    this.records.set(record.id, record);
    this.bytes.set(record.id, fileBytes);
  }

  get(file_id: string): FileRecord | null {
    return this.records.get(file_id) ?? null;
  }

  update(record: FileRecord): void {
    this.records.set(record.id, record);
  }

  list(): FileRecord[] {
    return Array.from(this.records.values());
  }
}

// ---------- SQL Store ----------
export class SqlFileStore implements FileStore {
  private db: sqlite.DatabaseSync;

  constructor(db: sqlite.DatabaseSync) {
    this.db = db;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        org_id TEXT,
        owner_user_id TEXT,
        stored_name TEXT,
        original_name TEXT,
        extension TEXT,
        mime_type TEXT,
        size_bytes INTEGER,
        sha256 TEXT,
        created_at INTEGER,
        deleted_at INTEGER
      )
    `);
  }

  save(record: FileRecord, _bytes: Uint8Array): void {
    const stmt = this.db.prepare(`
      INSERT INTO files (id, org_id, owner_user_id, stored_name, original_name,
        extension, mime_type, size_bytes, sha256, created_at, deleted_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      record.id, record.org_id, record.owner_user_id, record.stored_name,
      record.original_name, record.extension, record.mime_type, record.size_bytes,
      record.sha256, record.created_at, record.deleted_at ?? null
    );
  }

  get(file_id: string): FileRecord | null {
    const stmt = this.db.prepare('SELECT * FROM files WHERE id = ?');
    const row = stmt.get(file_id);
    if (!row) return null;
    return {
      id: row[0] as string,
      org_id: row[1] as string,
      owner_user_id: row[2] as string,
      stored_name: row[3] as string,
      original_name: row[4] as string,
      extension: row[5] as string,
      mime_type: row[6] as string,
      size_bytes: row[7] as number,
      sha256: row[8] as string,
      created_at: row[9] as number,
      deleted_at: row[10] === null ? null : (row[10] as number),
    };
  }

  update(record: FileRecord): void {
    const stmt = this.db.prepare(`
      UPDATE files SET org_id = ?, owner_user_id = ?, stored_name = ?,
        original_name = ?, extension = ?, mime_type = ?, size_bytes = ?,
        sha256 = ?, created_at = ?, deleted_at = ?
      WHERE id = ?
    `);
    stmt.run(
      record.org_id, record.owner_user_id, record.stored_name,
      record.original_name, record.extension, record.mime_type, record.size_bytes,
      record.sha256, record.created_at, record.deleted_at ?? null, record.id
    );
  }

  list(): FileRecord[] {
    const stmt = this.db.prepare('SELECT * FROM files');
    const rows = stmt.all();
    return rows.map((row: any[]) => ({
      id: row[0] as string,
      org_id: row[1] as string,
      owner_user_id: row[2] as string,
      stored_name: row[3] as string,
      original_name: row[4] as string,
      extension: row[5] as string,
      mime_type: row[6] as string,
      size_bytes: row[7] as number,
      sha256: row[8] as string,
      created_at: row[9] as number,
      deleted_at: row[10] === null ? null : (row[10] as number),
    }));
  }
}

// ---------- File Uploads System ----------
export class FileUploads {
  private store: FileStore;
  private storageDir: string;
  private hmacSecret: string;
  private allowedExtensions: Set<string>;
  private maxFileSize: number;

  constructor(config: {
    store: FileStore;
    storageDir: string;
    hmacSecret: string;
    allowedExtensions?: string[];
    maxFileSize?: number;
  }) {
    this.store = config.store;
    this.storageDir = config.storageDir;
    this.hmacSecret = config.hmacSecret;
    this.allowedExtensions = new Set(
      config.allowedExtensions ?? ['pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'csv', 'docx', 'xlsx']
    );
    this.maxFileSize = config.maxFileSize ?? 10 * 1024 * 1024; // 10 MB default
  }

  upload(
    user: { id: string; orgs: string[] },
    org_id: string,
    original_filename: string,
    bytes: Uint8Array,
    declared_content_type: string
  ): { file_id: string } | { error: string } {
    // Authorization check
    if (!user.orgs.includes(org_id)) {
      return { error: 'unauthorized' };
    }

    // Size limit check
    if (bytes.length > this.maxFileSize) {
      return { error: 'file too large' };
    }

    // Sanitize original filename
    const sanitizedOriginal = this.sanitizeFilename(original_filename);

    // Extract extension
    const ext = path.extname(sanitizedOriginal).toLowerCase().replace('.', '');
    if (!ext || !this.allowedExtensions.has(ext)) {
      return { error: 'extension not allowed' };
    }

    // Magic bytes validation
    const magicValid = this.validateMagicBytes(ext, bytes);
    if (!magicValid) {
      return { error: 'magic bytes mismatch' };
    }

    // Generate random stored name
    const storedName = crypto.randomUUID() + '.' + ext;

    // Compute SHA256
    const sha256 = crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');

    // Create file record
    const fileId = crypto.randomUUID();
    const record: FileRecord = {
      id: fileId,
      org_id,
      owner_user_id: user.id,
      stored_name: storedName,
      original_name: sanitizedOriginal,
      extension: ext,
      mime_type: declared_content_type,
      size_bytes: bytes.length,
      sha256,
      created_at: Date.now(),
      deleted_at: null,
    };

    // Save to store
    this.store.save(record, bytes);

    // Write bytes to storage directory
    const filePath = path.join(this.storageDir, storedName);
    fs.writeFileSync(filePath, Buffer.from(bytes));

    return { file_id: fileId };
  }

  create_download_link(
    user: { id: string; orgs: string[] },
    file_id: string,
    ttl_seconds: number = 300
  ): { url: string } | { error: string } {
    const record = this.store.get(file_id);
    if (!record || record.deleted_at !== null) {
      return { error: 'not found' };
    }

    // Authorization check
    if (!user.orgs.includes(record.org_id)) {
      return { error: 'unauthorized' };
    }

    const expiresAt = Math.floor(Date.now() / 1000) + ttl_seconds;
    const payload = `${record.id}:${expiresAt}`;
    const signature = crypto
      .createHmac('sha256', this.hmacSecret)
      .update(payload)
      .digest('hex');

    const token = Buffer.from(`${payload}:${signature}`).toString('base64url');
    return { url: `https://files.example.com/download/${token}` };
  }

  /**
   * Returns the bytes for a link token only in the exact form it was issued, unexpired, with a valid HMAC and an
   * existing file. Output: { bytes } or { error }. Touches: the database and storage. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
   */
  download(token: string): { bytes: Uint8Array } | { error: string } {
    let payload: string;
    try {
      payload = Buffer.from(token, 'base64url').toString('utf8');
    } catch {
      return { error: 'invalid link' };
    }
    // Only the exact token this service issued is accepted. Base64 decoding ignores the spare bits of the last
    // character, so a link with that character changed (A -> B) decoded to the same bytes and still worked; a
    // token must re-encode to itself. Found by the flaky tamper test on PR 18, 2026-11-09, session 04ec72ff.
    if (Buffer.from(payload, 'utf8').toString('base64url') !== token) {
      return { error: 'invalid link' };
    }

    const parts = payload.split(':');
    if (parts.length !== 3) {
      return { error: 'invalid link' };
    }

    const [file_id, expires_str, signature] = parts;

    let expires_at: number;
    try {
      expires_at = parseInt(expires_str, 10);
      if (isNaN(expires_at)) {
        return { error: 'invalid link' };
      }
    } catch {
      return { error: 'invalid link' };
    }

    // Check expiration
    if (expires_at < Math.floor(Date.now() / 1000)) {
      return { error: 'link expired' };
    }

    // Verify HMAC signature in constant time
    const expectedPayload = `${file_id}:${expires_at}`;
    const expectedSignature = crypto
      .createHmac('sha256', this.hmacSecret)
      .update(expectedPayload)
      .digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
      return { error: 'invalid link' };
    }

    // Retrieve file record
    const record = this.store.get(file_id);
    if (!record || record.deleted_at !== null) {
      return { error: 'not found' };
    }

    // Read bytes from storage
    const filePath = path.join(this.storageDir, record.stored_name);
    if (!fs.existsSync(filePath)) {
      return { error: 'not found' };
    }

    const fileBytes = fs.readFileSync(filePath);
    return { bytes: new Uint8Array(fileBytes) };
  }

  delete_file(
    user: { id: string; orgs: string[] },
    file_id: string
  ): { success: boolean } | { error: string } {
    const record = this.store.get(file_id);
    if (!record || record.deleted_at !== null) {
      return { error: 'not found' };
    }

    // Authorization check
    if (!user.orgs.includes(record.org_id)) {
      return { error: 'unauthorized' };
    }

    record.deleted_at = Date.now();
    this.store.update(record);

    return { success: true };
  }

  private sanitizeFilename(filename: string): string {
    // Strip path components
    let name = path.basename(filename);
    // Remove control characters and null bytes
    name = name.replace(/[\x00-\x1f\x7f]/g, '');
    // Limit length
    if (name.length > 255) {
      name = name.substring(0, 255);
    }
    return name;
  }

  private validateMagicBytes(ext: string, bytes: Uint8Array): boolean {
    if (bytes.length === 0) return false;

    const header = bytes.slice(0, 8);

    switch (ext) {
      case 'png':
        return header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4e && header[3] === 0x47;
      case 'jpg':
      case 'jpeg':
        return header[0] === 0xff && header[1] === 0xd8 && header[2] === 0xff;
      case 'gif':
        return header[0] === 0x47 && header[1] === 0x49 && header[2] === 0x46 && header[3] === 0x38;
      case 'pdf':
        return header[0] === 0x25 && header[1] === 0x50 && header[2] === 0x44 && header[3] === 0x46;
      case 'docx':
      case 'xlsx':
        return header[0] === 0x50 && header[1] === 0x4b && header[2] === 0x03 && header[3] === 0x04;
      case 'txt':
      case 'csv':
        // Text types: reject if they contain NUL bytes
        for (let i = 0; i < bytes.length; i++) {
          if (bytes[i] === 0x00) return false;
        }
        return true;
      default:
        return false;
    }
  }
}