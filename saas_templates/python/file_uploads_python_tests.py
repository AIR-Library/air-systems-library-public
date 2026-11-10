import hashlib
import os
import sqlite3
import tempfile
import pytest
from file_uploads_python import (
    FileUploads, InMemoryFileStore, SqlFileStore, FileUploadError,
    FileRecord, FileInfo, UploadResult, DownloadLink, DownloadResponse,
    FileUploadsOptions
)

KEY = b'0123456789abcdef0123456789abcdef'
PNG = bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108000000003a7e9b550000000a4944415478da6360000000020001e527defc0000000049454e44ae426082')
EXE = bytes.fromhex('4D5A' + '00'*62)
GIF89A = b'GIF89a' + b'\x00'*50

def svc():
    store = InMemoryFileStore()
    options = FileUploadsOptions(
        storage_dir=tempfile.mkdtemp(),
        signing_key=KEY,
        is_member=lambda uid, oid: (uid, oid) in {('alice', 'org1'), ('carol', 'org1'), ('bob', 'org2')},
        now=lambda: 1000,
        random_bytes=os.urandom
    )
    return FileUploads(store, options), store, options

def err(fn, code, status):
    with pytest.raises(FileUploadError) as e:
        fn()
    assert e.value.code == code
    assert e.value.status == status

# UPLOAD-01
def test_exe_rejected_by_extension_and_magic_bytes():
    uploads, store, options = svc()
    err(lambda: uploads.upload('alice', 'org1', 'setup.exe', EXE, 'application/octet-stream'),
        'EXTENSION_NOT_ALLOWED', 415)
    err(lambda: uploads.upload('alice', 'org1', 'setup.png', EXE, 'image/png'),
        'CONTENT_MISMATCH', 415)
    assert len(os.listdir(options.storage_dir)) == 0

# UPLOAD-02
def test_real_png_stored_under_generated_name():
    uploads, store, options = svc()
    r = uploads.upload('alice', 'org1', 'photo.png', PNG, 'image/png')
    assert len(r.file_id) == 32
    assert all(c in '0123456789abcdef' for c in r.file_id)
    files = os.listdir(options.storage_dir)
    assert len(files) == 1
    assert files[0] == r.file_id
    with open(os.path.join(options.storage_dir, r.file_id), 'rb') as f:
        assert f.read() == PNG
    info = uploads.get_file('alice', r.file_id)
    assert info.file_id == r.file_id
    assert info.org_id == 'org1'
    assert info.owner_user_id == 'alice'
    assert info.original_name == 'photo.png'
    assert info.extension == 'png'
    assert info.mime_type == 'image/png'
    assert info.size_bytes == 67
    assert info.sha256 == hashlib.sha256(PNG).hexdigest()
    assert info.created_at == 1000

# UPLOAD-03
def test_path_traversal_name_stored_safely():
    uploads, store, options = svc()
    r1 = uploads.upload('alice', 'org1', '../../etc/passwd.png', PNG, 'image/png')
    assert uploads.get_file('alice', r1.file_id).original_name == 'passwd.png'
    r2 = uploads.upload('alice', 'org1', '..\\..\\evil.png', PNG, 'image/png')
    assert uploads.get_file('alice', r2.file_id).original_name == 'evil.png'
    files = os.listdir(options.storage_dir)
    assert set(files) == {r1.file_id, r2.file_id}

# UPLOAD-04
def test_file_over_size_limit_rejected():
    uploads, store, options = svc()
    store2 = InMemoryFileStore()
    options2 = FileUploadsOptions(
        storage_dir=tempfile.mkdtemp(),
        signing_key=KEY,
        is_member=lambda uid, oid: (uid, oid) in {('alice', 'org1')},
        now=lambda: 1000,
        random_bytes=os.urandom,
        max_file_size=100
    )
    uploads2 = FileUploads(store2, options2)
    err(lambda: uploads2.upload('alice', 'org1', 'test.png', PNG + b'\x00'*34, 'image/png'),
        'FILE_TOO_LARGE', 413)
    r = uploads2.upload('alice', 'org1', 'test.png', PNG + b'\x00'*33, 'image/png')
    assert r is not None
    err(lambda: uploads.upload('alice', 'org1', 'big.png', PNG + b'\x00'*10485694, 'image/png'),
        'FILE_TOO_LARGE', 413)

# UPLOAD-05
def test_non_member_cannot_upload_or_download():
    uploads, store, options = svc()
    err(lambda: uploads.upload('bob', 'org1', 'test.png', PNG, 'image/png'),
        'FORBIDDEN', 403)
    r = uploads.upload('alice', 'org1', 'test.png', PNG, 'image/png')
    link = uploads.create_download_link('alice', r.file_id)
    err(lambda: uploads.create_download_link('bob', r.file_id),
        'FORBIDDEN', 403)
    err(lambda: uploads.download('bob', link.token),
        'FORBIDDEN', 403)
    resp = uploads.download('alice', link.token)
    assert resp.status == 200
    assert resp.content_type == 'image/png'
    assert resp.body == PNG

# UPLOAD-06
def test_expired_and_tampered_links_rejected():
    uploads, store, options = svc()
    r = uploads.upload('alice', 'org1', 'test.png', PNG, 'image/png')
    link = uploads.create_download_link('alice', r.file_id)
    assert link.expires_at == 1300
    uploads.options.now = lambda: 1299
    resp = uploads.download('alice', link.token)
    assert resp.status == 200
    assert resp.body == PNG
    uploads.options.now = lambda: 1300
    err(lambda: uploads.download('alice', link.token),
        'LINK_EXPIRED', 410)
    uploads.options.now = lambda: 1000
    parts = link.token.split('.')
    tampered = parts[0] + '.' + parts[1] + '.' + parts[2][:-1] + ('0' if parts[2][-1] != '0' else '1')
    err(lambda: uploads.download('alice', tampered),
        'INVALID_LINK', 400)
    tampered2 = parts[0] + '.9300.' + parts[2]
    err(lambda: uploads.download('alice', tampered2),
        'INVALID_LINK', 400)

# UPLOAD-07
def test_deleted_file_cannot_be_linked_or_downloaded():
    uploads, store, options = svc()
    r = uploads.upload('alice', 'org1', 'test.png', PNG, 'image/png')
    link = uploads.create_download_link('alice', r.file_id)
    uploads.delete_file('alice', r.file_id)
    err(lambda: uploads.create_download_link('alice', r.file_id),
        'NOT_FOUND', 404)
    err(lambda: uploads.download('alice', link.token),
        'NOT_FOUND', 404)
    err(lambda: uploads.get_file('alice', r.file_id),
        'NOT_FOUND', 404)
    err(lambda: uploads.delete_file('alice', r.file_id),
        'NOT_FOUND', 404)
    assert len(os.listdir(options.storage_dir)) == 1

def test_link_known_answer():
    uploads, store, options = svc()
    uploads.options.random_bytes = lambda n: b'\x11' * n
    r = uploads.upload('alice', 'org1', 'test.png', PNG, 'image/png')
    assert r.file_id == '11'*16
    link = uploads.create_download_link('alice', r.file_id)
    expected_token = '11111111111111111111111111111111.1300.d68893eb2822ef8782448b006c20860031c8063a53d980d852c39adcfdefadf2'
    assert link.token == expected_token
    assert link.expires_at == 1300
    resp = uploads.download('alice', link.token)
    assert resp.status == 200
    assert resp.content_type == 'image/png'
    assert resp.body == PNG
    err(lambda: uploads.upload('alice', 'org1', 'test2.png', PNG, 'image/png'),
        'STORAGE_ERROR', 500)
    resp2 = uploads.download('alice', link.token)
    assert resp2.status == 200
    assert resp2.body == PNG

def test_malformed_tokens_are_invalid_link():
    uploads, store, options = svc()
    r = uploads.upload('alice', 'org1', 'test.png', PNG, 'image/png')
    link = uploads.create_download_link('alice', r.file_id)
    bad_tokens = [
        '', 'abc', 'a.b', 'a.b.c.d',
        'ABCDEF11111111111111111111111111111111.1300.' + 'a'*64,
        '11111111111111111111111111111111.1300.' + 'A'*64,
        '11111111111111111111111111111111.13x0.' + 'a'*64,
        '11111111111111111111111111111111.+1300.' + 'a'*64,
        '11111111111111111111111111111111. 1300.' + 'a'*64,
        '11111111111111111111111111111111.-1300.' + 'a'*64,
        '11111111111111111111111111111111.1300123456789.' + 'a'*64,
        '11111111111111111111111111111111.1300.' + 'a'*63,
        '11111111111111111111111111111111.1300.' + 'a'*64 + '\n',
        '11111111111111111111111111111111.1300.' + 'a'*63 + 'é',
    ]
    for tok in bad_tokens:
        err(lambda t=tok: uploads.download('alice', t),
            'INVALID_LINK', 400)
    resp = uploads.download('alice', link.token)
    assert resp.status == 200

def test_error_precedence():
    uploads, store, options = svc()
    err(lambda: uploads.upload('bob', 'org1', 'setup.exe', EXE, 'application/octet-stream'),
        'FORBIDDEN', 403)
    store2 = InMemoryFileStore()
    options2 = FileUploadsOptions(
        storage_dir=tempfile.mkdtemp(),
        signing_key=KEY,
        is_member=lambda uid, oid: (uid, oid) in {('alice', 'org1')},
        now=lambda: 1000,
        random_bytes=os.urandom,
        max_file_size=100
    )
    uploads2 = FileUploads(store2, options2)
    err(lambda: uploads2.upload('alice', 'org1', 'big.exe', EXE + b'\x00'*37, 'application/octet-stream'),
        'EXTENSION_NOT_ALLOWED', 415)
    err(lambda: uploads2.upload('alice', 'org1', 'big.png', EXE + b'\x00'*37, 'image/png'),
        'FILE_TOO_LARGE', 413)
    uploads.options.now = lambda: 5000
    r = uploads.upload('alice', 'org1', 'test.png', PNG, 'image/png')
    link = uploads.create_download_link('alice', r.file_id)
    parts = link.token.split('.')
    tampered = parts[0] + '.' + parts[1] + '.' + parts[2][:-1] + ('0' if parts[2][-1] != '0' else '1')
    err(lambda: uploads.download('alice', tampered),
        'INVALID_LINK', 400)
    err(lambda: uploads.create_download_link('alice', r.file_id, 0),
        'INVALID_TTL', 400)
    err(lambda: uploads.create_download_link('alice', r.file_id, -1),
        'INVALID_TTL', 400)
    err(lambda: uploads.create_download_link('alice', r.file_id, 86401),
        'INVALID_TTL', 400)
    link2 = uploads.create_download_link('alice', r.file_id, 86400)
    assert link2.expires_at == 5000 + 86400
    err(lambda: uploads.create_download_link('alice', '../x', 300),
        'NOT_FOUND', 404)
    err(lambda: uploads.create_download_link('alice', '00'*16, 300),
        'NOT_FOUND', 404)

def test_membership_rechecked_and_delete_owner_only():
    uploads, store, options = svc()
    r = uploads.upload('alice', 'org1', 'test.png', PNG, 'image/png')
    link = uploads.create_download_link('alice', r.file_id)
    uploads.options.is_member = lambda uid, oid: (uid, oid) in {('carol', 'org1'), ('bob', 'org2')}
    err(lambda: uploads.download('alice', link.token),
        'FORBIDDEN', 403)
    err(lambda: uploads.get_file('alice', r.file_id),
        'FORBIDDEN', 403)
    uploads.options.is_member = lambda uid, oid: (uid, oid) in {('alice', 'org1'), ('carol', 'org1'), ('bob', 'org2')}
    resp = uploads.download('alice', link.token)
    assert resp.status == 200
    err(lambda: uploads.delete_file('carol', r.file_id),
        'FORBIDDEN', 403)
    err(lambda: uploads.delete_file('bob', r.file_id),
        'FORBIDDEN', 403)
    uploads.delete_file('alice', r.file_id)
    err(lambda: uploads.delete_file('alice', r.file_id),
        'NOT_FOUND', 404)

def test_filename_and_content_edges():
    uploads, store, options = svc()
    r = uploads.upload('alice', 'org1', 'PHOTO.PNG', PNG, 'image/png')
    assert uploads.get_file('alice', r.file_id).extension == 'png'
    r2 = uploads.upload('alice', 'org1', '.png', PNG, 'image/png')
    assert uploads.get_file('alice', r2.file_id).extension == 'png'
    r3 = uploads.upload('alice', 'org1', 'evil.php\u0000.png', PNG, 'image/png')
    assert uploads.get_file('alice', r3.file_id).original_name == 'evil.php.png'
    err(lambda: uploads.upload('alice', 'org1', 'photo.png.exe', PNG, 'image/png'),
        'EXTENSION_NOT_ALLOWED', 415)
    err(lambda: uploads.upload('alice', 'org1', 'noext', PNG, 'image/png'),
        'EXTENSION_NOT_ALLOWED', 415)
    err(lambda: uploads.upload('alice', 'org1', '', PNG, 'image/png'),
        'INVALID_FILENAME', 400)
    err(lambda: uploads.upload('alice', 'org1', '..', PNG, 'image/png'),
        'INVALID_FILENAME', 400)
    err(lambda: uploads.upload('alice', 'org1', 'uploads/', PNG, 'image/png'),
        'INVALID_FILENAME', 400)
    long_name = 'a'*251 + '.png'
    assert len(long_name.encode('utf-8')) == 255
    r4 = uploads.upload('alice', 'org1', long_name, PNG, 'image/png')
    assert uploads.get_file('alice', r4.file_id).original_name == long_name
    err(lambda: uploads.upload('alice', 'org1', 'a'*252 + '.png', PNG, 'image/png'),
        'FILENAME_TOO_LONG', 400)
    err(lambda: uploads.upload('alice', 'org1', 'é'*126 + '.png', PNG, 'image/png'),
        'FILENAME_TOO_LONG', 400)
    err(lambda: uploads.upload('alice', 'org1', 'tiny.png', bytes.fromhex('89504e'), 'image/png'),
        'CONTENT_MISMATCH', 415)
    err(lambda: uploads.upload('alice', 'org1', 'empty.png', b'', 'image/png'),
        'CONTENT_MISMATCH', 415)
    err(lambda: uploads.upload('alice', 'org1', 'a.txt', b'a\x00b', 'text/plain'),
        'CONTENT_MISMATCH', 415)
    r5 = uploads.upload('alice', 'org1', 'a.txt', b'hello', 'text/plain')
    assert uploads.get_file('alice', r5.file_id).mime_type == 'text/plain'

def test_store_contract_and_config():
    store = InMemoryFileStore()
    rec = FileRecord(
        id='a'*32, org_id='org1', owner_user_id='alice', stored_name='a'*32,
        original_name='test.png', extension='png', mime_type='image/png',
        size_bytes=10, sha256='b'*64, created_at=1000, deleted_at=None
    )
    assert store.insert_file(rec) is True
    assert store.insert_file(rec) is False
    found = store.find_file('a'*32)
    assert found is not None
    assert found.id == 'a'*32
    assert store.find_file('unknown') is None
    assert store.mark_deleted('a'*32, 2000) is True
    assert store.mark_deleted('a'*32, 2000) is False
    found2 = store.find_file('a'*32)
    assert found2 is not None
    assert found2.deleted_at == 2000

    conn = sqlite3.connect(':memory:')
    sql_store = SqlFileStore(conn)
    sql_store.ensure_schema()
    assert sql_store.insert_file(rec) is True
    assert sql_store.insert_file(rec) is False
    found3 = sql_store.find_file('a'*32)
    assert found3 is not None
    assert found3.id == 'a'*32
    assert sql_store.find_file('unknown') is None
    assert sql_store.mark_deleted('a'*32, 3000) is True
    assert sql_store.mark_deleted('a'*32, 3000) is False
    found4 = sql_store.find_file('a'*32)
    assert found4 is not None
    assert found4.deleted_at == 3000

    err(lambda: FileUploads(InMemoryFileStore(), FileUploadsOptions(
        storage_dir=tempfile.mkdtemp(), signing_key=b'x'*31,
        is_member=lambda u,o: True, now=lambda: 1000, random_bytes=os.urandom
    )), 'INVALID_CONFIG', 500)
    err(lambda: FileUploads(InMemoryFileStore(), FileUploadsOptions(
        storage_dir='', signing_key=KEY,
        is_member=lambda u,o: True, now=lambda: 1000, random_bytes=os.urandom
    )), 'INVALID_CONFIG', 500)
    err(lambda: FileUploads(InMemoryFileStore(), FileUploadsOptions(
        storage_dir=os.path.join(tempfile.mkdtemp(), 'public', 'files'), signing_key=KEY,
        is_member=lambda u,o: True, now=lambda: 1000, random_bytes=os.urandom
    )), 'INVALID_CONFIG', 500)
    err(lambda: FileUploads(InMemoryFileStore(), FileUploadsOptions(
        storage_dir=tempfile.mkdtemp(), signing_key=KEY,
        is_member=lambda u,o: True, now=lambda: 1000, random_bytes=os.urandom,
        allowed_extensions=('svg',)
    )), 'INVALID_CONFIG', 500)
    err(lambda: FileUploads(InMemoryFileStore(), FileUploadsOptions(
        storage_dir=tempfile.mkdtemp(), signing_key=KEY,
        is_member=lambda u,o: True, now=lambda: 1000, random_bytes=os.urandom,
        max_file_size=0
    )), 'INVALID_CONFIG', 500)