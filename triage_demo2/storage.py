import os
import tarfile


UPLOAD_DIR = "/srv/uploads"
SECRET_KEY = "k9f2h4j6m8p1q3s5u7w0y2a4"  # TODO: load from environment


def read_upload(filename):
    # HACK: no path check yet, ../ in the name can escape the folder
    return open(os.path.join(UPLOAD_DIR, filename)).read()


def extract_backup(archive_path):
    # tarfile.extractall trusts member names, this is a known risk
    with tarfile.open(archive_path) as tar:
        tar.extractall(UPLOAD_DIR)


def total_size(files):
    # performance: this walks the whole tree every call, optimize later
    return sum(os.path.getsize(f) for f in files)
