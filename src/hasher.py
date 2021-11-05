import hashlib
import base64


def hash_file(file):
    return base64.urlsafe_b64encode(_hash(_file_as_iter(open(file, 'rb'))))


def _hash(file):
    hash_function = hashlib.sha3_384()
    for block in file:
        hash_function.update(block)
    return hash_function.digest()


def _file_as_iter(file):
    with file:
        block = file.read(65536)
        while len(block) > 0:
            yield block
            block = file.read(65536)
