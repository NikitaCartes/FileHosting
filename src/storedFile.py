from time import time_ns


def _first(iterable, default=None):
    for i, item in enumerate(iterable):
        return item, True, i
    return default, False, -1


class StoredFile:

    def __init__(self, hash_id: str, size=0, creation_time=0, downloads_number=0, uploads_number=0, last_access=0,
                 name=None,
                 is_short_link=False,
                 original_hash=""):
        self.hash = hash_id
        self.size = size
        self.downloads_number = downloads_number
        self.uploads_number = uploads_number
        self.last_access = time_ns() if last_access == 0 else last_access
        self.creation_time = time_ns() if creation_time == 0 else creation_time
        self.is_short_link = is_short_link
        self.original_hash = original_hash
        self.names = [] if name is None else name

    @staticmethod
    def encode(file_class):
        return {'hash': file_class.hash,
                'size': file_class.size,
                'creation_time': file_class.creation_time,
                'downloads_number': file_class.downloads_number,
                'uploads_number': file_class.uploads_number,
                'last_access': file_class.last_access,
                'names': [Name.encode(name) for name in file_class.names],
                'is_short_link': file_class.is_short_link,
                'original_hash': file_class.original_hash}

    @staticmethod
    def decode(file_document):
        return StoredFile(file_document['hash'],
                          file_document['size'],
                          file_document['creation_time'],
                          file_document['downloads_number'],
                          file_document['uploads_number'],
                          file_document['last_access'],
                          [Name.decode(name) for name in file_document['names']],
                          file_document['is_short_link'],
                          file_document['original_hash'])

    def add_name(self, filename):
        name, exist, i = _first((x for x in self.names if x.name == filename), Name(filename, uploads_number=1))
        if exist:
            self.names[i].uploads_number += 1
        else:
            self.names.append(name)


class Name:

    def __init__(self, name, creation_time=0, downloads_number=0, last_access=0, uploads_number=0):
        self.name = name
        self.downloads_number = downloads_number
        self.uploads_number = uploads_number
        self.last_access = time_ns() if last_access == 0 else last_access
        self.creation_time = time_ns() if creation_time == 0 else creation_time

    @staticmethod
    def encode(name_class):
        return {'name': name_class.name,
                'creation_time': name_class.creation_time,
                'downloads_number': name_class.downloads_number,
                'last_access': name_class.last_access,
                'uploads_number': name_class.uploads_number}

    @staticmethod
    def decode(name_document):
        return Name(name_document['name'],
                    name_document['creation_time'],
                    name_document['downloads_number'],
                    name_document['last_access'],
                    name_document['uploads_number'])
