from time import time_ns


class StoredFile:

    def __init__(self, hash_id, creation_time=0, usage=0, name=None, short_link=False, original_hash=""):
        self.hash = hash_id
        self.usage = usage
        self.creation_time = time_ns() if creation_time == 0 else creation_time
        self.short_link = short_link
        self.original_hash = original_hash
        self.names = [] if name is None else [Name(name)]

    @staticmethod
    def encode(file_class):
        return {'hash': file_class.hash,
                'creation_time': file_class.creation_time,
                'usage': file_class.usage,
                'names': [Name.encode(name) for name in file_class.names],
                'short_link': file_class.short_link,
                'original_hash': file_class.original_hash}

    @staticmethod
    def decode(file_document):
        return StoredFile(file_document['hash'],
                          file_document['creation_time'],
                          file_document['usage'],
                          [Name.decode(name) for name in file_document['names']],
                          file_document['short_link'],
                          file_document['original_hash'])


class Name:

    def __init__(self, name, creation_time=0, usage=0):
        self.name = name
        self.usage = usage
        self.creation_time = time_ns() if creation_time == 0 else creation_time

    @staticmethod
    def encode(name_class):
        return {'name': name_class.hash,
                'creation_time': name_class.size,
                'usage': name_class.usage}

    @staticmethod
    def decode(name_document):
        return StoredFile(name_document['name'],
                          name_document['creation_time'],
                          name_document['usage'])
