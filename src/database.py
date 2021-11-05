import string
from typing import List

from pymongo import ReturnDocument, MongoClient

from storedFile import StoredFile, Name

from settings import DATABASE_URL


class Database:

    def __init__(self):
        self.session = MongoClient(DATABASE_URL)['FileHosting']['FileHosting']

    def insert_file(self, file: StoredFile) -> None:
        self.session.insert_one(StoredFile.encode(file))

    def find_file(self, file_hash: string) -> StoredFile:
        return StoredFile.decode(self.session.find_one({'hash': file_hash}))

    def find_files(self, files_hash: List[string]) -> List[StoredFile]:
        return [StoredFile.decode(self.session.find_one({'hash': file_hash})) for file_hash in files_hash]

    def get_files(self) -> List[StoredFile]:
        return [StoredFile.decode(file) for file in self.session.find({})]

    def delete_file(self, file_hash: string) -> StoredFile:
        return StoredFile.decode(self.session.find_one_and_delete({'hash': file_hash}))

    def replace_file(self, file_hash: string, new_file: StoredFile) -> StoredFile:
        return StoredFile.decode(
            self.session.find_one_and_replace({'hash': file_hash}, StoredFile.encode(new_file),
                                              return_document=ReturnDocument.AFTER))

    def usage_increase(self, file_hash: string) -> None:
        self.session.update_one({'hash': file_hash}, {'$inc': {'usage': 1}})

    def add_name(self, file_hash: string, name: Name) -> None:
        self.session.update_one({'hash': file_hash}, {'$addToSet': Name.encode(name)})
