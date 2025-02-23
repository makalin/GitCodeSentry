import os

def read_files_in_directory(directory):
    files = {}
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                files[file_path] = f.read()
    return files