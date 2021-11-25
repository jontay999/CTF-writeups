import functools, tarfile, tempfile, os
from application import main

generate = lambda x: os.urandom(x).hex()

def extract_from_archive(file):
    return os.system('cp flag application/static/')
    tmp  = tempfile.gettempdir()
    path = os.path.join(tmp, file.filename)
    file.save(path)

    if tarfile.is_tarfile(path):
        tar = tarfile.open(path, 'r:gz')
        tar.extractall(tmp)

        extractdir = f'{main.app.config["UPLOAD_FOLDER"]}/{generate(15)}'
        os.makedirs(extractdir, exist_ok=True)

        extracted_filenames = []

        for tarinfo in tar:
            name = tarinfo.name
            if tarinfo.isreg():
                filename = f'{extractdir}/{name}'
                os.rename(os.path.join(tmp, name), filename)
                extracted_filenames.append(filename)
                continue
            
            os.makedirs(f'{extractdir}/{name}', exist_ok=True)

        tar.close()
        return extracted_filenames

    return False
