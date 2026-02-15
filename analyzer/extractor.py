import zipfile
import os
import shutil

def extract_apk(apk_path, extract_folder):
    folder_name = os.path.splitext(os.path.basename(apk_path))[0]
    extract_path = os.path.join(extract_folder,folder_name)

    os.makedirs(extract_path,exist_ok=True)

    with zipfile.ZipFile(apk_path,'r') as zip_ref:
        zip_ref.extractall(extract_path)

    return extract_path
