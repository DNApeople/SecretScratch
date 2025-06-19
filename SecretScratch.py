import os
from os import path
import zipfile
import json
from math import ceil
import base64
import lzma
import gzip
import hashlib
import requests
import textwrap
import argparse
import string
import random
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad ,unpad
    
from time import sleep

wd = os.getcwd()
dump_path = path.join(wd, "project_dump")

class JsonExtract:
    @staticmethod
    def local(project_file: str, extract_dir: str) -> dict:
        with zipfile.ZipFile(project_file, "r") as project:
            project.extractall(dump_path)

        with open(path.join(extract_dir, "project.json"), "r") as project_json:
            json_data = json.loads(project_json.read()) 
        
        return json_data

    @staticmethod
    def web(project_id: int) -> dict:
        session = requests.Session()
        project_id = str(project_id)

        public_data = session.get(
            f"https://api.scratch.mit.edu/projects/{project_id}"
        )

        public_data_json = public_data.json()

        try:
            project_token = public_data_json["project_token"]
        except KeyError:
            if public_data_json["code"] == "NotFound":
                raise Exception(f"ProjectNotFoundError: project of id:{project_id} not found")

        project_code = session.get(
            f"https://projects.scratch.mit.edu/{project_id}?token={project_token}"
        )

        return project_code.json()

def sha56sum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def getrandstr(length: int) -> str:
    ascii_chars = string.ascii_letters + string.digits
    return ''.join(random.choices(ascii_chars, k=length))

def load_entries(project_json: str) -> dict:
    entries = {
        "sprites" : [],
        "comment_ids" : [],
        "total_comments" : 0,
        "other_data" : None
    }

    entries["sprites"] = project_json["targets"][1:]
    entries["other_data"] = project_json["targets"][0]

    for i in range(len(entries["sprites"])):
        sprite_comments = list(entries["sprites"][i]["comments"].keys())
        entries["comment_ids"].append(sprite_comments)
        entries["total_comments"] += len(sprite_comments)

    return entries

def embed(project_json: dict, data: bytes, outfile: str, encrypted: bool, blocks_per_sprite: int):
    data = lzma.compress(data)
    charlimit = 8000
    comments_per_sprite = blocks_per_sprite

    decrypt_token = {"password": "", "salt": "", "data_hash": ""}
    comment_format = {
        "blockId": None,
        "x": 0,
        "y": 0,
        "width": 200,
        "height": 200,
        "minimized": True,
        "text": ""
    }
    targets = project_json["targets"]
    sprite = targets[1]

    if encrypted:
        ekey = sha56sum(get_random_bytes(32))
        salt = get_random_bytes(32)

        aes_key = PBKDF2(ekey, salt, dkLen=32)
        cipher  = AES.new(aes_key, AES.MODE_CBC)
        data = cipher.iv + cipher.encrypt(pad(data, AES.block_size))

        decrypt_token["password"] = ekey
        decrypt_token["salt"] = base64.b64encode(salt).decode()
        decrypt_token["data_hash"] = sha56sum(data)
    
    data_b64 = base64.b64encode(data).decode()
    comments_needed = ceil(len(data_b64)/charlimit)
    sprites_needed = ceil(comments_needed/comments_per_sprite)

    if comments_needed == comments_per_sprite:
        tail_count = 0
    elif comments_needed < comments_per_sprite:
        tail_count = comments_needed
    else:
        tail_count = comments_needed % comments_per_sprite

    data_blocks = textwrap.wrap(data_b64, charlimit)

    new_sprites = []
    blocks_written = 0

    for i in range(sprites_needed):
        sprite_cp = sprite.copy()
        sprite_name = f"sprite_{i}"
        print(f"\n[+] sprite: {sprite_name}")
        sprite_cp["name"] = sprite_name

        new_comments = {}

        if (tail_count > 0) and (i+1 == sprites_needed):
            comments_per_sprite = tail_count

        for j in range(comments_per_sprite):
            comment_cp = comment_format.copy()

            comment_cp["text"] = data_blocks[blocks_written]
            comment_cp["minimized"] = True
            comment_cp["x"] = -20000
            comment_cp["y"] = 9000

            comment_id = getrandstr(20)
            new_comments[comment_id] = comment_cp
            blocks_written += 1

            print(f"\t[ block: {str(blocks_written)} => comment: ({str(j+1)} id: {comment_id})]")
        
        sprite_cp["comments"] = new_comments
        new_sprites.append(sprite_cp)

    new_targets = [targets[0], *new_sprites]
    project_json["targets"] = new_targets

    with open(path.join(dump_path, "project.json"), "w") as project:
        project.write(json.dumps(project_json, indent=4))

    cwd = os.getcwd()

    os.chdir(dump_path)
    with zipfile.ZipFile(path.join(cwd, outfile), "w", zipfile.ZIP_DEFLATED) as project_out:
        for file in os.listdir(dump_path):
            project_out.write(file)

    print(f"\n[+] |e|m|b|e|d|d|e|d|==| & written: {outfile}")

    if encrypted:
        token_file = path.join(wd, f"{outfile}.dcr.json")
        with open(token_file, "w") as token:
            token.write(json.dumps(decrypt_token, indent=4))

        print(f"[+] decrypt token: {token_file} (KEEP SAFE)")

    autoremove()

def extract(entries: dict, outfile: str, decrypt_token : str | None = "") -> None:
    breaker = False
    blocks_read = 0
    data_b64 = ""
    for i, sprite in enumerate(entries["sprites"]):
        if breaker:
            break
        print(f"\n[+] sprite: {sprite["name"]}")
        for j, comment_id in enumerate(entries["comment_ids"][i]):
            block_text = sprite["comments"][comment_id]["text"]
            if block_text == "":
                breaker = True
                break
            print(f"\t[ block: {str(blocks_read + 1)} => comment: ({str(j+1)} id: {comment_id})]")
            data_b64 += block_text
            blocks_read += 1

    data = base64.b64decode(data_b64)

    if decrypt_token:
        with open(decrypt_token, "r") as token:
            token_data = json.loads(token.read())   
        
        if sha56sum(data) == token_data["data_hash"]:
            aes_key = PBKDF2(token_data["password"], base64.b64decode(token_data["salt"]), dkLen=32)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=data[:16])
            data = unpad(cipher.decrypt(data[16:]), AES.block_size)
        else:
            raise Exception("Data hash dosen't match, possible corruption")

    data = lzma.decompress(data)

    with open(outfile, "wb") as out:
        out.write(data)
    
    print(f"\n[+] |||||||||||| -> ( extracted ) & written: {outfile}")
    
    autoremove()
    
def autoremove():
    if path.exists(dump_path):
        for file in os.listdir(dump_path):
            os.remove(path.join(dump_path, file))
        os.chdir(wd)
        sleep(0.1)
        os.rmdir(dump_path)

        print(f"[+] autoremoved {dump_path}")
    
def main():
    parser = argparse.ArgumentParser(description='SecretScratch file embedder/extractor.')
    subparsers = parser.add_subparsers(dest='action')

    embed_sub = subparsers.add_parser('embed')
    embed_sub.add_argument('-i', '--input', required=True, action="store", type=str, help="File to embed")
    embed_sub.add_argument('-c', '--cover', required=True, action="store", type=str, help="Cover file (scratch project)")
    embed_sub.add_argument('-o', '--output', required=True, action="store", type=str, help="Output file")
    embed_sub.add_argument('-enc','--encrypt',action="store_true", help="Encrypt data")

    extract_sub = subparsers.add_parser('extract')
    web_local = extract_sub.add_mutually_exclusive_group(required=True)
    web_local.add_argument('-web', '--webproject', action="store", type=int, help="Download project by <project_id>")
    web_local.add_argument('-loc', '--localfile', action="store", type=str, help="Local project file")
    extract_sub.add_argument('-o', '--output', required=True, action="store", type=str, help="Output file")
    extract_sub.add_argument('-dec','--decrypt',action="store", type=str, help="Decrypt data --decrypt <token.json>")

    args = parser.parse_args()

    action = args.action

    if action == "embed":
        with open(args.input, "rb") as file:
            data = file.read()
        project_json = JsonExtract.local(args.cover, dump_path)
        embed(project_json, data, args.output, args.encrypt, 100)
    elif action == "extract":
        if args.webproject:
            project_json = JsonExtract.web(args.webproject)   
        else:
            project_json = JsonExtract.local(args.localfile, dump_path)
        entries = load_entries(project_json)
        extract(entries, args.output, args.decrypt)
    else:
        parser.parse_args(['--help'])

if __name__ == "__main__":
    main()
