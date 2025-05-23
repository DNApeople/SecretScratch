import os
from os import path
import zipfile
import json
from math import ceil
import base64
import lzma
import hashlib
import textwrap
import argparse
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad ,unpad
    
from time import sleep

wd = os.getcwd()
dump_path = path.join(wd, "project_dump")

def sha56sum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def load_entries(infile: str) -> tuple[dict, dict]:
    entries = {
        "sprites" : [],
        "comment_ids" : [],
        "total_comments" : 0,
        "other_data" : None
    }

    with zipfile.ZipFile(infile, "r") as project:
        project.extractall(dump_path)

    with open(path.join(dump_path, "project.json"), "r") as project_json:
        json_data = json.loads(project_json.read()) 

    entries["sprites"] = json_data["targets"][1:]
    entries["other_data"] = json_data["targets"][0]

    for i in range(len(entries["sprites"])):
        sprite_comments = list(entries["sprites"][i]["comments"].keys())
        entries["comment_ids"].append(sprite_comments)
        entries["total_comments"] += len(sprite_comments)

    return entries, json_data

def embed(project_json: dict, entries: dict, data: bytes, outfile: str, encrypted: bool) -> None:
    data = lzma.compress(data)
    charlimit = 8000

    decrypt_token = {"password": "", "salt": "", "data_hash": ""}

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
    comments_needed = ceil(len(data)/charlimit)

    if comments_needed > entries["total_comments"]:
        autoremove()
        raise Exception(f"Comments needef for embed: {comments_needed}, but found {entries["total_comments"]}")
    
    data_blocks = textwrap.wrap(data_b64, charlimit)

    breaker = False
    blocks_written   = 0
    for i, sprite in enumerate(entries["sprites"]):
        if breaker:
            break
        print(f"\n[+] sprite: {sprite["name"]}")
        for j, comment_id in enumerate(entries["comment_ids"][i]):
            if blocks_written >= len(data_blocks):
                breaker = True
                break
            print(f"\t[ block: {str(blocks_written + 1)} => comment: ({str(j+1)} id: {comment_id})]")
            sprite["comments"][comment_id]["text"] = data_blocks[blocks_written]
            sprite["comments"][comment_id]["minimized"] = True
            sprite["comments"][comment_id]["x"] = -20000
            sprite["comments"][comment_id]["y"] = 9000
            blocks_written += 1

    project_json["targets"] = []
    project_json["targets"].append(entries["other_data"])

    for sprite in entries["sprites"]:
        project_json["targets"].append(sprite)
    
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
    for file in os.listdir(dump_path):
        os.remove(path.join(dump_path, file))
    os.chdir(wd)
    sleep(0.1)
    os.rmdir(dump_path)

    print(f"[+] autoremoved {dump_path}")
    
def main():
    parser = argparse.ArgumentParser(description='SecretScratch file embeder/extractor.')

    EmbExt  = parser.add_mutually_exclusive_group(required=True)
    EmbExt.add_argument('-em','--embed', help="File to be embeded.")
    EmbExt.add_argument('-ex','--extract',action='store_true', help="extract from <input.sb3>")
    parser.add_argument('-i','--input',required=True, help="Scratch .sb3 file.")
    parser.add_argument('-o','--output',required=True, help="Output file (Can be used with -em/--embed & -ex/--extract)")

    encrypt = parser.add_mutually_exclusive_group()
    encrypt.add_argument('-enc','--encrypt',action='store_true', help="Encrypt embeding data")
    encrypt.add_argument('-dec','--decrypt', help="Decrypt extracted data (-dec/--decrypt <keys.json>)")
    args = parser.parse_args() 

    if args.embed:
        with open(args.embed, "rb") as file:
            data = file.read()
        entries, json_data = load_entries(args.input)
        embed(json_data, entries, data, args.output, args.encrypt)
    elif args.extract:
        entries, _ = load_entries(args.input)
        extract(entries, args.output, args.decrypt)

if __name__ == "__main__":
    main()
