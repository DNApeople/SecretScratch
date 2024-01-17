import os
import zipfile
import json
import math
import base64
import lzma
import hashlib
import textwrap
from collections import namedtuple
from time import sleep
import argparse
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad ,unpad


def SHA256(data):
    return hashlib.sha256(data).hexdigest()

def load(InputFile : str = "path\\to\\input\\file") -> tuple:
    InputFile:str = InputFile
    DefautlPath:str = str(os.path.join(os.getcwd(), "Project"))

    # Try to extract sb3/sb2 file to Default.path//Project.
    try:
        with zipfile.ZipFile(InputFile, "r") as sb3:
            sb3.extractall(DefautlPath)
        sb3.close()
    except zipfile.BadZipFile:
        # ALL scratch projects are valid zip files.
        print(f"^^^^^^ {InputFile} isn't a valid scratch project file or is either corrupted. ^^^^^^")

    if os.path.exists(os.path.join(DefautlPath, 'project.json')):

        with open(os.path.join(DefautlPath, 'project.json')) as jfile:
            JsonData = json.loads(jfile.read())
        jfile.close()

        Entries : dict = {
            "Sprites"       : list(JsonData["targets"][1:]), # All sprites in project                                                          # List of all sprites
            "CommentIDs"    : [],                            # IDs of all comments 
            "TotalComments" : 0,                             # Sum of all comment boxes                                                          # sum of all comment boxes
            "OtherData"     : JsonData["targets"][0]         # Other data in "targets" list                                                       # other data in json file
        }

        # form a list of commentIDs per sprite & add it to Entries["CommentIDs"].
        Entries["CommentIDs"] = [list(Entries["Sprites"][i]['comments'].keys()) for i in range(len(Entries["Sprites"]))]

        # sum of all comment boxes in all sprites & update Entries["TotalComments"] with it.
        for i in range(len(Entries["CommentIDs"])):
            Entries["TotalComments"] += len(Entries["CommentIDs"][i])

        # Create named tuple with returning values
        ProjectData = namedtuple('ProjectData', (
            "CurrentPath",
            "Entries"    ,
            "All"        ,
        ))
            
        return ProjectData(
            DefautlPath,
            Entries,
            JsonData
        )
    # return None, None, None if project.json not found inside scratch project (zipfile)
    return ProjectData(
        None,
        None,
        None
    )

def action(Action : str, data : bytes, output : str, Encrypted, ProjectData : tuple):
    """           
    ProjectData --> direct output of "load" function
    """ 
    def embed(embed = data, output : str = output, encrypt = Encrypted):
        embed      = lzma.compress(embed)
        output     = output
        cwd        = os.getcwd()
        charLimit  = 8000  # max length scratch allows in comment box

        if encrypt:
            CryptKey = (get_random_bytes(32), SHA256(get_random_bytes(32))) #(Salt, Password)
            
            AES_Key        = PBKDF2(CryptKey[1], CryptKey[0], dkLen=32) # Generate AES key for encryption
            cipher         = AES.new(AES_Key, AES.MODE_CBC)
            Encrypted_data = cipher.encrypt(pad(embed, AES.block_size))
            embed          = cipher.iv + Encrypted_data            

            Decrypt_token = json.dumps(
            {   
                "password"  : CryptKey[1],
                "salt"      : base64.b64encode(CryptKey[0]).decode(),
                "data_hash" : SHA256(embed)
            }
            , indent=4
            )

        data  = base64.b64encode(embed).decode()
        boxes = math.ceil(len(data)/charLimit) # Get ammount of comment boxes neede to embed file

        if boxes > ProjectData.Entries["TotalComments"]:
            autoremove()
            print(f"^^^^^^ {boxes} comment boxes needed for embedding ,only {ProjectData.Entries['TotalComments']} found. ^^^^^^")

        DataBlocks = textwrap.wrap(data, charLimit) # brake data into 8000 char blocks.
        
        BrakeMain = False
        counter   = 0
        for n, sprite in enumerate(ProjectData.Entries["Sprites"]):
            if BrakeMain:
                break
            print(f"\n[+] In {sprite['name']}\n")
            for _, ID in enumerate(ProjectData.Entries['CommentIDs'][n]):
                if counter >= len(DataBlocks):
                    BrakeMain = True
                    break
                print(f"  [=>] CommentID = {ID} : part {str(counter + 1)}")
                sprite["comments"][ID]["text"]      = DataBlocks[counter]
                sprite["comments"][ID]["minimized"] = True
                sprite["comments"][ID]["x"]         = -20000 #-1706.6666666666665
                sprite["comments"][ID]["y"]         = 9000   #879.9999999999999
                counter += 1  
        print("\n")

        ProjectData.All["targets"] = [ProjectData.Entries["OtherData"]]
        for sprite in ProjectData.Entries["Sprites"]:
            ProjectData.All["targets"].append(sprite)

        with open(os.path.join(ProjectData.CurrentPath, "project.json"), "w") as jfile:
            jfile.write(json.dumps(ProjectData.All, indent=4))
        jfile.close()

        os.chdir(ProjectData.CurrentPath)
        with zipfile.ZipFile(os.path.join(cwd, output), "w", zipfile.ZIP_DEFLATED) as end:
            for file in os.listdir(ProjectData.CurrentPath):
                end.write(file)
        end.close()

        autoremove()

        print(f"[+] Embedded in {output}")

        if encrypt:
            write_token_to = f"{output}.dcr.json"
            with open(write_token_to, "w") as token_file:
                token_file.write(Decrypt_token)
            token_file.close()

            print(f"[+] Decrypt token written to {write_token_to} (Keep safe)")
        print("\n")

    def extract(output = output, Decrypt_key = Encrypted):

        BrakeMain = False
        counter   = 0
        b64string = ''
        for n, sprite in enumerate(ProjectData.Entries["Sprites"]):
            if BrakeMain:
                break
            print(f"\n[+] In {sprite['name']}\n")
            for _, ID in enumerate(ProjectData.Entries['CommentIDs'][n]):
                text = sprite['comments'][ID]['text']
                if text == '':
                    BrakeMain = True
                    break
                print(f"[=>] CommentID = {ID} : part {str(counter + 1)}")
                b64string += sprite["comments"][ID]["text"]
                counter += 1
        print("\n")
        
        Main_data = base64.b64decode(b64string)

        if Decrypt_key:
            with open(Decrypt_key, "r") as file:
                Crypt_token = json.loads(file.read())
            file.close()
        
            if SHA256(Main_data) != Crypt_token["data_hash"]:
                Data_corrupt = True

            try:
                AES_Key = PBKDF2(Crypt_token["password"], base64.b64decode((Crypt_token["salt"])), dkLen=32)
                cipher  = AES.new(AES_Key, AES.MODE_CBC, iv = Main_data[:16])

                Main_data = unpad(cipher.decrypt(Main_data[16:]), AES.block_size)
                
            except Exception as exception:
                if Data_corrupt:
                    print(f"Data hash dosent't match original from '{Decrypt_key} : data_hash'")
                    raise exception
                else:
                    raise exception

        with open(output, "wb") as out:
            out.write(lzma.decompress(Main_data))
        out.close()

        print(f"[+] Extracted to {output}")

        autoremove()
        print("\n")

    def autoremove():
        for file in os.listdir(ProjectData.CurrentPath):
            os.remove(os.path.join(ProjectData.CurrentPath, file))
        os.chdir("..")
        sleep(0.1)
        os.rmdir(ProjectData.CurrentPath)

        print(f"[+] Autoremoved {ProjectData.CurrentPath}")

    if  Action == "embed":
        embed()

    if Action == "extract":
        extract()

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
        file.close()
    
        action(
            "embed",
            data,
            args.output,
            args.encrypt,
            load(InputFile = args.input)
        )

    if args.extract:
        action(
            "extract",
            None,
            args.output,
            args.decrypt,
            load(InputFile = args.input)
        )

if __name__ == "__main__":
    main()