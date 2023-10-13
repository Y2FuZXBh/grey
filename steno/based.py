from struct import pack
from os.path import normpath
from cryptography.fernet import Fernet

sp = "example.jpg"
payload = "hello world"
key = "aPxm;j?Kzm04V6VZ$Y!yFfXP@g[CAuP9?)SmM.(vma:=^?EZEBkFU4qs*8%?zYbh".encode()
dp = "payload.jpg"

def hide(source, outpath, message):
    newFile = []
    source = normpath(source)
    outpath = normpath(outpath)
    with open(source, "rb") as tmp:
        for l in tmp.readlines():
            newFile.append(l)
    newFile.append(b"\xff\xd9")
    for i in message:
        _ = ord(i) + 100
        newFile.append(pack("B", _))
    newFile.append(b"\xff\xd9")
    with open(outpath, "wb") as up:
        up.writelines(newFile)

def show(source, password):
    source = normpath(source)
    message = ""
    with open(source, "rb") as check:
        for item in (
            check.readlines()[-1].split(b"\xff\xd9")[-2].decode("unicode_escape")
        ):
            message += chr(ord(item) - 100)
    if password:
        message = Fernet(password).decrypt(message).decode()
    return message

encrypted_string = Fernet(key).encrypt(payload.encode()).decode()

# hide
hide(
    source=sp,
    outpath=dp,
    message=encrypted_string,
)

# show
text = show(source=sp, password=key.encode())

# test
with open(sp, "rb") as tmp:
    print(tmp.readlines()[-1])
print(f"\n{sp}", text, sep="\n")
