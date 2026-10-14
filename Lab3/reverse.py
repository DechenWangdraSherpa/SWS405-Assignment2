import base64

data = open("vip.txt").read().strip().strip("\x00")
step1 = base64.b64decode(data)            # undo the LAST step first
key = 3                                    # replace with the key you read in evilscript.py
print("".join(chr(b ^ key) for b in step1))
