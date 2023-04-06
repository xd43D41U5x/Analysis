#Simple RC4 decrypt function
def rc4Decrypt(data,key):  
    S = list(range(256))
    j = 0
    out = []
    #KSA Phase
    for i in range(256):
        j = (j + S[i] + key[i % len(key)])% 256
        S[i] , S[j] = S[j] , S[i]
    #PRGA Phase
    i = j = 0
    for char in data:
        i = ( i + 1 ) % 256
        j = ( j + S[i] ) % 256
        S[i] , S[j] = S[j] , S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    return out

#read in shellcode as bytes
with open('feedmuhface', mode='rb') as file: 
    fileContent = file.read()

#convert key to bytes
key = str.encode("3jB(2bsG#@c7")

decrypt = rc4Decrypt(fileContent,key)
decOut = ''

#format decrypted data for writing
for d in decrypt:
     decOut += "{:02x}".format(d,'x').upper()
decOutFinal = bytearray.fromhex(decOut)    

with open('shellout', 'wb') as f:
        #for d in decrypt:
        f.write(decOutFinal)

print(f'\n[*] - Output file decrypted and saved as shellout')  
