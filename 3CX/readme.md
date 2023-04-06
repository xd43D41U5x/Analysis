See pdf for analysis.  It is pretty large, so keep hitting "more" or download. 

cpp = Uses AES GCM and the found values during analysis to decrypt.  
7z = Patched dll to make analysis easier.  
py = simple rc4 decrypt example that could be used here

I also wrote a python script to parse the BCrypt Auth Cipher Mode Info found in AES GCM during the BCrypt call.
https://github.com/xd43D41U5x/Scripts/blob/master/bCryptCipherInfoParser.py
