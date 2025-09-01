from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from output import *

B = Matrix(ZZ, [[1,0,a],[0,1,b],[0,0,c]])
R = B.LLL()
x,y,z = min(R.rows(), key=lambda v: v.norm())

assert (z - a*x - b*y) % c == 0 and (z - a*x - b*y)//c == 1  
iv  = (-x) % (1<<128)
key = (-y) % (1<<128)

pt = unpad(AES.new(key.to_bytes(16,'big'), AES.MODE_CBC, iv.to_bytes(16,'big')).decrypt(bytes.fromhex(ct)), 16)
print(pt.decode())
