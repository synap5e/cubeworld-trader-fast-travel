portal_data_zl = (
'78daed9c3d4ec3401046e706d050d0711497e9525352525244a242db51463900a7e0045c811b70032e80c2281bad46bbb6e3'
'9f24309bf7f4c59ab5bd6b2bd2b393d8f18d885cebeb5660c76a2473fada1156333867f710c211f7ff58ef3cc0451d2e62f7'
'f5dd7654b2ee080b704ec28e696b6a73acefe50893b70e00137c9fbcb2365fafb6318d848385a61ce144bb0a00a7f35db390'
'4d9a964d4deb08f80ee0c5f717f9191e7c07a8c3f7a5bc7505df01eaf0fd59be0f46958f05be0354e3fbbdbc67b18bf01dc0'
'bbef4ff215a346a7ba9c190b7c07a8c0f707f9488e6b9d35d314df015cfbaed347f9549d75da53a426be0378f77d78f01dc0'
'afeff1d3bb3d8fdb337bb908df01bcfb6ebfa767c916e13b805fdfe375b7f80bbc2dbae6e33b8077dfedc5f7d62bf2a9c677'
'00bfbea79b66e37d74adb18bf01da002dfed7df259ec3af80ee0d7f7856c4605df01eaf0ddfee7bd6ce23b8077df1bd9273e'
'c7a6bf6824e03bc0dffa3ee7f97549e481e1f97500ff41f92174f51d687acf08d3b60e008e0e177051fc02300bc712'
)

import zlib
portal_data = zlib.decompress(portal_data_zl.decode('hex'))


# This array is used to encode and decode the resource files 
data_key = [
0x00001092, 0x0000254F, 0x00000348, 0x00014B40, 0x0000241A, 0x00002676,
0x0000007F, 0x00000009, 0x0000250B, 0x0000018A, 0x0000007B, 0x000012E2,
0x00007EBC, 0x00005F23, 0x00000981, 0x00000011, 0x000085BA, 0x0000A566,
0x00001093, 0x0000000E, 0x0002D266, 0x000007C3, 0x00000C16, 0x0000076D,
0x00015D41, 0x000012CD, 0x00000025, 0x0000008F, 0x00000DA2, 0x00004C1B,
0x0000053F, 0x000001B0, 0x00014AFC, 0x000023E0, 0x0000258C, 0x000004D1,
0x00000D6A, 0x0000072F, 0x00000BA8, 0x000007C9, 0x00000BA8, 0x0000131F,
0x000C75C7, 0x0000000D
]

def swap(data, index1, index2):
	temp = data[index1]
	data[index1] = data[index2]
	data[index2] = temp

def encoder(data, decode):
	data = bytearray(data)
	size = len(data)
	r = range(size)
	if decode:
		r = reversed(r)
	for i in r:
		location = data_key[i % 44] + i
		swap(data, i, location % size)
	for i in range(size):
		data[i] = 0xFF - data[i]
	return data

print "Backing up files"
f = file('data1.db', 'rb')
d = f.read()
f.close()
f = file('data1.db.bak', 'wb')
f.write(d)
f.close()
print "Backed up data1.db to data1.db.bak"

import sqlite3

conn = sqlite3.connect('data1.db')
for model in range(0, 4):
	conn.execute("UPDATE blobs SET value=? WHERE key=?", (sqlite3.Binary(encoder(portal_data, False)), unicode("market-stand%d.cub" % model)))
conn.commit()
conn.close()

print "DONE!"
print "-"*60
print ""
print "press enter to close"
raw_input()
