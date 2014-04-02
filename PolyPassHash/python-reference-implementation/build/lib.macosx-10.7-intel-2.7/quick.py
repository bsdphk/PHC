import fastpolymath_c
print "[2,4,5] * [14,30,32] -> "
x = fastpolymath_c.full_lagrange(chr(2)+chr(4)+chr(5),chr(14)+chr(30)+chr(32))

for c in x:
  print ord(c),

print


