
import sys
s = "".join(sys.argv[1:]).replace(" ","").strip()

if s == "":
    print("reading from stdin until EOF")
    s = sys.stdin.read()
    s = s.replace(" ","").replace("\t","").strip()

size = int(len(s) / 2)
print("Array size: " + str(size))
print("{ ", end="")
for i in range(size):
    print("0x" + s[i*2:i*2+2], end="")
    if i < size - 1:
        print(", ", end="")
print(" }")
