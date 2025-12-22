
import os
import time

print("Test EXE started")

# Tạo file test
with open(os.path.expandvars("%TEMP%\\exe_test.txt"), "w") as f:
    f.write("Test file from EXE\n")

print("Test complete")
time.sleep(2)
