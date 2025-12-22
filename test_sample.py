#!/usr/bin/env python3
import os
import time

# Tạo file test
temp_dir = os.path.expandvars("%TEMP%")
test_file = os.path.join(temp_dir, "python_dynamic_test.txt")

with open(test_file, "w") as f:
    f.write("Test file created by Python dynamic analysis\n")
    f.write("This proves dynamic analysis is working!\n")

# Tạo thêm một file khác
output_file = os.path.join(temp_dir, "python_test_output.txt")
with open(output_file, "w") as f:
    f.write("Output from Python test\n")

# Tạo folder
test_folder = os.path.join(temp_dir, "python_test_folder")
os.makedirs(test_folder, exist_ok=True)

print("Python test script executed successfully!")
time.sleep(2)
