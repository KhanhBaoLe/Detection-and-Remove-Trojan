import os
import subprocess

def create_test_batch():
    """Tạo file .bat test đơn giản"""
    batch_code = '''@echo off
REM Test Dynamic Analysis Script
REM File này sẽ tạo một số file test

REM Tạo file text trong TEMP
echo Test file created by dynamic analysis > "%TEMP%\\dynamic_test_file.txt"
echo. >> "%TEMP%\\dynamic_test_file.txt"
echo Timestamp: %date% %time% >> "%TEMP%\\dynamic_test_file.txt"

REM Tạo thêm một file khác
echo Hello from dynamic analysis test > "%TEMP%\\test_output.txt"

REM Tạo một thư mục test
mkdir "%TEMP%\\dynamic_test_folder" 2>nul

REM Sửa đổi file
echo Modified by dynamic analysis >> "%TEMP%\\dynamic_test_file.txt"

REM Chạy timeout
timeout /t 2 /nobreak

echo.
echo Test completed successfully!
timeout /t 2 /nobreak
exit /b 0
'''
    
    project_root = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(project_root, "test_sample.bat")
    
    with open(test_file, 'w') as f:
        f.write(batch_code)
    
    print(f"✅ Created test file: {test_file}")
    return test_file


def create_test_python():
    """Tạo file .py test đơn giản"""
    python_code = '''#!/usr/bin/env python3
import os
import time

# Tạo file test
temp_dir = os.path.expandvars("%TEMP%")
test_file = os.path.join(temp_dir, "python_dynamic_test.txt")

with open(test_file, "w") as f:
    f.write("Test file created by Python dynamic analysis\\n")
    f.write("This proves dynamic analysis is working!\\n")

# Tạo thêm một file khác
output_file = os.path.join(temp_dir, "python_test_output.txt")
with open(output_file, "w") as f:
    f.write("Output from Python test\\n")

# Tạo folder
test_folder = os.path.join(temp_dir, "python_test_folder")
os.makedirs(test_folder, exist_ok=True)

print("Python test script executed successfully!")
time.sleep(2)
'''
    
    project_root = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(project_root, "test_sample.py")
    
    with open(test_file, 'w') as f:
        f.write(python_code)
    
    print(f"✅ Created test file: {test_file}")
    return test_file


def create_test_exe():
    """Tạo file .exe test bằng PyInstaller"""
    simple_code = '''import os
import time

print("Test EXE started")

# Tạo file test
with open(os.path.expandvars("%TEMP%\\\\exe_test.txt"), "w") as f:
    f.write("Test file from EXE\\n")

print("Test complete")
time.sleep(2)
'''
    
    project_root = os.path.dirname(os.path.abspath(__file__))
    script_file = os.path.join(project_root, "simple_test.py")
    
    with open(script_file, 'w') as f:
        f.write(simple_code)
    
    # Build EXE
    try:
        result = subprocess.run(
            ["pyinstaller", "--onefile", "--windowed", script_file],
            cwd=project_root,
            capture_output=True,
            timeout=60
        )
        
        exe_file = os.path.join(project_root, "dist", "simple_test.exe")
        
        if os.path.exists(exe_file):
            print(f"✅ Created test EXE: {exe_file}")
            return exe_file
        else:
            print("❌ PyInstaller failed - using BAT instead")
            return None
    except Exception as e:
        print(f"⚠️ PyInstaller error: {e}")
        return None


def main():
    print("="*70)
    print("🔧 Creating test files for dynamic analysis...")
    print("="*70)
    print()
    
    create_test_batch()
    create_test_python()
    create_test_exe()
    
    print()
    print("="*70)
    print("✅ Test files created successfully!")
    print("="*70)
    print()
    print("Now run the main program and use Dynamic Analysis:")
    print("  1. python main.py")
    print("  2. Click '🔬 Dynamic Analysis'")
    print("  3. Select 'YES' to scan a single file")
    print("  4. Choose 'test_sample.bat' or 'test_sample.py'")
    print()
    print("You should see the analysis results in the log window!")
    print()


if __name__ == "__main__":
    main()