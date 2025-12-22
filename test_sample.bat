@echo off
REM Test Dynamic Analysis Script
REM File này sẽ tạo một số file test

REM Tạo file text trong TEMP
echo Test file created by dynamic analysis > "%TEMP%\dynamic_test_file.txt"
echo. >> "%TEMP%\dynamic_test_file.txt"
echo Timestamp: %date% %time% >> "%TEMP%\dynamic_test_file.txt"

REM Tạo thêm một file khác
echo Hello from dynamic analysis test > "%TEMP%\test_output.txt"

REM Tạo một thư mục test
mkdir "%TEMP%\dynamic_test_folder" 2>nul

REM Sửa đổi file
echo Modified by dynamic analysis >> "%TEMP%\dynamic_test_file.txt"

REM Chạy timeout
timeout /t 2 /nobreak

echo.
echo Test completed successfully!
timeout /t 2 /nobreak
exit /b 0
