import os
import tempfile
import time
from scanner.dynamic_analysis_api import DynamicAPI
from database.db_manager import DatabaseManager

def create_test_executable():
    """Tạo file .exe test đơn giản"""
    # Tạo script Python tạm thời
    test_code = '''
import os
import time

# Tạo file test
with open(os.path.expandvars("%TEMP%\\\\dynamic_test_file.txt"), "w") as f:
    f.write("Test file created by dynamic analysis")

# Tạo process con
os.system("echo Hello > %TEMP%\\\\test_output.txt")

# Đợi một chút
time.sleep(3)

print("Test complete!")
'''
    
    # Tạo file tạm thời
    temp_dir = tempfile.gettempdir()
    script_path = os.path.join(temp_dir, "test_dynamic.py")
    
    with open(script_path, 'w') as f:
        f.write(test_code)
    
    return script_path

def test_dynamic_analysis():
    """Test phân tích động"""
    print("=" * 80)
    print("🧪 TESTING DYNAMIC ANALYSIS")
    print("=" * 80)
    
    # Khởi tạo
    db = DatabaseManager()
    api = DynamicAPI(db)
    
    # Tạo file test
    test_file = create_test_executable()
    print(f"\n✅ Created test file: {test_file}")
    
    # Chạy dynamic analysis
    print(f"\n🔬 Running dynamic analysis...")
    result = api.analyze(test_file, timeout=10, capture_network=False)
    
    # Hiển thị kết quả
    print("\n" + "=" * 80)
    print("📊 ANALYSIS RESULT")
    print("=" * 80)
    
    if result['success']:
        print(f"✅ Status: SUCCESS")
        print(f"📌 Run ID: {result['run_id']}")
        print(f"📌 Sample ID: {result['sample_id']}")
        print(f"🔴 Threat Score: {result['threat_score']:.1f}/100")
        print(f"⏱️ Duration: {result['duration']:.2f}s")
        print(f"📊 Exit Code: {result['exit_code']}")
        
        summary = result['summary']
        print(f"\n📋 Detailed Summary:")
        print(f"  Process Info:")
        if summary['process_summary']:
            proc = summary['process_summary'][0]
            print(f"    - Max Memory: {proc.get('max_memory_mb', 0):.1f} MB")
            print(f"    - Max CPU: {proc.get('max_cpu_percent', 0):.1f}%")
            print(f"    - Child Processes: {len(proc.get('child_processes', []))}")
        
        print(f"  File System Changes:")
        if summary['fs_summary']:
            fs = summary['fs_summary'][0]
            print(f"    - Files Created: {fs.get('files_created', 0)}")
            print(f"    - Files Modified: {fs.get('files_modified', 0)}")
            created = fs.get('created_files', [])
            if created:
                for f in created[:3]:
                    print(f"      • {f}")
        
        print(f"\n✅ Dynamic analysis completed successfully!")
    else:
        print(f"❌ Status: FAILED")
        print(f"❌ Error: {result.get('error')}")
    
    # Cleanup
    try:
        os.remove(test_file)
    except:
        pass
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    test_dynamic_analysis()