import os, sys

main_dir = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, main_dir)
os.system(f"ls -al {main_dir}")
os.system(f"ls -al {main_dir}/api")
os.system(f"ls -al {main_dir}/api/common")
sys.path.insert(0, os.path.join(main_dir, 'api/common/deps'))
sys.path.insert(0, os.path.join(main_dir, 'api/common'))
sys.path.insert(0, os.path.join(main_dir, 'api/deps'))
sys.path.insert(0, os.path.join(main_dir, 'deps'))
sys.path.insert(0, '/opt/deps')
sys.path.insert(0, '/opt')
print(sys.path)

BOOTSTRAP = True
