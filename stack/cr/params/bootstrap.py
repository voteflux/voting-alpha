import os, sys

main_dir = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, main_dir)
sys.path.insert(0, os.path.join(main_dir, '../common/deps'))
sys.path.insert(0, os.path.join(main_dir, '../common'))
sys.path.insert(0, '/opt/common/deps')
sys.path.insert(0, '/opt/common')
sys.path.insert(0, '/opt/deps')
sys.path.insert(0, '/opt')
print('path', sys.path)

BOOTSTRAP = True