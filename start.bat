echo 'Installing needed things to compile...'

pip install ctypes
pip install pyinstaller

pyinstaller main.py --onefile
echo 'Done compiling , check for the executeable'
