from androguard.core.bytecodes import apk
import sys
import hashlib

banner = "\33[92m" + """
   ____      _          _    ____  _  __     _        __       
  / ___| ___| |_       / \  |  _ \| |/ /    (_)_ __  / _| ___  
 | |  _ / _ \ __|____ / _ \ | |_) | ' /_____| | '_ \| |_ / _ \ 
 | |_| |  __/ ||_____/ ___ \|  __/| . \_____| | | | |  _| (_) |
  \____|\___|\__|   /_/   \_\_|   |_|\_\    |_|_| |_|_|  \___/              
                                                                                                                                                                                                            
Author: @erberkan
Date: 11-09-2020
""" + " \033[0m"


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


dangerous_perm_list = [
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.READ_HISTORY_BOOKMARKS",
    "android.permission.WRITE_HISTORY_BOOKMARKS",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.READ_LOGS",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.GET_TASKS",
    "android.permission.BLUETOOTH",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE"
]


def get_file_hashes(file):
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256 = hashlib.sha256(f.read()).hexdigest();

    return "\nMD5: {0}".format(md5.hexdigest()) + "\n" + "SHA1: {0}".format(
        sha1.hexdigest() + "\n" + "SHA256: {0}".format(sha256))


try:
    usr_arg = sys.argv[1]

    print(banner)

    apk_file = apk.APK(usr_arg)

    print(bcolors.WARNING + "[>] Application Name = " + apk_file.get_app_name() + bcolors.ENDC)
    print("[>] Package Name = " + apk_file.package)
    print(bcolors.OKBLUE + get_file_hashes(usr_arg) + bcolors.ENDC)

    print(bcolors.BOLD + "\n[>] Permissions:\n" + bcolors.ENDC)

    for perms in apk_file.permissions:
        if dangerous_perm_list.__contains__(perms):
            print("\t" + bcolors.FAIL + "[!] " + perms + bcolors.ENDC)
        else:
            print("\t" + "[-] " + perms)

    print("KTHNXBYE!")
except:
    print(banner)
    print("Usage: python3 getApkInfos.py <apk file>")
