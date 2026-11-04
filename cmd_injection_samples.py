import os
import subprocess

# --- VULNERABLE examples ---

def ping_host_v1(hostname):  # VULNERABLE
    os.system("ping -c 1 " + hostname)

def ping_host_v2(hostname):  # VULNERABLE
    os.system(f"ping -c 1 {hostname}")

def run_script_v1(filename):  # VULNERABLE
    cmd = "cat " + filename
    subprocess.run(cmd, shell=True)

def list_dir_v1(dirname):  # VULNERABLE
    os.popen("ls " + dirname)


# --- SAFE examples ---

def ping_host_safe(hostname):  # SAFE
    subprocess.run(["ping", "-c", "1", hostname])

def run_script_safe(filename):  # SAFE
    subprocess.run(["cat", filename])

def static_command():  # SAFE
    os.system("echo hello")