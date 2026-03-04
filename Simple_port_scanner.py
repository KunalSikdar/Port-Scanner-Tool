import socket,sys
import time, queue
import threading
import requests


usage = "Python3 Simple_port_scanner.py TARGET START_PORT END_PORT THREDS "

print("*" *50)
print("Python Simple Port Scanner ")
print("*" *50)

target = sys.argv[1]
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])
thread_no = int(sys.argv[4])

result = "[+] Result:\nPORT\TSTATE\tSERVICE\n"

try:
    target = socket.gethostbyname(target)
except:
    print("[-] Host resoulation failed...!")
    exit()

print("[+] Scanning target : {}".format(target))

if not target or not str(start_port) or not end_port or not thread_no :
    print(usage)
    exit()

def get_banner(port , s):
    if(port == 80):
        responses = requests.get("http://" + target)
        return responses.headers['server']
    try:
        return s.recv(1024).decode()
    except:
        return 'Not Found '

def scan_port(t_no):
    global result
    while not q.empty():
        port = q.get()
        print("Scanning for port {}..".format(port))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            conn = s.connect_ex((target , port))
            if not conn:
                banner = get_banner(port , s)
                banner = ''.join(banner.splitlines())
                result += f"{port}\tOPEN\t{banner}\n"
                s.close()
        except:
            pass
        q.task_done()

q = queue.Queue()
start_time = time.time()
for j in range(start_port, end_port +1):
    q.put(j)

for i in range(thread_no):
    t = threading.Thread(target = scan_port,args = (i,))
    t.start()
q.join()

end_time = time.time()
print(result)
print("Time taken : {}".format(end_time - start_time))

with open("ports.txt", 'w') as file:
    file.write(f"Ports scan results for target : {target}\n ")
    file.write(result)
print("[+] Written to file ports.txt ")

