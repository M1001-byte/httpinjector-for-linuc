from signal import SIGKILL,SIGINT,signal
from time import sleep, strftime
import socket, select, os,  re, requests, ssl, multiprocessing, threading, socks, json, traceback
from subprocess import Popen,PIPE
from colorama import Fore

class injector():
    def __init__(self,config_file:str="config.json") -> None:
        self.config_file = config_file
        self.reconn_attemps = 0
        self.parse_config()
        self.listen_sock()
        try:
            while True:
                threading.Thread(target=self.sshtunnel).start()
                conn,_ = self.local_server.accept()
                self.reconn_attemps += 1
                sleep(0.2)
                if self.reconn_attemps >= 100:
                    self.reconn_attemps = 0
                    os.system("clear")
                
                conn.settimeout(self.timeout)
                self.handle_connection(conn)
        except Exception as er:
            pass
    def parse_config(self) -> None:
        """
        Read config from json file
        """
        try:
            self.sleep_dict = {
                '[split]': 0.6,
                '[delay]': 2,
                '[instant]': 0.02

            }

            self.config_json = json.loads(open(self.config_file, 'r').read())
            self.profile = self.config_json['Profiles'][0]
            print_log(f"Using profile: {Fore.GREEN}{self.profile['Name']}{Fore.WHITE}")
            
            self.local_addr = ("127.0.0.1", int(self.config_json['Settings']['bind_port']))
            
            ssh_field = str(self.profile['ssh']).split("@")
            payload = self.profile["payload"]
            
            self.ssh = ssh_field[0].split(':')
            
            self.ssh_auth = ssh_field[1].split(':')
            self.proxy = self.profile['proxy'].split(':') if self.profile['proxy'].find(':') != -1  else ''
            self.sni = self.profile['sni']
            
            raw_payload = self.replace_payload(payload)
            
            # sleep 
            split_payload = re.findall(r'\[split\]|\[delay\]|\[instant\]',raw_payload)
            if len(split_payload) != 0:
                    self.payload = raw_payload.split(split_payload[0])
                    self.sleep = self.sleep_dict[split_payload[0]]
            else:
                self.payload = raw_payload
            
            self.connect_to = self.ssh if self.proxy == '' else self.proxy
            self.connect_to[1] = int(self.connect_to[1])
            self.connect_to_ip = (domain_to_ip(self.connect_to[0]),self.connect_to[1])
            
            self.timeout = self.config_json['Settings']['timeout']
            self.recv_buffer_size = self.config_json['Settings']['recv_buffer_size']

            self.regex_status_code = re.compile("^HTTP\/\d.\d\s[0-9]{3}")
        except Exception as er:
            if VERBBOSE: print(traceback.format_exc())
            print_log_error(er.args[0])
        
    
    def listen_sock(self) -> None:
        """
        Create local socket to accept ssh client 
        """
        try:
            self.local_server = socket.create_server(self.local_addr)
            self.local_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.local_server.listen(1)
            print_log(f"Local server listen on: {Fore.GREEN}{self.local_addr[0]}:{self.local_addr[1]}{Fore.WHITE}")
        except Exception as er:
            if VERBBOSE: print_log_error(er.args[1])
            exit(0)
    
    def connect_remote(self) -> None:
        """
        Connect to ssh/proxy
        """
        try:
            addr = self.connect_to[0]
            
            print_log(f"Reconnection retries: {Fore.BLUE}{self.reconn_attemps}{Fore.WHITE}")
            print_log(f"Connect to socket: {Fore.YELLOW}{addr}:{self.connect_to[1]}{Fore.WHITE}")
            
            print_log(f"{Fore.BLUE}{addr}{Fore.WHITE} -> {Fore.YELLOW}{self.connect_to_ip[0]}{Fore.WHITE}")

            self.remote_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.remote_server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
            
            if self.sni != '':
                print_log(f'SNI Handshake to {Fore.GREEN}{self.sni}{Fore.WHITE}')
                context = ssl._create_unverified_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                self.remote_server = context.wrap_socket(self.remote_server,server_hostname=self.sni,do_handshake_on_connect=True)
            
            self.remote_server.connect(tuple(self.connect_to))
            
            if type(self.payload) is list:
                for i in self.payload:
                    self.remote_server.send(i.encode())
                    print_log(f'Payload: {Fore.GREEN}{repr(i)}{Fore.WHITE}')
                    sleep(self.sleep)
            else:
                self.remote_server.send(self.payload.encode())
                print_log(f'Payload: {Fore.GREEN}{repr(self.payload)}{Fore.WHITE}')
        except Exception as er:
            if VERBBOSE: print_log_error(er.args[1])


    def handle_connection(self,conn:tuple) -> None:
        """
        Manage connection data
        """
        try:
            ssh_packet = False
            self.connect_remote()

            inputs = [conn,self.remote_server]
            

            while True:
                read, _ , _ = select.select(inputs,[],inputs)
                for s in read:
                    data = s.recv(self.recv_buffer_size)
                    if data:
                        if s is conn:
                            #print('conn:',data)
                            if b"CONNECT" in data:
                                    
                                    conn.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
                                    continue
                            self.remote_server.sendall(data)
                        
                        elif s is self.remote_server:
                            #print('remote_server:',data)
                            status_code = self.regex_status_code.findall(data.decode("utf-8","ignore"))
                            if len(status_code) != 0:
                                print_log(f"{Fore.YELLOW}{response_code(data)}{Fore.WHITE}")
                                if "200" not in status_code :
                                    print_log("Auto replace response.")
                                    print_log(f"{Fore.BLUE}HTTP/1.1 200 OK{Fore.WHITE}")

                            if b"SSH-2.0-" in data:
                                    ssh_packet = True
                                    ssh_string  = re.findall('^SSH-2.0-.*',data.decode("utf-8","ignore"))[0]
                                    print_log(f"{Fore.GREEN}{ssh_string}{Fore.WHITE}")
                            
                            if ssh_packet: conn.sendall(data)
                    else:
                        self.close_conn(conn)

        except Exception as er:
            pass
    
    def close_conn(self,conn) -> None:
        conn.close()
        self.remote_server.close()
        
    def sshtunnel(self):
        try:
            
            bash = f'sshpass -p "{self.ssh_auth[1]}" ssh  -v -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o  ConnectTimeout={self.timeout} '
            if self.proxy or self.sni != '':
                bash += f' {self.ssh_auth[0]}@{self.ssh[0]} -p {self.ssh[1]} -N -D 1080   -o "ProxyCommand=ncat --proxy-type http --proxy 127.0.0.1:{self.local_addr[1]} %h %p"'
            else:
                bash += f' {self.ssh_auth[0]}@127.0.0.1 -p {self.local_addr[1]} -D 1080 -N'
            
            op = Popen(bash + " ",shell=True,stdout=PIPE, stderr=PIPE,stdin=PIPE)
            self.ssh_pid = op.pid
                    
            info_match = ["kex: algorithm:","kex: host key algorithm:","Server host key:"]
            banner_ = False
            conn = False
            
            if conn != True:
                for l in op.stderr:
                    line = l.decode(errors="ignore").lstrip("debug1:")
                    if any(x in line for x in info_match):

                        print_log(f"{line.strip()}")
                    if "SSH2_MSG_SERVICE_ACCEPT received" in line:
                        banner_ = True 
                        print_log("Server Banner:")
                    elif "Authentications that can continue: publickey,password" not in line and banner_:
                        print_log(line) 
                    elif "Permission denied" in line:
                        print_log(f"{Fore.RED}Username or password are inncorect.{Fore.WHITE}")
                    elif "Authenticated to" in line:
                        print_log(f"{Fore.GREEN}Happy Surfing. :) {Fore.WHITE}")
                        conn = True
                       #start_pinger(self.config_file)
                        multiprocessing.Process(target=start_pinger,args=(self.config_file,)).start()

                    else:
                        banner_ = False


        except KeyboardInterrupt:
            os.kill(self.ssh_pid,SIGKILL)
            exit(130)
        except Exception as er:
            if VERBBOSE:print(traceback.format_exc())
            print_log_error(er)
            os.kill(self.ssh_pid,SIGKILL)
            exit(1)
            self.remote_server.close()
    
    def replace_payload(self,payload:str) -> bytes:
        try:
            new_payload = payload

            content = {
                "[host_port]": f"{self.ssh[0]}:{self.ssh[1]}",
                "[host]": f"{self.ssh[0]}",
                "[port]": f":{self.ssh[1]}",
                "[sni]": f"{self.sni}",
                "[proxy]": '',
                "[ua]": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
                "[cr]": "\r",
                "[lf]": "\n",
                "[crlf]": "\r\n",
            }
            if type(self.proxy) == tuple:
                content["[proxy]"] = f"{self.proxy[0]}:{self.proxy[1]}",
            
            for key in content:
                new_payload = new_payload.replace(key,content[key])
            
        except Exception as er:
            if VERBBOSE: print(traceback.format_exc())
            print_log_error(str(er.args))
        finally:
            return new_payload


def start_pinger(config_file:str="config.json") -> None|int:
    er = False
    count = 0
    sock = socks.socksocket()
    while True:
        try:
            pinger_options = json.loads(open(config_file,"r").read())['Pinger']
            host_port = (pinger_options['host'].split(":")[0],int(pinger_options['host'].split(":")[1]))
            timeout_ = pinger_options['timeout']

            sock.settimeout(timeout_)

            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 1080)

            socket.socket = socks.socksocket
            data_ping = bool(pinger_options['data_ping'])
            
            sleep(0.4)
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_)
            s.connect(host_port)
            headers = f'GET / HTTP/1.1\r\nHost: {host_port}\r\nUser-Agent: pyinjector/@M1001-BYTE\r\n\r\n'
            s.sendall(headers.encode())
            s.recv(4096)
            print_log(f"Ping {Fore.GREEN}200 OK{Fore.WHITE} ")
            count += 1
            if count >= 100:
                count = 0
                os.system("clear")
    
        except Exception as error:
            if "timed out" in str(error):
                print_log_error(f"Ping timeout.")
                if os.geteuid() == 0 and data_ping:
                    airplane()
                break
    return 0
                
        

def airplane() -> None:
    try:
        cmd = "settings put global airplane_mode_on {} &>/dev/null\n am broadcast -a android.intent.action.AIRPLANE_MODE --ez state {}&>/dev/null\n "
        os.system(cmd.format("1","true"))
        print_log(f"{Fore.YELLOW}Turn on airplane{Fore.WHITE}")

        os.system(cmd.format("0","false"))
        print_log(f"{Fore.YELLOW}Turn off airplane{Fore.WHITE}")
    except Exception as er:
        if VERBBOSE: print(traceback.format_exc())
        print_log_error(str(er))
        exit(0)

def get_ip() -> str:
    try:
        r = requests.get("http://ipinfo.io/ip",proxies={"http": "socks5://localhost:1080"},timeout=3)
        country = requests.get("http://ipinfo.io/country",proxies={"http": "socks5://localhost:1080"},timeout=3).text.rstrip()
        ip = f"{r.text} ({country})"
    except Exception as er:
        ip = "Proxy error."
    finally:
        return ip

def print_log_error(msg:str=None,signal=None,frame=None):
    if msg != None and signal == None:
        print(f"[{strftime('%H:%M:%S')}] {Fore.RED}{msg}{Fore.WHITE}")
    else:
        print(f"[{strftime('%H:%M:%S')}] {Fore.RED}Exiting...{Fore.WHITE}")
        exit(130)

response_code = lambda string : string.decode("utf-8","ignore").split("\r\n")[0]
domain_to_ip = lambda domain : socket.gethostbyname(domain)
print_log = lambda msg : print(f"[{strftime('%H:%M:%S')}] {msg}")

if __name__ == "__main__":
    VERBBOSE = True
    signal(SIGINT, print_log_error)
    os.system("clear")
    injector()
