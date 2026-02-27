import socket
from IPy import IP

def get_banner(sock): #function that gets th banner values running in a port 
    return sock.recv(1024) #actual function that recieves (recv) the banner

def check_ip(ipaddress):
    try:
        IP(ipaddress) #checks if the given input is ip or not (gives ValueError if not ip)  
        return ipaddress 
    except ValueError: 
        return socket.gethostbyname(ipaddress) #convert domain name to ip

def port_scan(ipaddress,port) :   #defined function
    try:
        sock=socket.socket() #to define a sock object that performs the library commands
        #can use anyname instead of sock
        sock.settimeout(0.0001)  #gives time to scan port correctly
        sock.connect((ipaddress,port))  #tries to connect to given ipaddress or port
        try:

            banner = get_banner(sock) # calls get_banner function
            print("[+] PORT "+ str(port)+ " IS OPEN")
            print(banner.decode().strip('\n')) #banner is the banner of what process is running, we just used .decode() to rmove excess data written with banner as it is encoded and need to be decoded before .strip() '\n' means strip line after \n
            print('\n')
        except:
            print("[+] PORT "+ str(port)+ " IS OPEN")

        #returns true nd execute try: if port connects successfully and it also means the port is ready to connect
    except:
        #print(f"[-] PORT {port} IS CLOSED") #if sock.connect( is unable to connect to given port)
        pass

def port_scan_automation(ipaddress,port_num):
    ipaddress=ipaddress.strip(' ') #removes any extra spaces
    converted_ip=check_ip(ipaddress) #converts domain to ip (func call)
    print(f"\n[+] SCANNING TARGET {converted_ip}")
    for port in range(1,port_num) : #for loop to scan desired ports
        port_scan(converted_ip,port)


      
if __name__ == "__main__":

    print("enter multiple targets to scan ports (domain or ip) WITH " , "")
    ipaddress=input("ENTER TARGET ( domain(www.xxx.com) or ip ) [+] ") #anything domain or iP
    port_num=int(input("enter the ports you want to scan (eg. 500- first 500 to be scanned)"))

    if ',' in ipaddress: #if user enters multiple targets separated by comma
        for ipaddress in ipaddress.split(','): #splits the input at comma and scans each target and uses a for loop to scan each target with variable ipaddress
            port_scan_automation(ipaddress,port_num)
    else:
        port_scan_automation(ipaddress,port_num)
        
