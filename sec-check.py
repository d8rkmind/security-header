import requests
from sys import argv as arg
from prettytable import PrettyTable
from urllib.parse import urlparse
from socket import gethostbyname


G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # end 


def indicator():
    x = arg[1]
    k = urlparse(x).netloc
    list1=[]
    list2=[]
    searchlist=["Date","Server","Content-Type","Cache-Control","X-TEC-API-VERSION","X-TEC-API-ROOT","X-TEC-API-ORIGIN","Transfer-Encoding","Pragma"]
    headerlist=["X-Frame-Options","Content-Security-Policy","X-XSS-Protection","X-Content-Type-Options","Strict-Transport-Security","P3P","X-Powered-By","X-Download-Options","Content-Disposition","Public-Key-Pins","Expect-CT","Cross-Origin-Resource-Policy","Cross-Origin-Opener-Policy","Access-Control-Allow-Origin","Access-Control-Allow-Credentials","Cross-Origin-Embedder-Policy","Feature-Policy","X-DNS-Prefetch-Control","Referrer-Policy","X-Permitted-Cross-Domain-Policies"]
    #template={"X-Frame-Options":"Clickjacking in iframe is possible ","Content-Security-Policy":"Few types of attacks(mainly injections) are possible check in internet","X-XSS-Protection":"the Risk of Cross Site Scripting (XSS) Attacks","X-Content-Type-Options":"Inferring the Response MIME Type is possible","X-Powered-By":" 'Powered by' is hidden by respective owners","X-Download-Options":"The malicious codes will be prevented from running on the website","Content-Disposition":"Content disposition is enabled cookie theft not possible within website(just one example)","Strict-Transport-Security":"No mechanism to force browser to use secure connection","Public-Key-Pins":"Missing secure ssl handshake or is replaced by Except-CT","Expect-CT":"Its a response-type header that prevents the usage of wrongly issued certificates for a site"}
    response=requests.get(x,params=None, headers=None, cookies=None, auth=None, timeout=None).headers
    ip = gethostbyname(k)
    t = PrettyTable(["Raw Headers"," informations"])
    t.add_row([B+"IP",ip+W])
    for i in searchlist:
        if i in response:
            t.add_row([B+i,response[i]+W])
    print(t)
    if "Set-Cookie" in response:
        print(Y+f'''
Set-Cookie:

{response["Set-Cookie"]}
       \n '''+W)
    
    for i in headerlist:
        if i in response:
            list1.append(i)

        else:
            list2.append(i)
    
    t = PrettyTable(['Headers', 'status'])
    for i in list1:
        k = G+i+W
        t.add_row([k,G+'✔'+W])

    for i in list2:
        k = R+i+W
        t.add_row([k,R+'✘'+W])

    print(t)
    #for i in list2:
     #   print("\n"+Y+i+": \n\t"+template[i]+W )


if __name__ == "__main__":
    
    try:
        print("\n")
        indicator()
    except IndexError:
        print(''' 
        Missing domain, 
            Usage :
                python3 sec-check.py  (http/https):// "domain"
        ''')
