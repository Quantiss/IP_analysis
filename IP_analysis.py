import requests
import json

def abuse(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip
    }

    headers = {
        'Accept': 'application/json',
        'Key': '' #set the API key
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)
    data = decodedResponse['data']
    return data

def main():
    print('''
         ___  ________        ________  ________   ________  ___           ___    ___ ________  ___  ________      
        |\  \|\   __  \      |\   __  \|\   ___  \|\   __  \|\  \         |\  \  /  /|\   ____\|\  \|\   ____\     
        \ \  \ \  \|\  \     \ \  \|\  \ \  \\\ \  \ \  \|\  \ \  \        \ \  \/  / | \  \___|\ \  \ \  \___|_    
         \ \  \ \   ____\     \ \   __  \ \  \\\ \  \ \   __  \ \  \        \ \    / / \ \_____  \ \  \ \_____  \   
          \ \  \ \  \___|      \ \  \ \  \ \  \\\ \  \ \  \ \  \ \  \____    \/  /  /   \|____|\  \ \  \|____|\  \  
           \ \__\ \__\          \ \__\ \__\ \__\\\ \__\ \__\ \__\ \_______\__/  / /       ____\_\  \ \__\____\_\  \ 
            \|__|\|__|           \|__|\|__|\|__| \|__|\|__|\|__|\|_______|\___/ /       |\_________\|__|\_________\\
                                                                          \|___|/        \|_________|   \|_________|
        ''')
    ip = input("[+] Please enter the IP address: ")
    print("[+] The output is located in output.txt")
    data = abuse(ip)
    IP = data['ipAddress']
    abuseR = data['abuseConfidenceScore']
    domain = data['domain']
    whitelisted = data['isWhitelisted']
    lastreport = data['lastReportedAt']
    totalReports = data['totalReports']
    isp = data['isp']
    usage = data['usageType']
    f = open('output', 'w+')
    f.write('''
     ___  ________        ________  ________   ________  ___           ___    ___ ________  ___  ________      
    |\  \|\   __  \      |\   __  \|\   ___  \|\   __  \|\  \         |\  \  /  /|\   ____\|\  \|\   ____\     
    \ \  \ \  \|\  \     \ \  \|\  \ \  \\\ \  \ \  \|\  \ \  \        \ \  \/  / | \  \___|\ \  \ \  \___|_    
     \ \  \ \   ____\     \ \   __  \ \  \\\ \  \ \   __  \ \  \        \ \    / / \ \_____  \ \  \ \_____  \   
      \ \  \ \  \___|      \ \  \ \  \ \  \\\ \  \ \  \ \  \ \  \____    \/  /  /   \|____|\  \ \  \|____|\  \  
       \ \__\ \__\          \ \__\ \__\ \__\\\ \__\ \__\ \__\ \_______\__/  / /       ____\_\  \ \__\____\_\  \ 
        \|__|\|__|           \|__|\|__|\|__| \|__|\|__|\|__|\|_______|\___/ /       |\_________\|__|\_________\\
                                                                      \|___|/        \|_________|   \|_________|
    ''')
    f.write('''
    [+] IP : {}
    [+] ISP : {}
    [+] Domain Name : {}
    [+] Usage : {}
    [+] Abuse Rating : {}
    [+] Whitelist status : {}
    [+] Last report : {}
    [+] Total reports :  {}
    '''.format(IP,isp,domain,usage,abuseR,whitelisted,lastreport,totalReports))

if __name__ == '__main__':
    main()
