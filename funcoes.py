from datetime import datetime
from datetime import date
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.message import EmailMessage
from email import encoders
import smtplib
from time import strftime
import pandas as pd
from tiger_pass import senha    

def validador_datas(dataBR1,dataBR2):
    
    #dataBR1 = '01/02/2022'
    #dataBR2 = '10/02/2022'

    # Data Inicial
    d1 = datetime.strptime(dataBR1, '%Y-%m-%d')

    # Data Final
    d2 = datetime.strptime(dataBR2, '%Y-%m-%d')

    #Calcula se o período informado é maior que 180 dias:
    if abs((d2 - d1).days)>180:        
        print("O período pesquisado não pode ser maior que 180 dias!")
        return
    else:
        dataUS1 = dataBR1[5:7]+ "/" + dataBR1[8:] + "/" + dataBR1[0:4]
        dataUS2 = dataBR2[5:7]+ "/" + dataBR2[8:] + "/" + dataBR2[0:4]
        dataUS = [dataUS1,dataUS2]
    return dataUS

#Função que retorna a Severity do CVE (4º Item da lista)
def busca_severity(siteSP):    
    if siteSP.find('a',attrs={'id': 'Cvss3NistCalculatorAnchor'}):
        severity_Input = siteSP.find('a',attrs={'id': 'Cvss3NistCalculatorAnchor'}).getText() 
        severity_Input = str(severity_Input).split(" ")[0]   
        severity_Input = float(severity_Input)
    elif siteSP.find('a',attrs={'id': 'Cvss3CnaCalculatorAnchor'}):
        #severity_Input = siteSP.find(attrs={'data-testid':'vuln-cvss3-cna-panel-score'}).getText()
        severity_Input = siteSP.find('a',attrs={'id': 'Cvss3CnaCalculatorAnchor'}).getText() 
        severity_Input = str(severity_Input).split(" ")[0]   
        severity_Input = float(severity_Input)  
    else:
        severity_Input = 'N/A'
    return severity_Input 

#Função que retorna os Hyperlinks do CVE (5º Item da lista)
def busca_links(siteSP,links_impresso = 0,i=0,counter=0,aux=0):

    if i == 0:
        links_impresso = ""
        #Separando a tabela que contém os links e quantidade de tags que contém links:
        counter = len(siteSP.find('table',class_='table table-striped table-condensed table-bordered detail-table').find_all('a'))
        if siteSP.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i)}):
            links_impresso = str(siteSP.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i)}).get_text())
            aux = 1
        else:
            links_impresso = str(siteSP.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i+1)}).get_text())
            aux = 2

    #Executando o comando de separar o link do corpo html através do get_text(), repetindo a qtd de vezes necessária:
    else:
        if aux==1:
            links_impresso = links_impresso + ', \n' + str(siteSP.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i)}).get_text())
        if aux==2:
            links_impresso = links_impresso + ', \n' + str(siteSP.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i+1)}).get_text())
            

    i=i+1

    if i == counter:
        return links_impresso 
    else:
        return busca_links(siteSP,links_impresso,i,counter,aux)

#Função que retorna os Known Affected Software Configurations (6º Item da lista)

def busca_kasc(siteSP,KASC=0,i=0,counter=0):
    
    if i == 0:
        KASC = ""
        #Separando a tabela que contém os links e quantidade de tags que contém links:
        counter = len(siteSP.find_all(text="CPE Configuration"))
        print ('passando primeira vez', counter)

        #Executando o comando de separar o link do corpo html através do get_text(), repetindo a qtd de vezes necessária:        
        if siteSP.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}):
            KASC = siteSP.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}).get_text()[2:]
        elif siteSP.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}):
            KASC = siteSP.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}).get_text()[2:]
        else:
            i=i-1
            KASC = 'N/A'
    else:   
        if siteSP.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}):
            KASC = KASC + ', \n' + siteSP.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}).get_text()[2:]
        elif siteSP.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}):
            KASC = KASC + ', \n' + siteSP.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}).get_text()[2:]
    i=i+1
    if i == counter:
        return KASC        
    else:
        return busca_kasc(siteSP,KASC,i,counter)

#Função que retorna a Data de Publicação da CVE (7º Item da lista)
def busca_publish(siteSP):     
    return siteSP.find('span',attrs={'data-testid':'vuln-published-on'}).getText()

#Função que retorna o Link de Detalhes da CVE (8º Item da lista)
def busca_details(cveInput):
    return 'https://nvd.nist.gov/vuln/detail/'+cveInput

def envia_email(listFull,email_flask):

    #Montando a estrutura do Dataframe com Pandas
    df = pd.DataFrame(data = listFull,columns=['Software/Sistema','CVE','Current Description', 'Severity',
    'References to Advisories, Solutions, and Tools','Known Affected Softwares Configuration','NVD Published Date','Link para o respectivo CVE'])

    #Gerando o arquivo do Excel a partir do Dataframe
    df.to_excel('Vulnerabilidades_CVE.xlsx',sheet_name='Vulnerabilidades - CVE',header=True,index=False)

    tabela=df.copy()
    segundo_excel = pd.DataFrame(tabela, columns=['Software/Sistema','CVE','Severity','NVD Published Date','Link para o respectivo CVE'])
    segundo_excel.to_excel('WebScrap.xlsx', index=False)
    tabela = pd.read_excel("WebScrap.xlsx")

    #Retira valores menores que 7 da tabela
    tabela.loc[tabela["Severity"]<7 or tabela["Severity"] == 'N/A',['Software/Sistema','CVE','Severity','NVD Published Date','Link para o respectivo CVE']]= None
    tabela = pd.DataFrame(tabela.dropna(how="any"))
    tabela_html=tabela.to_html()

    #Configurar e-mail e senha
    EMAIL_ADDRESS = 'timetigerpython@gmail.com'
    EMAIL_PASSWORD = senha
    fromaddr = EMAIL_ADDRESS
    toaddr = email_flask
    today = (datetime.today()).strftime('%d/%m/%Y')
    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['Subject'] = ("Vulnerabilidades Críticas, Data: ")+today
    body = (f"Segue na tabela abaixo as vulnerabilidades classificadas como altas:\n\n{tabela_html}")
    msg.attach(MIMEText(body, 'html'))
    filename = "Vulnerabilidades_CVE.xlsx"
    attachment = open("Vulnerabilidades_CVE.xlsx", "rb")
    p = MIMEBase('application', 'octet-stream')
    p.set_payload((attachment).read())
    encoders.encode_base64(p)
    p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
    msg.attach(p)
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login(fromaddr, senha)
    text = msg.as_string()
    s.sendmail(fromaddr, toaddr, text)
    s.quit()