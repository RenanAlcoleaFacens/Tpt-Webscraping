from fileinput import filename
from math import fabs
from re import A
from attr import attrs
from numpy import empty
import requests
from datetime import datetime
import pandas as pd
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.message import EmailMessage
from email import encoders
from bs4 import BeautifulSoup
from time import sleep
from attr import attrs
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from tiger_pass import senha
from funcoes import *
import re
from datetime import date

#software = input('Digite qual a vulnerabilidade que gostaria de procurar: ')
'''software = 'microsoft'
#startDate_input = input('Informe qual a data de Início: ')
startDate_input = '02/01/2022'
#endDate_input = input('Informe qual a data Final: ')
endDate_input = '02/07/2022'''

#Parâmetros de Opções do Webdriver do Chrome 
options = Options()
options.add_argument('window-size=800,1000')
#options.add_argument('--headless')

#Definindo o navegador através do Webdriver e inicializando com parâmetros de um objetos da classe "Option"
navegador = webdriver.Chrome(options=options)
navegador.get('https://nvd.nist.gov/vuln/search')

#Sleep de 2 segundos para renderizar toda a página
sleep(2)

#Seleciona o tipo de Busca como Avançado
advanced = navegador.find_element(By.ID,'SearchTypeAdvanced')
advanced.click()

sleep(2)

#Seleciona a caixa de pesquisa da vulnerabilidade e digita a String passada pelo usuário
keywords = navegador.find_element(By.ID,'Keywords')
software = input("Digite a CVE desejada para pesquisa: ")
software=software.upper()
keywords.send_keys(software)

#Definindo Range de Início da busca
datas=validador_datas()
startDate = navegador.find_element(By.ID,'published-start-date')
startDate_input = input("Informe a data de início [mm/dd/yyyy]: ")
startDate.send_keys(startDate_input)

#Definindo Range Final da busca
endDate = navegador.find_element(By.ID,'published-end-date')
endDate_input= input("Informe a data de término [mm/dd/yyyy]: ")
endDate.send_keys(endDate_input)

#Validar email
padrao = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
while True:
    email_informado = input("Digite um e-mail válido para receber as CVEs encontradas: ")
    if (re.search(padrao,email_informado)) :
        print("Email válido")
        break

#Selecionando o botão de Search
submitBtn = navegador.find_element(By.ID,'vuln-search-submit')
submitBtn.click()

sleep(2)

#Transformando o conteúdo da página no padrão do Beautiful Soup 4
siteFP = BeautifulSoup(navegador.page_source,'html.parser')
tableContent = siteFP.find('table', attrs={'data-testid': 'vuln-results-table'})
headContent =  siteFP.find('div', attrs={'id': 'body-section'})


listFull = []

#Verifica a quantidade de páginas das CVE
qtd_result = int(siteFP.find('strong',attrs={'data-testid':'vuln-matching-records-count'}).getText())
if qtd_result%20 > 0:
    pages = (qtd_result//20)+1
else:
    pages = qtd_result//20

print("Iniciando a pesquisa...")
########################################################################################################################################################
for j in range (pages):    
    newsiteFP = BeautifulSoup(navegador.page_source,'html.parser')
    
    # Calcula a quantidade de itens da página atual
    if qtd_result <= 20:
        fim_contagem = qtd_result
    elif j == pages-1:
        fim_contagem = qtd_result - 20 * j        
    else:
        fim_contagem = 20    
    
    for i in range (fim_contagem):                  
        
        tableContent = newsiteFP.find('table', attrs={'data-testid': 'vuln-results-table'})
        headContent =  newsiteFP.find('div', attrs={'id': 'body-section'})

        #Criação da Lista de CVE e Informações
        listResult =[]
        
        if  headContent.find('strong',attrs={'data-testid': 'vuln-matching-records-count'}).get_text() == '0':
            print('Não existem falhas para este período informado')

        else:
            #Obtendo segundo elemento da Lista final (CVE)
            cveInput = tableContent.find('a',attrs={'data-testid': 'vuln-detail-link-'+str(i)}).getText()

            #Obtendo o terceiro elemento da Lista final (Descrição)
            descInput = tableContent.find('p',attrs={'data-testid': 'vuln-summary-'+str(i)}).getText()

            #Obtendo o quarto elemento da Lista final (Severidade)            
            navegador.get('https://nvd.nist.gov/vuln/detail/'+cveInput)
            sleep(2)
            siteSP = BeautifulSoup(navegador.page_source,'html.parser')
            severity_Input=float(busca_severity(siteSP)) 
            

            #Obtendo o quinto elemento da Lista final (Referências)
            reference_Input = busca_links(siteSP)
            #Obtendo o sexto elemento da Lista final (Knowledge Affected System)
            kasc_Input = busca_kasc(siteSP)  
            #Obtendo o setimo elemento da Lista final (Data de Publicação)
            publish_Input = busca_publish(siteSP)
            #Obtendo o oitavo elemento da Lista final (Link CVE)
            details_Input = busca_details(cveInput)
            
            listResult = [software,cveInput,descInput,severity_Input,reference_Input,kasc_Input,publish_Input,details_Input]        
            listFull.append(listResult)           
            navegador.back() 
    
    if j < pages-1 and qtd_result >20:
        nextBtn = navegador.find_element(By.LINK_TEXT,'>')
        nextBtn.click()
    

########################################################################################################################################################

#Montando a estrutura do Dataframe com Pandas
df = pd.DataFrame(data = listFull,columns=['Software/Sistema','CVE','Current Description', 'Severity',
'References to Advisories, Solutions, and Tools','Known Affected Softwares Configuration','NVD Published Date','Link para o respectivo CVE'])

#Gerando o arquivo do Excel a partir do Dataframe
df.to_excel('Relatório de Vulnerabilidades - CVE.xlsx',sheet_name='Vulnerabilidades - CVE',header=True,index=False)

print("Pesquisa concluída!\nEstamos enviando as informações para o email informado")

#Tabela para o Body do email
tabela=df.copy()
segundo_excell = pd.DataFrame(tabela, columns=['Software/Sistema','CVE','Severity','NVD Published Date','Link para o respectivo CVE'])
segundo_excell.to_excel('webscrap.xlsx', index=False)
tabela = pd.read_excel("webscrap.xlsx")

#Retira valores menores que 7 da tabela
tabela.loc[tabela["Severity"]<7 ,['Software/Sistema','CVE','Severity','NVD Published Date','Link para o respectivo CVE']]= None
tabela = pd.DataFrame(tabela.dropna(how="any"))


#Configurar e-mail e senha
EMAIL_ADDRESS = 'timetigerpython@gmail.com'
EMAIL_PASSWORD = senha
fromaddr = EMAIL_ADDRESS
toaddr = email_informado
#today=date.today()
msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = ("Vulnerabilidades Críticas, Data: ")
body = (f"Segue na tabela abaixo as vulnerabilidades classificadas como altas:\n\n{tabela}")
msg.attach(MIMEText(body, 'plain'))
filename = "Relatório de Vulnerabilidades - CVE.xlsx"
attachment = open("C:\\Users\\lenovo\\Documents\\WebScraping\\Relatório de Vulnerabilidades - CVE.xlsx", "rb")
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



