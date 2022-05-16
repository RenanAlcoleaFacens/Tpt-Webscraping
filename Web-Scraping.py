from fileinput import filename
from math import fabs
from re import A
from attr import attrs
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from time import sleep
import pandas as pd
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.message import EmailMessage
from email import encoders
from tiger_pass import senha
from selenium.webdriver.common.by import By
from datetime import date
import re
from openpyxl import workbook,load_workbook

options = Options()
options.add_argument('window-size=800,1200')
#options.add_argument("--headless")

home = ("https://nvd.nist.gov/")
navegador = webdriver.Chrome(options=options)
navegador.get('https://nvd.nist.gov/vuln/search')

sleep(2)

site = BeautifulSoup(navegador.page_source, 'html.parser')
caixa_advanced = navegador.find_element(By.ID, 'SearchTypeAdvanced')
caixa_advanced.click()

sleep(2)

cve_input = navegador.find_element(By.ID, "Keywords")
cve_informado = input("Digite a CVE desejada para pesquisa: ")
cve_informado=cve_informado.upper()
cve_input.send_keys(cve_informado)

data_inicio = navegador.find_element(By.ID, "published-start-date")
data_informada_inicio = input("Informe a data de início [mm/dd/yyyy]: ")
data_inicio.send_keys(data_informada_inicio)
data_fim = navegador.find_element(By.ID, "published-end-date")
data_informada_fim = input("Informe a data de término [mm/dd/yyyy]: ")
data_fim.send_keys(data_informada_fim)

#Validar email
padrao = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
while True:
    email_informado = input("Digite um e-mail válido para receber as CVEs encontradas: ")
    if (re.search(padrao,email_informado)) :
        print("Email válido")
        break
    
pesquisar = navegador.find_element(By.ID, "vuln-search-submit")
pesquisar.click()

sleep(2)

page_content = navegador.page_source
site = BeautifulSoup(page_content, 'html.parser')
dados_scraping = []
inicio_contagem = site.find('strong', attrs={'data-testid': 'vuln-displaying-count-from'}).text
inicio_contagem = int(inicio_contagem) - 1
fim_contagem = site.find('strong', attrs={'data-testid': 'vuln-displaying-count-through'}).text
fim_contagem = int(fim_contagem) - 1
numero = 0

print("Iniciando a pesquisa...")

while numero <= fim_contagem:

    
    cves = site.find('tr', attrs={'data-testid': 'vuln-row-' + str(numero)})
    severity = cves.find('a', attrs={'data-testid': 'vuln-cvss3-link-' + str(numero)})
    if (severity):
        severity = (severity.text).split(" ")[0]
        #severity = float(severity)

    cves = site.find('tr', attrs={'data-testid': 'vuln-row-' + str(numero)})
    titulo = cves.find('a', attrs={'data-testid': 'vuln-detail-link-' + str(numero)})
    link = cves.find('a', attrs={'data-testid': 'vuln-detail-link-' + str(numero)})
    descricao = cves.find('p', attrs={'data-testid': 'vuln-summary-' + str(numero)})
    data = cves.find('span', attrs={'data-testid': 'vuln-published-on-' + str(numero)})
    link_completo = home+link['href']
    


    # Clicou em cima da CVE e vai nos detalhes da CVE
    segunda_pag = navegador.find_element(by=By.LINK_TEXT, value=titulo.text)
    segunda_pag.click()

    #Itens da página da CVE específica
    navegador_url = navegador.current_url
    site_page_2 = BeautifulSoup(page_content, 'html.parser')
    hyperlink = site_page_2.find('tr', attrs={'data-testid': 'vuln-hyperlinks-row-0'})


    
    #known = navegador.find_element('b', attrs={'data-testid': 'vuln-software-cpe-1-0-0'})
    #known = ""
    navegador.back()
    
    numero= numero+1

    dados_scraping.append([cve_informado,titulo.text, descricao.text ,severity, hyperlink,"", data.text,link_completo])

dados = pd.DataFrame(dados_scraping, columns=['Software/Sistema','CVE','Current Description','Severity','References to Advisories,Solutions, and Tools','Know Affected Software Configurations','NVD Published Date','Link para o respectivo CVE'])
dados.to_excel('webScraping.xlsx', index=False)

print("Pesquisa concluída!\nEstamos enviando as informações para o email informado")

#Tabela para o Body do email
tabela=dados.copy()
segundo_excell = pd.DataFrame(tabela, columns=['Software/Sistema','CVE','Severity','NVD Published Date','Link para o respectivo CVE'])
segundo_excell.to_excel('webscrap.xlsx', index=False)
tabela = pd.read_excel("webscrap.xlsx")

'''planilha=load_workbook("webscrap.xlsx")
aba_ativa=planilha.active
for celula in aba_ativa["C"]:
    if (celula.value) >=7:
        linha=celula.row
    else:
        continue
planilha.save("webscrap.xlsx", index=False)    '''    

#Configurar e-mail e senha
EMAIL_ADDRESS = 'timetigerpython@gmail.com'
EMAIL_PASSWORD = senha
fromaddr = EMAIL_ADDRESS
toaddr = email_informado
msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = ("Vulnerabilidades Críticas, Data: ")
body = (f"Segue na tabela abaixo as vulnerabilidades classificadas como altas:\n\n{tabela}")
msg.attach(MIMEText(body, 'plain'))
filename = "webScraping.xlsx"
attachment = open("C:\\Users\lenovo\\Documents\\WebScraping\\Desafio Python Web Scraping\\webScraping.xlsx", "rb")
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

