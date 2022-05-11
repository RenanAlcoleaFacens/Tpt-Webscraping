from fileinput import filename
from math import fabs
import requests
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




options = Options()
options.add_argument('window-size=800,1200')

navegador = webdriver.Chrome(options=options)
navegador.get('https://nvd.nist.gov/vuln/search')

sleep(2)

site = BeautifulSoup(navegador.page_source, 'html.parser')

caixa_advanced = navegador.find_element_by_id('SearchTypeAdvanced')
caixa_advanced.click()

cve_input = navegador.find_element_by_id("Keywords")
cve_informado = input("Digite a CVE desejada para pesquisa: ")
cve_input.send_keys(cve_informado)

data_inicio = navegador.find_element_by_id("published-start-date")
data_informada_inicio = input("Informe a data de início [mm/dd/yyyy]: ")
data_inicio.send_keys(data_informada_inicio)


data_fim = navegador.find_element_by_id("published-end-date")
data_informada_fim = input("Informe a data de término [mm/dd/yyyy]: ")
data_fim.send_keys(data_informada_fim)

email_informado = input("Digite o e-mail para serem enviadas as CVEs encontradas: ")


pesquisar = navegador.find_element_by_id("vuln-search-submit")
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
while numero <= fim_contagem:

    numero_string = str(numero)
    cves = site.find('tr', attrs={'data-testid': 'vuln-row-' + str(numero)})
    lista = []
    lista_cves = lista.append(cves)

    titulo = cves.find('a', attrs={'data-testid': 'vuln-detail-link-' + str(numero)})

    link = cves.find('a', attrs={'data-testid': 'vuln-detail-link-' + str(numero)})

    descricao = cves.find('p', attrs={'data-testid': 'vuln-summary-' + str(numero)})

    data = cves.find('span', attrs={'data-testid': 'vuln-published-on-' + str(numero)})

    if (severity):

        severity = cves.find('a', attrs={'data-testid': 'vuln-cvss3-link-' + str(numero)})
    else:
        severity = " "

    segunda_pag = navegador.find('a', attrs={'data-testid': 'vuln-detail-link-' + str(numero)})
    segunda_pag.click()
    
    hyperlink = cves.find('a', attrs={'class': 'external' + str(numero)})

    known = cves.find('b', attrs={'data-testid': 'vuln-software-cpe-1-0-0'})

    navegador.back()

    numero = numero + 1

    dados_scraping.append([cve_informado,titulo.text, descricao.text ,severity,hyperlink['href'],known, data.text,link['href']])

driver.back()

dados = pd.DataFrame(dados_scraping, columns=['Software/Sistema','CVE','Current Description','Severity','References to Advisories,Solutions, and Tools','Know Affected Software Configurations','NVD Published Date','Link para o respectivo CVE'])
dados.to_excel('webScraping.xlsx', index=False)

#Configurar e-mail e senha
EMAIL_ADDRESS = 'timetigerpython@gmail.com'
EMAIL_PASSWORD = senha

fromaddr = EMAIL_ADDRESS
toaddr = email_informado

msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = "CVEs encontradas"
body = "Segue em anexo as CVEs encontradas na pesquisa"
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


   

#sleep(5000)


 



       