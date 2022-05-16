from fileinput import filename
from math import fabs
from re import A
from attr import attrs
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
from selenium.webdriver.common.by import By

## Função que seleciona os hyperlinks na página resultado ##
# Precisa receber o argumento em BS (Beautiful Soup)
def selects_hyperlinks(pagina_resultadoCVE_BS,hyperlink_RefExt=0,i=0,counter=0):
    
    print("Entrou na função")
    if i == 0:
        print("passou no i 0")
        hyperlink_RefExt=[]
        hyperlink_table = pagina_resultadoCVE_BS.find('table',class_='table table-striped table-condensed table-bordered detail-table')
        #Separando a tabela que contém os links e quantidade de tags que contém links:
        qty = hyperlink_table.find_all('a')
        print(qty)

    #Executando o comando de separar o link do corpo html através do get_text(), repetindo a qtd de vezes necessária:    
    hyperlink_RefExt.append(site.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i)}).get_text())
    i=i+1

    if i == counter:
        print(I,"i")
        print("Saindo da função")
        return hyperlink_RefExt
    else:
        return selects_hyperlinks(pagina_resultadoCVE_BS,hyperlink_RefExt,i,counter)


print("Iniciando programa.")

options = Options()
#Inicia o o chrome com janela em tamanho reduzido:
options.add_argument('window-size=800,1200')

#Abre Google Chrome
navegador = webdriver.Chrome(options=options)
navegador.get('https://nvd.nist.gov/vuln/search')

#O programa espera 2 segundos (sleep) para que o site carregue.
sleep(2)

site = BeautifulSoup(navegador.page_source, 'html.parser')

#### Parametros de Pesquisa ####

#Encontra a caixa de pesquisa e clica no botão de pesquisa avançada.
caixa_advanced = navegador.find_element(By.ID, 'SearchTypeAdvanced')
caixa_advanced.click()

#Recebe do usuário o tipo de CVE
cve_input = navegador.find_element(By.ID, "Keywords")
#cve_informado = input("Digite a CVE desejada para pesquisa: ")
cve_informado = 'apache'
cve_input.send_keys(cve_informado)

#Recebe do usuário a data de inicio da pesquisa
#MELHORIA: deixar esta seção no formato dd/mm/yyyy E criar validação de dados
data_inicio = navegador.find_element(By.ID, "published-start-date")
#data_informada_inicio = input("Informe a data de início [mm/dd/yyyy]: ")
data_informada_inicio = '04/01/2022'
data_inicio.send_keys(data_informada_inicio)

#Recebe do usuário a data de fim da pesquisa
data_fim = navegador.find_element(By.ID, "published-end-date")
#data_informada_fim = input("Informe a data de término [mm/dd/yyyy]: ")
data_informada_fim = '05/01/2022'
data_fim.send_keys(data_informada_fim)

#Email para receber relatório
#email_informado = input("Digite o e-mail para serem enviadas as CVEs encontradas: ")
email_informado = 'leonardo.souza@facens.br'

#Aperta o botão de pesquisa
pesquisar = navegador.find_element(By.ID, "vuln-search-submit")
pesquisar.click()
print("Iniciando pesquisa")

#Aguarda um tempo para carregar a página.
sleep(2)

#### Pesquisa executada ####

#Neste ponto, outra página é aberta. Aplicar Beautiful Soup novamente, porque a página mudou.
#A página atual é a exibição da lista de resultados para parâmetros pesquisados.

page_content = navegador.page_source

site = BeautifulSoup(page_content, 'html.parser')
dados_scraping = []
print("Página com lista de resultados acessada!")

#Identifica o inicio e fim de contagem para executar loop:
#inicio
inicio_contagem = site.find('strong', attrs={'data-testid': 'vuln-displaying-count-from'}).text
inicio_contagem = int(inicio_contagem) - 1

#fim
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

    severity = cves.find('a', attrs={'data-testid': 'vuln-cvss3-link-' + str(numero)})

    if (severity):
        severity = cves.find('a', attrs={'data-testid': 'vuln-cvss3-link-' + str(numero)})
    else:
        severity = " "

    # Clicou em cima da CVE e vai nos detalhes da CVE:
    segunda_pag = navegador.find_element(by=By.LINK_TEXT, value=titulo.text)
    segunda_pag.click()

    sleep(5)
    #Itens da página da CVE específica
    #navegador_url = navegador.current_url
    #navegador_url = (navegador.current_url).page_source
    #site_page_2 = BeautifulSoup(page_content, 'html.parser')
    pagina_CVE = BeautifulSoup(navegador.page_source, 'html.parser')
    
    #Léo: creio que na linha acima deva passar a var "navegador_url"
    #Anotação: site_page_2 passa a pagina errada, está passando a página de lista de resultados.
    print(pagina_CVE)
    print("Página de resultados acessada e parseada")
    hyperlink=0    
    selects_hyperlinks(pagina_CVE)

    #known = navegador.find_element('b', attrs={'data-testid': 'vuln-software-cpe-1-0-0'})
    known = ""


    navegador.back()

    #sleep(5000)

    numero = numero + 1

    #dados_scraping.append([cve_informado,titulo.text, descricao.text ,severity,hyperlink['href'],known, data.text,link['href']])
    dados_scraping.append([cve_informado,titulo.text, descricao.text ,"", hyperlink,"", data.text,link['href']])



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