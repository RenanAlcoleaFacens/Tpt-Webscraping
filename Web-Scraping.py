'''
from fileinput import filename
from math import fabs
from re import A
from attr import attrs
from numpy import empty
from datetime import datetime
import pandas as pd
import os
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

#Validar email
padrao = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
while True:
    email_informado = input("Digite um e-mail válido para receber as CVEs encontradas: ")
    if (re.search(padrao,email_informado)) :
        print("Email válido")
        break
'''

#software = input('Digite qual a vulnerabilidade que gostaria de procurar: ')
#startDate_input = input('Informe qual a data de Início: ')
#startDate_input = '02/01/2022'
#endDate_input = input('Informe qual a data Final: ')
#endDate_input = '02/07/2022'
#email_informato = input("Digite um e-mail válido para receber as CVEs encontradas: ")

from ssl import AlertDescription
import pandas as pd
from bs4 import BeautifulSoup
from time import sleep
from attr import attrs
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from tiger_pass import senha
from funcoes import *
from flask import Flask, render_template, flash
from flask import request
from datetime import datetime
import pyautogui as pag

app = Flask(__name__)

@app.route("/")
def homepage():
    return render_template("homepage.html")

@app.route("/pesquisar", methods=['POST'])
def pesquisar():
    error = None
    try:

        software_flask = request.form['software']
        email_flask = request.form['email']
        data_inicio_flask = request.form['dataInicio']
        data_termino_flask = request.form['dataTermino']        

        datas = validador_datas(data_inicio_flask, data_termino_flask)
        startDate_input = datas[0]
        endDate_input = datas[1]    

        #Parâmetros de Opções do Webdriver do Chrome 
        options = Options()
        options.add_argument('window-size=800,1000')
        options.add_argument('--headless')

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
        software_flask =software_flask.upper()
        keywords = navegador.find_element(By.ID,'Keywords')
        keywords.send_keys(software_flask)       

        #Definindo Range de Início da busca
        startDate = navegador.find_element(By.ID,'published-start-date')        
        startDate.send_keys(startDate_input)

        #Definindo Range Final da busca
        endDate = navegador.find_element(By.ID,'published-end-date')        
        endDate.send_keys(endDate_input)

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
                    
                    listResult = [software_flask,cveInput,descInput,severity_Input,reference_Input,kasc_Input,publish_Input,details_Input]        
                    listFull.append(listResult)           
                    navegador.back() 
            
            if j < pages-1 and qtd_result >20:
                nextBtn = navegador.find_element(By.LINK_TEXT,'>')
                nextBtn.click()
            

        ########################################################################################################################################################

        #Envio do Email
        envia_email(listFull,email_flask)
    except:
        #return render_template("homepage.html", error = error)
        pag.alert(text="Por favor, preencha novamente os campos.", title="Erro" )
        return render_template("homepage.html")

#colocar o site no ar
if __name__ == "__main__":
    app.secret_key = 'super secret key'
    app.run(debug=True)



