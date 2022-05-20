
from lib2to3.pgen2 import driver
import os
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

        # Recebe a Data da página HTML e converte no formato do site Nist
        datas = validador_datas(data_inicio_flask, data_termino_flask)
        startDate_input = datas[0]
        endDate_input = datas[1]    

        #Parâmetros de Opções do Webdriver do Chrome 
        chrome_options = webdriver.ChromeOptions()
        chrome_options.binary_location = os.environ.get('GOOGLE_CHROME_BIN')
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--no-sandbox')
        driver = webdriver.Chrome(executable_path=os.environ.get('CHROMEDRIVER_PATH'), chrome_options=chrome_options)

        #Definindo o navegador através do Webdriver e inicializando com parâmetros de um objetos da classe "Option"
        driver.get('https://nvd.nist.gov/vuln/search')

        #Sleep de 2 segundos para renderizar toda a página
        sleep(2)

        #Seleciona o tipo de Busca como Avançado
        advanced = driver.find_element(By.ID,'SearchTypeAdvanced')
        advanced.click()

        sleep(2)

        #Seleciona a caixa de pesquisa da vulnerabilidade e digita a String passada pelo usuário
        software_flask =software_flask.upper()
        keywords = driver.find_element(By.ID,'Keywords')
        keywords.send_keys(software_flask)       

        #Definindo Range de Início da busca
        startDate = driver.find_element(By.ID,'published-start-date')        
        startDate.send_keys(startDate_input)

        #Definindo Range Final da busca
        endDate = driver.find_element(By.ID,'published-end-date')        
        endDate.send_keys(endDate_input)

        #Selecionando o botão de Search
        submitBtn = driver.find_element(By.ID,'vuln-search-submit')
        submitBtn.click()

        sleep(2)

        #Transformando o conteúdo da página no padrão do Beautiful Soup 4
        siteFP = BeautifulSoup(driver.page_source,'html.parser')
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

            newsiteFP = BeautifulSoup(driver.page_source,'html.parser')
            
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
                    driver.get('https://nvd.nist.gov/vuln/detail/'+cveInput)
                    sleep(2)
                    siteSP = BeautifulSoup(driver.page_source,'html.parser')
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
                    driver.back() 
            
            if j < pages-1 and qtd_result >20:
                nextBtn = driver.find_element(By.LINK_TEXT,'>')
                nextBtn.click()
            

        ########################################################################################################################################################

        #Envio do Email
        envia_email(listFull,email_flask)
        
        return render_template("success.html")
    except:
        #return render_template("homepage.html", error = error)
        return render_template("homepage.html")

#colocar o site no ar
if __name__ == "__main__":
    app.secret_key = 'super secret key'
    app.run()



