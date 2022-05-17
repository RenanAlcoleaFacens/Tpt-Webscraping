import pandas as pd
from bs4 import BeautifulSoup
from time import sleep
from attr import attrs
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from tiger_pass import senha
from funcoes import *


#software = input('Digite qual a vulnerabilidade que gostaria de procurar: ')
software = 'microsoft'
#startDate_input = input('Informe qual a data de Início: ')
startDate_input = '02/01/2022'
#endDate_input = input('Informe qual a data Final: ')
endDate_input = '02/07/2022'

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

#Seleciona a caixa de pesquisa da vulnerabilidade e digita a String passada pelo usuário
keywords = navegador.find_element(By.ID,'Keywords')
keywords.send_keys(software)

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
            severity_Input = busca_severity(siteSP)   

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
