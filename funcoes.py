#Recebendo os dois inpusts como argumento:
from datetime import datetime


def validador_datas():
    
    dataBR1 = '01/05/2022'
    dataBR2 = '16/10/2023'

    # Data Inicial
    d1 = datetime.strptime(dataBR1, '%d/%m/%Y')

    # Data Final
    d2 = datetime.strptime(dataBR2, '%d/%m/%Y')

    #Calcula se o período informado é maior que 180 dias:
    if abs((d2 - d1).days)>180:        
        print("O período pesquisado não pode ser maior que 180 dias!")
        return
    else:
        dataUS1 = dataBR1[3:6]+dataBR1[0:3]+dataBR1[6:]
        dataUS2 = dataBR2[3:6]+dataBR2[0:3]+dataBR2[6:]
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
        severity_Input = 0
    return severity_Input

#Função que retorna os Hyperlinks do CVE (5º Item da lista)
def busca_links(pagina_resultadoCVE_BS,links_impresso = 0,i=0,counter=0):

    if i == 0:
        links_impresso = ""
        #Separando a tabela que contém os links e quantidade de tags que contém links:
        counter = len(pagina_resultadoCVE_BS.find('table',class_='table table-striped table-condensed table-bordered detail-table').find_all('a'))
        links_impresso = str(pagina_resultadoCVE_BS.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i)}).get_text())

    #Executando o comando de separar o link do corpo html através do get_text(), repetindo a qtd de vezes necessária:
    else:
        links_impresso = links_impresso + '\n' + str(pagina_resultadoCVE_BS.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i)}).get_text())

    i=i+1

    if i == counter:
        return links_impresso 
    else:
        return busca_links(pagina_resultadoCVE_BS,links_impresso,i,counter)

#Função que retorna os Known Affected Software Configurations (6º Item da lista)

def busca_kasc(pagina_resultadoCVE_BS,KASC=0,i=0,counter=0):
    
    if i == 0:
        KASC = ""
        #Separando a tabela que contém os links e quantidade de tags que contém links:
        counter = len(pagina_resultadoCVE_BS.find_all(text="CPE Configuration"))

        if pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}):
            KASC = pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}).get_text()[2:]
        elif pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}):
            KASC = KASC + '\n ' + pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}).get_text()[2:]
        else:
            KASC="N/A"
            return KASC

    #Executando o comando de separar o link do corpo html através do get_text(), repetindo a qtd de vezes necessária:    
    
    if pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}):
        KASC = KASC + '\n ' + pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}).get_text()[2:]
    elif pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}):
        KASC = KASC + '\n ' + pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}).get_text()[2:]
    else:
        KASC="N/A"
        return KASC
    
    i=i+1

    if i == counter:
        return KASC
    else:
        return busca_kasc(pagina_resultadoCVE_BS,KASC,i,counter)

#Função que retorna a Data de Publicação da CVE (7º Item da lista)
def busca_publish(siteSP):     
    return siteSP.find('span',attrs={'data-testid':'vuln-published-on'}).getText()

#Função que retorna o Link de Detalhes da CVE (8º Item da lista)
def busca_details(cveInput):
    return 'https://nvd.nist.gov/vuln/detail/'+cveInput