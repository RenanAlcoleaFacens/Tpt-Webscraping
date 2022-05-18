from datetime import datetime

#Função que retorna a Severity do CVE (4º Item da lista)

#Recebendo os dois inpusts como argumento:
def validador_datas(dataBR1, dataBR2):
    
    '''dataBR1 = '01/05/2022'
    dataBR2 = '16/10/2023'''

    # Data Inicial
    d1 = datetime.strptime(dataBR1, '%Y-%m-%d')

    # Data Final
    d2 = datetime.strptime(dataBR2, '%Y-%m-%d')

    #2022/10/04


    #Calcula se o período informado é maior que 180 dias:
    if abs((d2 - d1).days)>180:        
        print("O período pesquisado não pode ser maior que 180 dias!")
        return
    else:
        dataUS1 = dataBR1[5:7]+ "/" + dataBR1[8:] + "/" + dataBR1[0:4]
        dataUS2 = dataBR2[5:7]+ "/" + dataBR2[8:] + "/" + dataBR2[0:4]
        dataUS = [dataUS1,dataUS2]
    return dataUS

def busca_severity(siteSP):    
    if siteSP.find('a',attrs={'id': 'Cvss3NistCalculatorAnchor'}):
        severity_Input = siteSP.find('a',attrs={'id': 'Cvss3NistCalculatorAnchor'}).getText()        
    else:
        severity_Input = 'N/A' 
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
        links_impresso = links_impresso + ', ' + str(pagina_resultadoCVE_BS.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i)}).get_text())

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
        else:
            KASC = pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}).get_text()[2:]

    #Executando o comando de separar o link do corpo html através do get_text(), repetindo a qtd de vezes necessária:    
    
    if pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}):
        KASC = KASC + ', ' + pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}).get_text()[2:]
    else:
        KASC = KASC + ', ' + pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}).get_text()[2:]
    
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