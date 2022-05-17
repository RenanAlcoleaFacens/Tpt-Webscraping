#Função que retorna a Severity do CVE (4º Item da lista)

def busca_severity(siteSP):    
    if siteSP.find('a',attrs={'id': 'Cvss3NistCalculatorAnchor'}):
        severity_Input = siteSP.find('a',attrs={'id': 'Cvss3NistCalculatorAnchor'}).getText()        
    else:
        severity_Input = 'N/A' 
    return severity_Input 

#Função que retorna os Hyperlinks do CVE (5º Item da lista)
def busca_links(pagina_resultadoCVE_BS,hyperlink_RefExt=0,links_impresso=0,i=0,counter=0):    
    
    if i == 0:
        links_impresso= ''
        hyperlink_RefExt=[]
        #Separando a tabela que contém os links e quantidade de tags que contém links:
        counter = len(pagina_resultadoCVE_BS.find('table',class_='table table-striped table-condensed table-bordered detail-table').find_all('a'))
    #Executando o comando de separar o link do corpo html através do get_text(), repetindo a qtd de vezes necessária:    
    hyperlink_RefExt.append(pagina_resultadoCVE_BS.find('td',attrs={'data-testid':'vuln-hyperlinks-link-'+str(i)}).get_text())
    links_impresso = links_impresso + str(hyperlink_RefExt[i]) + ', '
    i=i+1
    if i == counter:
        return links_impresso
    else:
        return busca_links(pagina_resultadoCVE_BS,hyperlink_RefExt,links_impresso,i,counter)


#Função que retorna os Known Affected Software Configurations (6º Item da lista)
def busca_kasc(pagina_resultadoCVE_BS,KASC=0,kasc_impresso=0,i=0,counter=0):
    
    if i == 0:
        kasc_impresso = ''
        KASC = []
        #Separando a tabela que contém os links e quantidade de tags que contém links:
        counter = len(pagina_resultadoCVE_BS.find_all(text="CPE Configuration"))

    #Executando o comando de separar o link do corpo html através do get_text(), repetindo a qtd de vezes necessária:     
    if pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}):
        KASC.append(pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0-0'}).get_text()[2:])
    else:
        KASC.append(pagina_resultadoCVE_BS.find('b',attrs={'data-testid':'vuln-software-cpe-'+str(i+1)+'-0-0'}).get_text()[2:])
    kasc_impresso = kasc_impresso + ', ' + str(KASC[i]) 
    i=i+1    
    
    if i == counter:
        return kasc_impresso
    else:
        return busca_kasc(pagina_resultadoCVE_BS,KASC,kasc_impresso,i,counter)

#Função que retorna a Data de Publicação da CVE (7º Item da lista)
def busca_publish(siteSP):     
    return siteSP.find('span',attrs={'data-testid':'vuln-published-on'}).getText()

#Função que retorna o Link de Detalhes da CVE (8º Item da lista)
def busca_details(cveInput):
    return 'https://nvd.nist.gov/vuln/detail/'+cveInput