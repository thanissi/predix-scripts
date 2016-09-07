import sys
import time
import subprocess
from subprocess import Popen
from subprocess import PIPE
import json
import os
import re
import base64
import shutil
import shlex
import xml.dom.minidom
try:
	from urllib2 import Request, urlopen
	from urllib2 import URLError, HTTPError
	from httplib import HTTPSConnection
except ImportError:
	from urllib.request import Request, urlopen
	from urllib.error import URLError, HTTPError
	from http.client import HTTPSConnection
from xml.dom.minidom import parse


def execCommand(command):
	print("Executing " + command)
	statementStatus = subprocess.call(command, shell=True)
	if statementStatus == 1 :
		print("Error executing " + command)
		sys.exit("Error executing " + command)

	return statementStatus

def deleteExistingApplication(applicationName):
	if doesItExist("cf a ", applicationName, 0) :
		deleteRequest = "cf delete -f -r " + applicationName
		statementStatus  = execCommand(deleteRequest)

		if statementStatus == 1 :
			time.sleep(5)  # Delay for 5 seconds
			execCommand(deleteRequest)

		#check if really gone
		if doesItExist("cf a ", applicationName, 0) :
			print("Unable to delete an application, trying again : " +deleteRequest)
			time.sleep(5)  # Delay for 5 seconds
			deleteExistingApplication(applicationName)

def deleteExistingService(serviceName):
	if doesItExist("cf s ", serviceName, 0) :
		deleteRequest = "cf delete-service -f " + serviceName
		statementStatus  = execCommand(deleteRequest)

		if statementStatus == 1 :
			time.sleep(5)  # Delay for 5 seconds
			execCommand(deleteRequest)

		#check if really gone
		if doesItExist("cf s ", serviceName, 0) :
	 		print("Unable to delete an service, trying again: " +deleteRequest)
			deleteExistingService(serviceName)

def doesItExist(command, name, sectionNumber ) :
	'''handle duplicates due to similar spellings, avoid using regular expressions'''
	result, err, exitcode = call(command)
	rows = result.split('\n')
	for row in rows:
		existingSection = row.split(" ")[sectionNumber]
		if existingSection == name :
			return True

def createService(serviceName, serviceRequest):
	print("Create service if it does not exist: " +serviceName)
	print(serviceRequest)
	if doesItExist("cf s ", serviceName, 0) :
		print("Service Intance already exists:" + serviceName)
		return
	else:
		statementStatus  = subprocess.call(serviceRequest, shell=True)
		if statementStatus == 1 :
			print("Error creating a service: " +serviceName)
			time.sleep(5)  # Delay for 5 seconds
			statementStatus  = subprocess.call(serviceRequest, shell=True)
			if statementStatus == 1 :
				print("Error creating a service: " +serviceName)
				sys.exit("Error creating a service instance: " +serviceName)
		else:
			#does it really exist yet
			if not doesItExist("cf s ", serviceName, 0) :
				time.sleep(5)
				createService(serviceName, serviceRequest)

def unbind(applicationName,serviceName):
	if doesItExist("cf a ", applicationName, 0) and doesItExist("cf a ", serviceName, 0):
		unbindRequest = "cf us " + applicationName + " " + serviceName
		print(unbindRequest)
		statementStatus  = subprocess.call(unbindRequest, shell=True)

		if statementStatus == 1 :
			print("Error unbinding an application: " + unbindRequest)
			time.sleep(5)  # Delay for 5 seconds
			statementStatus  = subprocess.call(unbindRequest, shell=True)
			if statementStatus == 1 :
				print("Error unbinding an application: " + unbindRequest)
				sys.exit("Error unbinding an application instance: " +applicationName + " from " + serviceName)


def call(cmd):
	"""Runs the given command locally and returns the output, err and exit_code, handles Pipes."""
	if "|" in cmd:
		cmd_parts = cmd.split('|')
	else:
		cmd_parts = []
		cmd_parts.append(cmd)
	i = 0
	p = {}
	for cmd_part in cmd_parts:
		cmd_part = cmd_part.strip()
		if i == 0:
		  p[i]=Popen(shlex.split(cmd_part),stdin=None, stdout=PIPE, stderr=PIPE)
		else:
		  p[i]=Popen(shlex.split(cmd_part),stdin=p[i-1].stdout, stdout=PIPE, stderr=PIPE)
		i = i +1
	(output, err) = p[i-1].communicate()
	exit_code = p[0].wait()

	return str(output).strip(), str(err), exit_code



# checkout submodules
def checkoutSubmodules():
	print("Pulling Submodules for " + os.getcwd())
	statementStatus  = subprocess.call('git submodule init', shell=True)
	if statementStatus == 1 :
		sys.exit("Error when init submodule ")
	statementStatus  = subprocess.call('git submodule update --init --remote', shell=True)
	if statementStatus == 1 :
		sys.exit("Error when updating submodules")

	return statementStatus


def buildProject(mavenCommand,projectDir):
	statementStatus  = subprocess.call(mavenCommand, shell=True)
	if statementStatus == 1 :
		sys.exit("Error building the project "+projectDir)

	return statementStatus

def encode_multipart_data (data, files):
    boundary = 'FILEBOUNDARY'

    def get_content_type (filename):
        return 'application/octet-stream'

    def encode_field (field_name):
        return ('--' + boundary,
                'Content-Disposition: form-data; name="%s"' % field_name,
                '', str (data [field_name]))

    def encode_file (field_name):
        filename = files [field_name]
        return ('--' + boundary,
                'Content-Disposition: form-data; name="%s"; filename="%s"' % (field_name, filename),
                'Content-Type: %s' % get_content_type(filename),
                '', open (filename, 'rb').read ())

    lines = []
    for name in data:
        lines.extend (encode_field (name))
    for name in files:
        lines.extend (encode_file (name))
    lines.extend (('--%s--' % boundary, ''))
    #print(lines)
    body = '\r\n'.join (lines)
    #print(body)
    #body = ''

    headers = {'content-type': 'multipart/form-data; boundary=' + boundary,
               'content-length': str (len (body))}

    return body, headers

def getJarFromArtifactory(config, cfCommand, projectDir):
	print("\tFast install =" + config.fastinstall)

	artifactId=""
	version=""
  	artifactory=""
  	artifactoryrepo=""
	artifactoryuser=""
	artifactorypass=""
	if config.fastinstall == 'y' :
		print("\tretrieve jar from Artifactory")
		print("\tartifactory repo=" + config.artifactoryrepo)
		print("\tartifactory user =" + config.artifactoryuser)
		#print("\tartifactory pass =" + config.artifactorypass)
	 	print ("\tCurrent Directory = " + os.getcwd())
	 	print ("\tProject Directory = " + projectDir)
		print('\tmvnsettings=' + config.mvnsettings)
		print('\tmavenRepo=' + config.mavenRepo)
		print("\tCopying artifacts..")
		os.chdir(projectDir)
 		print ("\tCurrent Directory = " + os.getcwd())
		f = open("pom.xml", 'r')
		f1 = f.read()
		f.close()
		print("\t============================")
		artifactIdTemp=re.search(r'<artifactId[^>]*>([^<]+)</artifactId>', f1)
		if artifactIdTemp:
        		print("\t" + artifactIdTemp.group(1))
			artifactId=artifactIdTemp.group(1)
		else:
			sys.exit("Error getting artifactId from " + projectDir + "/pom.xml")
		versionTemp=re.search(r'<version[^>]*>([^<]+)</version>', f1)
		if versionTemp:
		        print("\t" + versionTemp.group(1))
			version=versionTemp.group(1)
		else:
			sys.exit("Error getting version from " + projectDir + "/pom.xml")
		print("\tArtifactId derived from pom.xml = " + artifactId)
		print("\tVersion derived from pom.xml" + version)
		os.chdir("..")
		f = open(config.mvnsettings, 'r')
		f1 = f.read()
		f.close()
		#print(f1)
		found = 0
		dom = parse(config.mvnsettings)
		serverlist = dom.getElementsByTagName("server")
		for aServer in  serverlist:
			artifactory1 = aServer.getElementsByTagName("id")[0].firstChild.data
			artifactoryuser = aServer.getElementsByTagName("username")[0].firstChild.data
			artifactorypass = aServer.getElementsByTagName("password")[0].firstChild.data
			print( "\tserver id === " + artifactory1 )
			repolist = dom.getElementsByTagName("repository")
			for aRepo in repolist:
				artifactory2 = aRepo.getElementsByTagName("id")[0].firstChild.data
				artifactoryrepo = aRepo.getElementsByTagName("url")[0].firstChild.data
				print("\tREPOSITORY INFO :" + artifactory2)
				if artifactory1 == artifactory2 :
					print("\tArtifactory derived from maven settings.xml ==== " + artifactory2)
					print("\tArtifactory url from maven settings.xml ==== " + artifactoryrepo)
					print("\tArtifactory user derived from maven settings.xml ==== " + artifactoryuser)
					#print("Artifactory pass derived from maven settings.xml ==== " + artifactorypass)
					if artifactorypass.find("${") == 0 :
						print("\tpassword is set to an environment variable that was not found, moving on to next entry")
					else:
						print("\tCurrent Directory = " + os.getcwd())
						os.chdir(projectDir)
						try:
							os.stat("target")
						except:
							os.mkdir("target")
						request = Request(artifactoryrepo + "/com/ge/predix/solsvc/" + projectDir + "/" + version + "/" + artifactId + "-" + version + ".jar")
						authString = artifactoryuser + ":" + artifactorypass
						base64string = base64.b64encode(bytearray(authString, 'UTF-8')).decode("ascii")
						request.add_header("Authorization", "Basic %s" % base64string)
						try:
							downloadFile="target/" + artifactId + "-" + version + ".jar"
							print("\tDownloading " + downloadFile)
							result = urlopen(request)
							with open(downloadFile, "wb") as local_file:
								local_file.write(result.read())
							print("\tFrom:" + artifactory + " url: " + artifactoryrepo)
							print("\tDownloading DONE")
							print("\t============================")
							found = 1
							os.chdir("..")
							break
						except URLError as err:
							e = sys.exc_info()[1]
							print("\tError: %s" % e)
							found = 0
							os.chdir("..")
							continue
						except HTTPError as err:
							e = sys.exc_info()[1]
							print("\tError: %s" % e)
							found = 0
							os.chdir("..")
							continue
			if found == 1:
				break

		if found == 0:
			sys.exit("\tError copying artifact "+projectDir)

def pushProject(config, appName, cfCommand, projectDir, checkIfExists):
	print("****************** Running pushProject for "+ appName + " ******************" )

	if checkIfExists == "true" :
		#check if really gone
		if doesItExist("cf a ", applicationName, 0) :
			print(appName + " already exists, skipping push")
			return

	if config.fastinstall == 'y' :
		getJarFromArtifactory(config, cfCommand, projectDir)

	statementStatus = cfPush(appName, cfCommand)
	return statementStatus

def cfPush(appName, cfCommand):
		print("Deploying to CF..., Current Directory = " + os.getcwd())
		print(cfCommand)
		statementStatus  = subprocess.call(cfCommand, shell=True)
		if statementStatus == 1 :
			sys.exit("Error deploying the project " + appName)
		print("Deployment to CF done.")
		return statementStatus

def createPredixUAASecurityService(config):
	#create UAA instance
    uaa_payload_filename = 'uaa_payload.json'
    data = {}
    data['adminClientSecret'] = config.uaaAdminSecret

	#cross-os compatibility requires json to be in a file
    with open(uaa_payload_filename, 'w') as outfile:
        json.dump(data, outfile)
        outfile.close()

	uaaJsonrequest = "cf cs "+config.predixUaaService+" "+config.predixUaaServicePlan +" "+config.rmdUaaName+ " -c " + os.getcwd()+'/'+uaa_payload_filename
	createService(config.rmdUaaName,uaaJsonrequest)

def getVcapJsonForPredixBoot (config):
    print("cf env " + config.predixbootAppName)
    predixBootEnv = subprocess.check_output(["cf", "env" ,config.predixbootAppName])
    systemProvidedVars=predixBootEnv.split('System-Provided:')[1].split('No user-defined env variables have been set')[0]
    config.formattedJson = "[" + systemProvidedVars.replace("\n","").replace("'","").replace("}{","},{") + "]"
    #print ("formattedJson=" + config.formattedJson)

def addUAAUser(config, userId , password, email,adminToken):
	createUserBody = {"userName":"","password":"","emails":[{"value":""}]}
	createUserBody["userName"] = userId
	createUserBody["password"] = password
	createUserBody["emails"][0]['value'] = email

	createUserBodyStr = json.dumps(createUserBody)
	print(createUserBodyStr)

	statementStatusJson = invokeURLJsonResponse(config.UAA_URI+"/Users", {"Content-Type": "application/json", "Authorization": adminToken}, createUserBodyStr, "")
	if statementStatusJson.get('error'):
		statementStatus = statementStatusJson['error']
		statementStatusDesc = statementStatusJson['error_description']
	else :
		statementStatus = 'success'
		statementStatusDesc = statementStatusJson['id']

	if statementStatus == 'success' or  'scim_resource_already_exists' not in statementStatusDesc :
		print("User is UAA ")
	else :
		sys.exit("Error adding Users "+statementStatusDesc )


def invokeURLJsonResponse(url, headers, data, method):
	responseCode = invokeURL(url, headers, data, method)
	return json.loads(open("json_output.txt").read())

def invokeURL(url, headers1, data, method):
	request = Request(url, headers=headers1)
	if method :
		request.get_method=lambda: method

	print ("Invoking URL ----" + request.get_full_url())
	print ("\tmethod ----" + request.get_method())
	print ("\t" + str(request.header_items()))
	print ("\tInput data=" + str(data))

	responseCode = 0
	try:
		if data :
			result = urlopen(request, data)
		else :
			result = urlopen(request)
		print (request.data)
		with open("json_output.txt", "wb") as local_file:
			local_file.write(result.read())
			print ("\t*******OUTPUT**********" +  open("json_output.txt").read())
		responseCode = result.getcode()
		print ("\tRESPONSE=" + str(responseCode))
		print ("\t" + str(result.info()))
	except URLError as err:
		e = sys.exc_info()[0]
		print( "Error: %s" % e)
		e = sys.exc_info()[1]
		print( "Error: %s" % e)
		sys.exit()
	except HTTPError as err:
		e = sys.exc_info()[0]
		print( "Error: %s" % e)
		sys.exit()
	print ("\tInvoking URL Complete----" + request.get_full_url())
	return responseCode

def createClientIdAndAddUser(config):
	# setup the UAA login
	adminToken = processUAAClientId(config,config.UAA_URI+"/oauth/clients","POST")

	# Add users
	print("****************** Adding users ******************")
	addUAAUser(config, config.rmdUser1 , config.rmdUser1Pass, config.rmdUser1 + "@gegrctest.ge.com",adminToken)
	addUAAUser(config, config.rmdAdmin1 , config.rmdAdmin1Pass, config.rmdAdmin1 + "@gegrctest.com",adminToken)

def createBindPredixACSService(config, rmdAcsName):
    acs_payload_filename = 'acs_payload.json'
    data = {}
    data['trustedIssuerIds'] = config.uaaIssuerId
    with open(acs_payload_filename, 'w') as outfile:
        json.dump(data, outfile)
        outfile.close()

	#create UAA instance
	acsJsonrequest = "cf cs "+config.predixAcsService+" "+config.predixAcsServicePlan +" "+rmdAcsName+ " -c "+ os.getcwd()+'/'+ acs_payload_filename
	print(acsJsonrequest)
	statementStatus  = subprocess.call(acsJsonrequest, shell=True)
	if statementStatus == 1 :
		sys.exit("Error creating a uaa service instance")

	statementStatus  = subprocess.call("cf bs "+config.predixbootAppName +" " + rmdAcsName , shell=True)
	if statementStatus == 1 :
			sys.exit("Error binding a uaa service instance to boot ")


	#statementStatus  = subprocess.call("cf restage "+config.predixbootAppName, shell=True)
	#if statementStatus == 1 :
	#		sys.exit("Error restaging a uaa service instance to boot")

	return statementStatus

def createGroup(config, adminToken,policyGrp):
	print("****************** Add Group ******************")
	createGroupBody = {"displayName":""}
	createGroupBody["displayName"] = policyGrp
	createGroupBodyStr = json.dumps(createGroupBody)
        print(createGroupBodyStr)

	statementStatusJson = invokeURLJsonResponse(config.UAA_URI+"/Groups", {"Content-Type": "application/json", "Authorization": adminToken}, createGroupBodyStr, "")

	if statementStatusJson.get('error'):
		statementStatus = statementStatusJson['error']
		statementStatusDesc = statementStatusJson['error_description']
	else :
		statementStatus = 'success'
		statementStatusDesc = 'success'

	if statementStatus == 'success' or  'scim_resource_exists' not in statementStatusDesc :
		print("Success creating or reusing the Group")
	else :
		sys.exit("Error Processing Adding Group on UAA "+statementStatusDesc )

def getGroupOrUserByDisplayName(uri, adminToken):
        getResponseJson=invokeURLJsonResponse(uri, {"Content-Type": "application/json", "Authorization": adminToken}, "", "")

	found = True
	statementStatus = 'success'

	if getResponseJson.get('totalResults') <=0 :
		statementStatus = 'not found'
		found = False

	return found, getResponseJson

def getGroup(config, adminToken ,grpname):
	# https://9938f377-5b07-4677-a951-cfeb36858836.predix-uaa-sysint.grc-apps.svc.ice.ge.com/Groups?filter=displayName+eq+%22test%22&startIndex=1
	return getGroupOrUserByDisplayName(config.UAA_URI+ "/Groups/?filter=displayName+eq+%22" + grpname + "%22&startIndex=1", adminToken)

def getUserbyDisplayName(config, adminToken ,username):
	# get https://9938f377-5b07-4677-a951-cfeb36858836.predix-uaa-sysint.grc-apps.svc.ice.ge.com/Users?attributes=id%2CuserName&filter=userName+eq+%22rmd_admin_1%22&startIndex=1
	return getGroupOrUserByDisplayName(config.UAA_URI+ "/Users/?attributes=id%2CuserName&filter=userName+eq+%22" + username + "%22&startIndex=1", adminToken)

def addAdminUserPolicyGroup(config, policyGrp,userName):

	adminToken = getTokenFromUAA(config, 1)
	if not adminToken :
		sys.exit("Error getting admin token from the UAA instance ")

	#check Get Group
	groupFound,groupJson = getGroup(config, adminToken,policyGrp)

	if not groupFound :
		createGroup(config,adminToken,policyGrp)
		groupFound,groupJson = getGroup(config, adminToken,policyGrp)



	userFound,userJson = getUserbyDisplayName(config,adminToken,userName)

	if not userFound :
		sys.exit(" User is not found in the UAA - error adding member to the group")

	members = []
	if groupJson.get('resources') :
		grpName = groupJson['resources'][0]
		if grpName.get('members') :
			groupMeberList = grpName.get('members')
			for groupMeber in groupMeberList:
				members.insert(0 ,groupMeber['value'])

	members.insert(0, userJson['resources'][0]['id'])

	print (' Member to be updated for the Group ,'.join(members))

	#update Group
	groupId = groupJson['resources'][0]['id']
	updateGroupBody = { "meta": {}, "schemas": [],"members": [],"id": "","displayName": ""}
	updateGroupBody["meta"] = groupJson['resources'][0]['meta']
	updateGroupBody["members"] = members
	updateGroupBody["displayName"] = groupJson['resources'][0]['displayName']
	updateGroupBody["schemas"] = groupJson['resources'][0]['schemas']
	updateGroupBody["id"] = groupId

	updateGroupBodyStr = json.dumps(updateGroupBody)
	uuaGroupURL = config.UAA_URI + "/Groups/"+groupId

	statementStatusJson = invokeURLJsonResponse(uuaGroupURL, {"Content-Type": "application/json", "Authorization": "%s" %adminToken, "if-match" : "*", "accept" : "application/json"}, updateGroupBodyStr, "PUT")
	if statementStatusJson.get('error'):
		statementStatus = statementStatusJson['error']
		statementStatusDesc = statementStatusJson['error_description']
	else :
		statementStatus = 'success'
		statementStatusDesc = 'success'

	if statementStatus == 'success' or  'Client already exists' not in statementStatusDesc :
		print ("User Successful adding " +userName + " to the group "+policyGrp)
	else :
		sys.exit("Error adding " +userName + " to the group "+policyGrp + " statementStatusDesc=" + statementStatusDesc )


def updateUserACS(config):
	addAdminUserPolicyGroup(config, "acs.policies.read",config.rmdAdmin1)
	addAdminUserPolicyGroup(config, "acs.policies.write",config.rmdAdmin1)
	addAdminUserPolicyGroup(config, "acs.attributes.read",config.rmdAdmin1)
	addAdminUserPolicyGroup(config, "acs.attributes.write",config.rmdAdmin1)

	addAdminUserPolicyGroup(config, "acs.policies.read",config.rmdUser1)
	addAdminUserPolicyGroup(config, "acs.attributes.read",config.rmdUser1)

def processUAAClientId (config,uuaClientURL,method):
	adminToken = getTokenFromUAA(config, 1)
	if not adminToken :
		sys.exit("Error getting admin token from the UAA instance ")

	# create a client id
	print("****************** Creating client id ******************")
	print(config.clientScope)
	print(config.clientScopeList)

	createClientIdBody = {"client_id":"","client_secret":"","scope":[],"authorized_grant_types":[],"authorities":[],"autoapprove":["openid"]}
	createClientIdBody["client_id"] = config.rmdAppClientId
	createClientIdBody["client_secret"] = config.rmdAppSecret
	createClientIdBody["scope"] = config.clientScopeList
	createClientIdBody["authorized_grant_types"] = config.clientGrantType
	createClientIdBody["authorities"] = config.clientAuthoritiesList

	createClientIdBodyStr = json.dumps(createClientIdBody)

	statementStatusJson = invokeURLJsonResponse(uuaClientURL, {"Content-Type": "application/json", "Authorization": adminToken}, createClientIdBodyStr, method)
	if statementStatusJson.get('error'):
		statementStatus = statementStatusJson['error']
		statementStatusDesc = statementStatusJson['error_description']
	else :
		statementStatus = 'success'
		statementStatusDesc = 'success'

	if statementStatus == 'success' or  'Client already exists' in statementStatusDesc :
		print("Success creating or reusing the Client Id")
	else :
		sys.exit("Error Processing ClientId on UAA "+statementStatusDesc )

	return adminToken


def updateClientIdAuthorities(config):
	processUAAClientId(config,config.UAA_URI+"/oauth/clients/"+config.rmdAppClientId,"PUT")

def getTokenFromUAA(config, isAdmin):
	realmStr=""
	if isAdmin == 1:
		realmStr = "admin:"+config.uaaAdminSecret
	else :
		realmStr = config.rmdAppClientId+":"+config.rmdAppSecret
        authKey = base64.b64encode(bytearray(realmStr, 'UTF-8')).decode("ascii")
        queryClientCreds= "grant_type=client_credentials"

        getClientTokenResponseJson=invokeURLJsonResponse(config.uaaIssuerId + "?" + queryClientCreds, {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic %s" % authKey}, "", "")

	print("Client Token is "+getClientTokenResponseJson['token_type']+" "+getClientTokenResponseJson['access_token'])
	return (getClientTokenResponseJson['token_type']+" "+getClientTokenResponseJson['access_token'])

def createRefAppACSPolicyAndSubject(config,acs_zone_header):
	adminUserTOken = getTokenFromUAA(config, 0)
	invokeURL(config.ACS_URI+'/v1/policy-set/refapp-acs-policy', {"Content-Type": "application/json", "Authorization": "%s" %adminUserTOken, "Predix-Zone-Id" : "%s" %acs_zone_header}, open("./acs/rmd_app_policy.json").read(), "PUT")

	#acsSubjectCurl = 'curl -X PUT "'+config.ACS_URI+'/v1/subject/' + config.rmdAdmin1 + '"' + ' -d "@./acs/' + config.rmdAdmin1 + '_role_attribute.json"'+headers
	invokeURL(config.ACS_URI+'/v1/subject/' + config.rmdAdmin1, {"Content-Type": "application/json", "Authorization": "%s" %adminUserTOken, "Predix-Zone-Id" : "%s" %acs_zone_header}, open("./acs/" + config.rmdAdmin1 + "_role_attribute.json").read(), "PUT")
	#acsSubjectCurl = 'curl -X PUT "'+config.ACS_URI+'/v1/subject/' + config.rmdUser1 + '"' + ' -d "@./acs/"' + config.rmdUser1 + '"_role_attribute.json"'+headers
	invokeURL(config.ACS_URI+'/v1/subject/' + config.rmdUser1, {"Content-Type": "application/json", "Authorization": "%s" %adminUserTOken, "Predix-Zone-Id" : "%s" %acs_zone_header}, open("./acs/" + config.rmdUser1+ "_role_attribute.json").read(), "PUT")

def createAsssetInstance(config,rmdPredixAssetName ,predixAssetName ):
	getPredixUAAConfigfromVcaps(config)
	asset_payload_filename = 'asset_payload.json'
	uaaList = [config.uaaIssuerId]
	data = {}
	data['trustedIssuerIds'] = uaaList
	with open(asset_payload_filename, 'w') as outfile:
		json.dump(data, outfile)
		print(data)
		outfile.close()

		assetJsonrequest = "cf cs "+predixAssetName+" "+config.predixAssetServicePlan +" "+rmdPredixAssetName+ " -c "+os.getcwd()+'/' +asset_payload_filename
		print ("Creating Service cmd "+assetJsonrequest)
		statementStatus  = subprocess.call(assetJsonrequest, shell=True)
		#if statementStatus == 1 :
			#sys.exit("Error creating a assset service instance")

def createTimeSeriesInstance(config,rmdPredixTimeSeriesName,predixTimeSeriesName):
    timeSeries_payload_filename = 'timeseries_payload.json'
    uaaList = [config.uaaIssuerId]
    data = {}
    data['trustedIssuerIds'] =uaaList
    with open(timeSeries_payload_filename, 'w') as outfile:
        json.dump(data, outfile)
        outfile.close()

	tsJsonrequest = "cf cs "+predixTimeSeriesName+" "+config.predixTimeSeriesServicePlan +" "+rmdPredixTimeSeriesName+ " -c "+os.getcwd()+'/'+timeSeries_payload_filename
	print ("Creating Service cmd "+tsJsonrequest)
	statementStatus  = subprocess.call(tsJsonrequest, shell=True)
	if statementStatus == 1 :
		sys.exit("Error creating a assset service instance")

def createAnalyticsRuntimeInstance(config,rmdPredixAnalyticsRuntime, predixAnalyticsRuntime):
	print("Creating Analytics runtime instance..")
	getPredixUAAConfigfromVcaps(config)
	asset_payload_filename = 'asset_payload.json'
	uaaList = [config.uaaIssuerId]
	data = {}
	data['trustedIssuerIds'] = uaaList
	with open(asset_payload_filename, 'w') as outfile:
		json.dump(data, outfile)
		print(data)
		outfile.close()

		assetJsonrequest = "cf cs "+predixAnalyticsRuntime+" "+config.predixAnalyticsRuntimePlan +" "+rmdPredixAnalyticsRuntime+ " -c "+os.getcwd()+'/' +asset_payload_filename
		print ("Creating Service cmd "+assetJsonrequest)
		statementStatus  = subprocess.call(assetJsonrequest, shell=True)
		#if statementStatus == 1 :
			#sys.exit("Error creating a assset service instance")

def createAnalyticsCatalogInstance(config,rmdPredixAnalyticsCatalog, predixAnalyticsCatalog):
	print("Creating Analytics catalog instance..")
	getPredixUAAConfigfromVcaps(config)
	asset_payload_filename = 'asset_payload.json'
	uaaList = [config.uaaIssuerId]
	data = {}
	data['trustedIssuerIds'] = uaaList
	with open(asset_payload_filename, 'w') as outfile:
		json.dump(data, outfile)
		print(data)
		outfile.close()

		assetJsonrequest = "cf cs "+predixAnalyticsCatalog+" "+config.predixAnalyticsCatalogPlan +" "+rmdPredixAnalyticsCatalog+ " -c "+os.getcwd()+'/' +asset_payload_filename
		print ("Creating Service cmd "+assetJsonrequest)
		statementStatus  = subprocess.call(assetJsonrequest, shell=True)
		#if statementStatus == 1 :
			#sys.exit("Error creating a assset service instance")

def getPredixUAAConfigfromVcaps(config):
	if not hasattr(config,'uaaIssuerId') :
		getVcapJsonForPredixBoot(config)
		d = json.loads(config.formattedJson)
		config.uaaIssuerId =  d[0]['VCAP_SERVICES'][config.predixUaaService][0]['credentials']['issuerId']
		config.UAA_URI = d[0]['VCAP_SERVICES'][config.predixUaaService][0]['credentials']['uri']
		uaaZoneHttpHeaderName = d[0]['VCAP_SERVICES'][config.predixUaaService][0]['credentials']['zone']['http-header-name']
		uaaZoneHttpHeaderValue = d[0]['VCAP_SERVICES'][config.predixUaaService][0]['credentials']['zone']['http-header-value']
		print("****************** UAA configured As ******************")
		print ("\n uaaIssuerId = " + config.uaaIssuerId + "\n UAA_URI = " + config.UAA_URI + "\n "+uaaZoneHttpHeaderName+" = " +uaaZoneHttpHeaderValue+"\n")
		print("****************** ***************** ******************")


def getPredixACSConfigfromVcaps(config):
	if not hasattr(config,'ACS_URI') :
		getVcapJsonForPredixBoot(config)
		d = json.loads(config.formattedJson)
		config.ACS_URI = d[0]['VCAP_SERVICES'][config.predixAcsService][0]['credentials']['uri']
		config.acsPredixZoneHeaderName = d[0]['VCAP_SERVICES'][config.predixAcsService][0]['credentials']['zone']['http-header-name']
		config.acsPredixZoneHeaderValue = d[0]['VCAP_SERVICES'][config.predixAcsService][0]['credentials']['zone']['http-header-value']
		config.acsOauthScope = d[0]['VCAP_SERVICES'][config.predixAcsService][0]['credentials']['zone']['oauth-scope']


def bindService(applicationName , rmdServiceInstanceName):
	statementStatus  = subprocess.call("cf bs "+applicationName +" " + rmdServiceInstanceName , shell=True)
	if statementStatus == 1 :
		sys.exit("Error binding a "+rmdServiceInstanceName+" service instance to boot ")


def restageApplication(applicationName):
	statementStatus  = subprocess.call("cf restage "+applicationName, shell=True)
	if statementStatus == 1 :
		sys.exit("Error restaging a uaa service instance to boot")

def getAnalyticsRuntimeURLandZone(config):
	if not hasattr(config,'ANALYTICRUNTIME_ZONE') :
		print("parsing analytics runtime zone and uri from vcap")
		analyticsRuntimeUri = ''
		analyticsRuntimeZone = ''
		d = json.loads(config.formattedJson)
		analyticsRuntimeZone = d[0]['VCAP_SERVICES'][config.predixAnalyticsRuntime][0]['credentials']['zone-http-header-value']
		analyticsRuntimeUri = d[0]['VCAP_SERVICES'][config.predixAnalyticsRuntime][0]['credentials']['execution_uri']
		if "https" in analyticsRuntimeUri:
			config.ANALYTICRUNTIME_URI = analyticsRuntimeUri.split('https://')[1].strip()
		else :
			config.ANALYTICRUNTIME_URI = analyticsRuntimeUri.split('http://')[1].strip()
		config.ANALYTICRUNTIME_ZONE = analyticsRuntimeZone

def getAnalyticsCatalogURLandZone(config):
	if not hasattr(config,'CATALOG_ZONE') :
		catalogUri = ''
		catalogZone = ''
		d = json.loads(config.formattedJson)
		catalogZone = d[0]['VCAP_SERVICES'][config.predixAnalyticsCatalog][0]['credentials']['zone-http-header-value']
		catalogUri = d[0]['VCAP_SERVICES'][config.predixAnalyticsCatalog][0]['credentials']['catalog_uri']
		if "https" in catalogUri:
			config.CATALOG_URI = catalogUri.split('https://')[1].strip()
		else :
			config.CATALOG_URI = catalogUri.split('http://')[1].strip()
		config.CATALOG_ZONE = catalogZone

def getAssetURLandZone(config):
	if not hasattr(config,'ASSET_ZONE') :
		assetUrl = ''
		assetZone =''
		d = json.loads(config.formattedJson)
		assetZone = d[0]['VCAP_SERVICES'][config.predixAssetService][0]['credentials']['instanceId']
		assetUrl = d[0]['VCAP_SERVICES'][config.predixAssetService][0]['credentials']['uri']
		config.ASSET_ZONE = assetZone
		config.ASSET_URI = assetUrl

def getTimeseriesURLandZone(config):
	if not hasattr(config,'TS_ZONE') :
		timeseriesUrl = ''
		timeseriesZone =''
		d = json.loads(config.formattedJson)
		timeseriesZone = d[0]['VCAP_SERVICES'][config.predixTimeSeriesService][0]['credentials']['query']['zone-http-header-value']
		timeseriesUrl = d[0]['VCAP_SERVICES'][config.predixTimeSeriesService][0]['credentials']['query']['uri']
		config.TS_ZONE = timeseriesZone
		config.TS_URI = timeseriesUrl

def getClientAuthoritiesforAssetAndTimeSeriesService(config):
	d = json.loads(config.formattedJson)

	config.assetScopes = config.predixAssetService+".zones."+d[0]['VCAP_SERVICES'][config.predixAssetService][0]['credentials']['instanceId']+".user"
	#get Ingest authorities
	tsInjest = d[0]['VCAP_SERVICES'][config.predixTimeSeriesService][0]['credentials']['ingest']
	config.timeSeriesInjestScopes = tsInjest['zone-token-scopes'][0] +"," + tsInjest['zone-token-scopes'][1]
	# get query authorities
	tsQuery = d[0]['VCAP_SERVICES'][config.predixTimeSeriesService][0]['credentials']['query']
	config.timeSeriesQueryScopes = tsQuery['zone-token-scopes'][0] +"," + tsQuery['zone-token-scopes'][1]

	if hasattr(config,'ANALYTICRUNTIME_ZONE') :
		config.analyticRuntimeScopes = "analytics.zones." + config.ANALYTICRUNTIME_ZONE + ".user"
	#config.catalogScopes = "analytics.zones." + config.CATALOG_ZONE + ".user"

	config.clientAuthoritiesList.append(config.assetScopes)
	config.clientAuthoritiesList.append(config.timeSeriesInjestScopes)
	config.clientAuthoritiesList.append(config.timeSeriesQueryScopes)
	if hasattr(config,'analyticRuntimeScopes') :
		config.clientAuthoritiesList.append(config.analyticRuntimeScopes)
	#config.clientAuthoritiesList.append(config.catalogScopes)


	config.clientScopeList.append(config.assetScopes)
	config.clientScopeList.append(config.timeSeriesInjestScopes)
	config.clientScopeList.append(config.timeSeriesQueryScopes)
	if hasattr(config,'analyticRuntimeScopes') :
		config.clientScopeList.append(config.analyticRuntimeScopes)
	#config.clientScopeList.append(config.catalogScopes)

	print ("returning timeseries client zone scopes query -->"+config.timeSeriesQueryScopes + " timeSeriesInjestAuthorities -->"+config.timeSeriesInjestScopes )


def updateUAAUserGroups(config, serviceGroups):
	groups = serviceGroups.split(",")
	#print (groups)
	for group in groups:
		#print (group)
		addAdminUserPolicyGroup(config, group,config.rmdAdmin1Pass)
		addAdminUserPolicyGroup(config, group,config.rmdUser1Pass)

def findRedisService(config):
	#setup Redis
	result = []
	process = subprocess.Popen('cf m',
	    shell=True,
	    stdout=subprocess.PIPE,
	    stderr=subprocess.PIPE )
	for line in process.stdout:
	    result.append(line)
	errcode = process.returncode
	#print (errcode)
	search_redis = config.predixRedis
	for line in result:
		if(line.find(search_redis) > -1):
			#print(line)
			config.predixRedis = line.split()[0].strip()
			print ("Setting Redis config.predixRedis as "+ config.predixRedis)

def getAuthorities(config):
	if not hasattr(config,'clientAuthoritiesList') :
		config.clientAuthoritiesList = list(config.clientAuthorities)
		config.clientScopeList = list(config.clientScope)

def updateClientAuthoritiesACS(config):
	getPredixACSConfigfromVcaps(config)
	config.clientAuthoritiesList.append(config.acsOauthScope)
	config.clientScope.append(config.acsOauthScope)
