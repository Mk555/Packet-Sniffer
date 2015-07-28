#!/usr/bin/python

#####################################
# Libs
#####################################

from scapy.all import *
import getpass
import argparse
import os
import sys
import time
import sqlite3 as sqlite
import re

#####################################
# Arguments
#####################################

# Get the current username
user = getpass.getuser()

# Check if      the user is root
if user != "root":
        print "You need to be root to use me."
        sys.exit(1);

#####################################
#  Variables
#####################################


## Create a Packet Count var
cptPck = 0

connexion = None
regexSpecialChars = re.compile( "\ " )

####################################
#  CLASS
####################################

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



#####################################
# Functions
#####################################


def initConn():
	
	dbVersion = ""
	cursor = None
	connexion = sqlite.connect("servers.db")

	with connexion:
		# Init the cursor
		cursor = connexion.cursor()
		
		# Prepare the request and execute it
		cursor.execute( 'SELECT SQLITE_VERSION()')
		dbVersion = cursor.fetchone()

		# Extract the data and print it
		print( "Connected to the database. (v %s)" %dbVersion )
		
# End function
#####################################

def checkIpPresence( ipToCheck ):
	
	cursor = None
	nbOccurences = 0

	connexion = sqlite.connect("servers.db")

	with connexion:

		cursor = connexion.cursor()
		
		cursor.execute( "Select count(*) From Servers Where ip = '" + ipToCheck + "';") 
		nbOccurences = cursor.fetchone()
		nbOccurences = int("%i" %nbOccurences)
	
	if( nbOccurences > 0 ):
		return True
	else:
		return False

# End function
#####################################

def addIpToDb( ipToAdd ):

	cursor = None
	
	connexion = sqlite.connect( "servers.db")

	with connexion:
		cursor = connexion.cursor()
	
		cursor.execute( "Insert into servers values ( '" + ipToAdd + "', '' );")

# End function
#####################################

def addContentPackToDb( contentPack ):

	cursor = None 

	connexion = sqlite.connect( "servers.db" )

	with connexion:
		cursor = connexion.cursor()
	
		# Replace special chars
		stringPack = '%r' %contentPack
		
		# DEBUG
		#print( stringPack )
		
		cursor.execute( r'Insert into packets (packContent) values ("' + stringPack + '");' )

# Capture packets

def captureStandart( packet ):
        global cptPck
        cptPck += 1

	contentPack = ""

	# DEBUG
        #print(bcolors.HEADER + "\nPacket #" + str(cptPck) + "" + bcolors.ENDC)
        #print( bcolors.OKGREEN + "src : " + packet[0][1].src + bcolors.ENDC + bcolors.OKBLUE + "\ndst : " + packet[0][1].dst + "\n" + bcolors.ENDC)

	if( checkIpPresence( packet[0][1].dst )):
		#print( bcolors.OKGREEN + "Exists in the DB" + bcolors.ENDC)
		cptPck = cptPck
	else:
		#print( "Doesn't exists in the DB")
		addIpToDb( packet[0][1].dst )

	
	try:
		addContentPackToDb( packet[0][1] )
	except sqlite.Error, e:
		#print( packet[0][1].summary() )
		addContentPackToDb( "" )
	
	sys.stdout.write( "\r" + str(cptPck) + " Packets sniffed." )
	sys.stdout.flush()
	


# End function
#####################################


#####################################
# Code
#####################################


initConn()


sniff(filter="tcp", prn=captureStandart)






print("END !! \n")











