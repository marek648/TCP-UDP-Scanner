# Nazov projektu :	IPK2
#									   
# Časť:		Makefile				 	   
#									   
# Autor:	Lörinc Marek	<xlorin00>							   
#############################################################################

CC=g++
CFLAGS=-std=c++11 -pedantic -Wall

all: main.cpp raw_socket.cpp raw_socket.h
	$(CC) $(CFLAGS) -O2 -o ipk-scan raw_socket.cpp main.cpp -lpcap 

