#include "Terminal.h"
#include "Util.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include<sys/ioctl.h> 	/* Describe la interfaz de socket para configurar dispositivos de red.*/
#include<net/if.h> 	/* Incluye struct ifreq */

void obtener_indice(int descriptor_de_socket, char* interfaz_de_red, int* indice)
{
	struct ifreq red;

	strcpy(red.ifr_name, interfaz_de_red);
	if(ioctl(descriptor_de_socket, SIOCGIFINDEX, &red) == -1)
	{
		perror("Error al obtener el indice.\n");
		exit(0);
	}

	*indice = red.ifr_ifindex;
}

void obtener_mac(int descriptor_de_socket, char* interfaz_de_red, unsigned char* mac)
{
	struct ifreq red;

	strcpy(red.ifr_name, interfaz_de_red);
	if(ioctl(descriptor_de_socket, SIOCGIFHWADDR, &red) == -1)
	{
		perror("Error al obtener la direccion fisica (MAC).\n");
		exit(0);
	}

	memcpy(mac, red.ifr_hwaddr.sa_data, 6);
}

void obtener_ip(int descriptor_de_socket, char* interfaz_de_red, unsigned char* ip)
{
	struct ifreq red;

	strcpy(red.ifr_name, interfaz_de_red);
	if(ioctl(descriptor_de_socket, SIOCGIFADDR, &red) == -1)
	{
		perror("Error al obtener la direccion logica (IP).\n");
		exit(0);
	}

	memcpy(ip, red.ifr_addr.sa_data + 2, 4);
}

void obtener_mascara_de_subred(int descriptor_de_socket, char* interfaz_de_red, unsigned char* mascara_de_subred)
{
	struct ifreq red;

	strcpy(red.ifr_name, interfaz_de_red);
	if(ioctl(descriptor_de_socket, SIOCGIFNETMASK, &red) == -1)
	{
		perror("Error al obtener la mascara de subred.\n");
		exit(0);
	}

	memcpy(mascara_de_subred, red.ifr_netmask.sa_data + 2, 4);
}

void obtener_datos_de_la_interfaz(int descriptor_de_socket, char* interfaz_de_red, Terminal* terminal)
{
	terminal -> dispositivo = interfaz_de_red;
	obtener_indice(descriptor_de_socket, interfaz_de_red, &(terminal -> indice));
	obtener_mac(descriptor_de_socket, interfaz_de_red, terminal -> mac);
	obtener_ip(descriptor_de_socket, interfaz_de_red, terminal -> ip);
	obtener_mascara_de_subred(descriptor_de_socket, interfaz_de_red, terminal -> mascara_de_subred);
}

void imprimir_informacion_de_terminal(Terminal t)
{
	printf("\tIndice            : %d\n", t.indice);

	printf("\tDireccion MAC     : ");
	for(int i = 0; i < 5; i++)
		printf("%.2x:", t.mac[i]);
	printf("%.2x\n", t.mac[5]);

	printf("\tDireccion IP      : ");
	for(int i = 0; i < 3; i++)
		printf("%d.", t.ip[i]);
	printf("%d\n", t.ip[3]);

	printf("\tMascara de subred : ");
	for(int i = 0; i < 3; i++)
		printf("%d.", t.mascara_de_subred[i]);
	printf("%d\n", t.mascara_de_subred[3]);
}

int obtener_cantidad_de_hosts(Terminal terminal)
{
	byte* mascara = terminal.mascara_de_subred;
	int num_bits_0 = 0;
	for(int i = 0; i < 4; i++)
		for(int j = 0; j < 8; j++)
			if (!((1 << j) & mascara[i]))
				num_bits_0++;
	return (1 << num_bits_0) - 2;
}
