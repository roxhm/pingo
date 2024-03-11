#include<stdio.h>
#include<stdlib.h>
#include<net/if.h>
#include<string.h>
#include"Util.h"

char* pedir_dispositivo_red()
{
	struct if_nameindex* if_names = if_nameindex();
	for(struct if_nameindex* if_name = if_names; if_name->if_index != 0; if_name++)
	{
		printf("Interfaz %d: %s\n", if_name->if_index, if_name->if_name);
	}
	int indice = -1;
	char* nombre_disp;
pedir_indice:
	printf("Indice de interfaz por seleccionar: ");
	scanf("%d", &indice);
	for(struct if_nameindex* if_name = if_names; if_name->if_index != 0; if_name++)
	{
		if (indice == if_name->if_index)
		{
			nombre_disp = malloc(strlen(if_name->if_name) + 1);
			strcpy(nombre_disp, if_name->if_name);
			return nombre_disp;
		}
	}
	printf("Ingrese un índice válido, por favor.\n");
	goto pedir_indice;
}

void imprimir_ip(byte* ip)
{
	for(int i = 0; i < 3; i++)
		printf("%d.", ip[i]);
	printf("%d", ip[3]);
}

void imprimir_arreglo(byte* arreglo, int cantidad)
{
	for(int i = 0; i < cantidad; i++)
		printf("%.2x", arreglo[i]);
}

void imprimir_mac(byte* mac)
{
	for(int i = 0; i < 5; i++)
		printf("%.2x:", mac[i]);
	printf("%.2x", mac[5]);
}

void imprimir_trama(byte* trama, int tamaÃ±o)
{
	printf("\t");
	for(int i = 0; i < tamaÃ±o; i++)
	{
		printf("%.2x ", trama[i]);
		if((i + 1) % 16 == 0)
			printf("\n\t");
	}
	fflush(stdout);
}

void sumar_uno(byte* ip, int posicion_bit)
{
	long long int aux = (ip[0] << 24) + (ip[1] << 16) + (ip[2] << 8) + ip[3];
	aux = aux + (1 << posicion_bit);

	ip[3] = aux % (1 << 8);
	aux = aux >> 8;
	ip[2] = aux % (1 << 8);
	aux = aux >> 8;
	ip[1] = aux % (1 << 8);
	aux = aux >> 8;
	ip[0] = aux % (1 << 8);
}
