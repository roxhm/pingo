#include"Arp.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<arpa/inet.h>
#include<linux/if_packet.h>
#include<net/ethernet.h>
#include<unistd.h>
#include<sys/time.h>

#include "Terminal.h"
#include "Util.h"
#include "Ethernet.h"


void estructurar_solicitud_arp(Trama_ARP* solicitud_arp, Terminal* terminal_origen, byte* ip_destino)
{
	armar_encabezado_mac_de_solicitud(&(solicitud_arp -> encabezado_mac), terminal_origen);
	armar_mensaje_arp_de_solicitud(&(solicitud_arp -> mensaje_arp), terminal_origen, ip_destino);
}

void armar_encabezado_mac_de_solicitud(Encabezado_mac* encabezado_mac, Terminal* terminal_origen)
{
	memcpy(encabezado_mac -> mac_destino, MAC_BROADCAST, 6);
	memcpy(encabezado_mac -> mac_origen, terminal_origen -> mac, 6);
	memcpy(encabezado_mac -> ethertype, ARP_ETHERTYPE, 2);
}

void armar_mensaje_arp_de_solicitud(Mensaje_ARP* mensaje_arp, Terminal* terminal_origen, byte* ip_destino)
{
	memcpy(mensaje_arp -> hardware, HARDWARE_ETHERNET, 2);
	memcpy(mensaje_arp -> protocolo, PROTOCOLO_IP, 2);
	mensaje_arp -> longitud_de_mac = 0x06;
	mensaje_arp -> longitud_de_ip  = 0x04;
	memcpy(mensaje_arp -> codigo_de_operacion, ARP_OPERACIÓN_SOLICITUD, 2);
	memcpy(mensaje_arp -> mac_origen, terminal_origen -> mac, 6);
	memcpy(mensaje_arp -> ip_origen, terminal_origen -> ip, 4);
	memcpy(mensaje_arp -> mac_destino, MAC_NULA, 6);
	memcpy(mensaje_arp -> ip_destino, ip_destino, 4);
}

void imprimir_trama_arp(Trama_ARP trama)
{
	printf("\tMAC Destino 	: ");
	imprimir_mac(trama.encabezado_mac.mac_destino);
	printf("\n");
	printf("\tMAC Origen	: ");
	imprimir_mac(trama.encabezado_mac.mac_origen);
	printf("\n");
	printf("\tEthertype	: ");
	imprimir_arreglo(trama.encabezado_mac.ethertype, 2);
	printf("\n");
	printf("\tHardware	: ");
	imprimir_arreglo(trama.mensaje_arp.hardware, 2);
	printf("\n");
	printf("\tProtocolo	: ");
	imprimir_arreglo(trama.mensaje_arp.protocolo, 2);
	printf("\n");
	printf("\tLongitud mac	: %.2x\n", trama.mensaje_arp.longitud_de_mac);
	printf("\tLongitud ip	: %.2x\n", trama.mensaje_arp.longitud_de_ip);
	printf("\tCodigo de op.	: ");
	imprimir_arreglo(trama.mensaje_arp.codigo_de_operacion, 2);
	printf("\n");
	printf("\tMAC Origen 	: ");
	imprimir_mac(trama.mensaje_arp.mac_origen);
	printf("\n");
	printf("\tIP Origen 	: ");
	imprimir_ip(trama.mensaje_arp.ip_origen);
	printf("\n");
	printf("\tMAC Destino 	: ");
	imprimir_mac(trama.mensaje_arp.mac_destino);
	printf("\n");
	printf("\tIP Destino 	: ");
	imprimir_ip(trama.mensaje_arp.ip_destino);
	printf("\n");
}

int enviar_trama(int descriptor_de_socket, int indice, byte* trama_info, int longitud)
{
	int bytes_enviados;
	struct sockaddr_ll capa_de_enlace;
	// Desde cuál dispositivo lo enviaremos
	memset(&capa_de_enlace, 0x00, sizeof(capa_de_enlace));
	capa_de_enlace.sll_family = AF_PACKET;
	capa_de_enlace.sll_protocol = htons(ETH_P_ALL);
	capa_de_enlace.sll_ifindex = indice;

	bytes_enviados = sendto(descriptor_de_socket,
	                        trama_info, longitud,                                       // bytes por enviar
	                        0,                                                          // banderas
	                        (struct sockaddr*)&capa_de_enlace, sizeof(capa_de_enlace)); // dispositivo por el cuál enviar

	return bytes_enviados != -1;
}

int recibir_respuesta_arp(int descriptor_de_socket, Terminal* terminal_origen, Trama_ARP* trama_info)
{
	const int TOLERANCIA_ARP = 3;
	int bytes_recibidos;
	int bandera = 1;
	byte trama_bytes[MAX_LONGITUD_TRAMA_ETHERNET];

	struct timeval start, end;
	long mtime = 0;
	long seconds, useconds;
	gettimeofday(&start, NULL);

	while(mtime < TOLERANCIA_ARP * 1000)
	{
		bytes_recibidos = recvfrom(descriptor_de_socket,
		                           trama_bytes, MAX_LONGITUD_TRAMA_ETHERNET,  // trama por recibir
		                           MSG_DONTWAIT, // banderas
		                           NULL, 0); // dispositivo del cuál recibir (cualquiera)
		if(bytes_recibidos == -1)
		{
			// no recibimos nada, seguir esperando.
			goto actualizar_tiempo;
		}
		/* printf("\nLlega trama con cabecera:\n"); */
		/* imprimir_trama(trama_bytes, sizeof(Encabezado_mac)); */
		bandera = filtro_arp(trama_bytes, terminal_origen);
		if(!bandera)
		{
			// Recibimos un mensaje ARP dirigido a nosotros.
			memcpy(trama_info, trama_bytes, sizeof(Trama_ARP));
			return 1;
		}
actualizar_tiempo:
		gettimeofday(&end, NULL);
		seconds = end.tv_sec - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;
		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
	}
	return 0;
}

int filtro_arp(byte* trama, Terminal* terminal_origen)
{
	Encabezado_mac* encabezado_mac = (Encabezado_mac*) trama;
	if(!memcmp(encabezado_mac->mac_destino, terminal_origen -> mac, 6) &&
	        !memcmp(encabezado_mac->ethertype, ARP_ETHERTYPE, 2))
	{
		// trama es un mensaje ARP dirigido a nosotros
		Trama_ARP* trama_arp = (Trama_ARP*) trama;
		Mensaje_ARP* mensaje_arp = &trama_arp->mensaje_arp;
		if(!memcmp(mensaje_arp->codigo_de_operacion, ARP_OPERACIÓN_RESPUESTA, 2) &&
		        !memcmp(mensaje_arp->ip_destino, terminal_origen -> ip, 4))
			return 0;
	}
	return 1;
}
