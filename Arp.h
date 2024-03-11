#pragma once
#include "Terminal.h"
#include "Ethernet.h"
#include "Util.h"

struct Mensaje_ARP
{
	byte hardware[2];
	byte protocolo[2];
	byte longitud_de_mac;
	byte longitud_de_ip;
	byte codigo_de_operacion[2];
	byte mac_origen[6];
	byte ip_origen[4];
	byte mac_destino[6];
	byte ip_destino[4];
};
typedef struct Mensaje_ARP Mensaje_ARP;

static byte HARDWARE_ETHERNET[] = {0x00, 0x01};
static byte PROTOCOLO_IP[] = {0x08, 0x00};
static byte ARP_OPERACIÓN_SOLICITUD[] = {0x00, 0x01};
static byte ARP_OPERACIÓN_RESPUESTA[] = {0x00, 0x02};
static byte ARP_ETHERTYPE[] = {0x08, 0x06};

// Las subdivisiones, aunque no son necesarias (puesto que todo se envía en un solo arreglo de bytes)
// se hicieron con el fin de tener de manera explícita los valores de cada campo.
struct Trama_ARP
{
	Encabezado_mac encabezado_mac;
	Mensaje_ARP mensaje_arp;
};

typedef struct Trama_ARP Trama_ARP;

void estructurar_solicitud_arp(Trama_ARP*, Terminal*, byte*);
void armar_encabezado_mac_de_solicitud(Encabezado_mac*, Terminal*);
void armar_mensaje_arp_de_solicitud(Mensaje_ARP*, Terminal*, byte*);
void imprimir_trama_arp(Trama_ARP trama);
int enviar_trama(int, int, byte*, int);
int recibir_respuesta_arp(int, Terminal*, Trama_ARP*);
int filtro_arp(byte*, Terminal*);


