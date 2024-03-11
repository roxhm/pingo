#pragma once 

#include "Util.h"

#define MAX_LONGITUD_TRAMA_ETHERNET 1514

struct Encabezado_mac
{
	byte mac_destino[6];
	byte mac_origen[6];
	byte ethertype[2];
};
typedef struct Encabezado_mac Encabezado_mac;

static byte MAC_NULA[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static byte MAC_BROADCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

