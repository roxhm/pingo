#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <limits.h>

#include <net/if.h> 		// socket
#include <arpa/inet.h> 		// htons
#include <net/ethernet.h> 	// ETH_P_ALL
#include<sys/time.h>

#include "Util.h"
#include "Terminal.h"
#include "Arp.h"
 
/* - - - - - - - - - - MACROS RELACIONADAS AL PROTOCOLO ICMP
 */ 
#define PROTOCOLO_ICMP  0x01	// En el encabezado IP de los mensajes de ICMP, el protocolo se configura en 0x01.
#define SOLICITUD_ECHO  0x08	// Tipo de ICMP para solicitud de ECHO.
#define RESPUESTA_ECHO  0x00 	// Tipo de ICMP para respuesta de ECHO.

/*
 */
const int TIEMPO_DE_ESPERA = 2;

/* - - - - - - - - - - ESTRUCTURAS
 */

/* -- Estructura que contiene todos los campos del encabezado IPv4.
 */
struct Encabezado_IPv4
{
	byte version_ihl;		// 4 bits son para la versión del protocolo IP (actualmente versión 4) y
					// 4 bits son para indicar la longitud del "e n c a b e z a d o"  IP. (min. 5 porque 5 x 4=20 y max. 15 porque 15 x 4 = 60).
	byte tipo_de_servicio;		// Indica la calidad de servicio. Actualmente en ruteo TOS0 = 0x00.
	byte longitud_total[2];		// Longitud del "d a t a g r a m a" IP.
	byte identificacion[2];		// Identifica al conjunto de "f r a g m e n t o s" de un "d a t a g r a m a" original.
	byte banderas_offset[2];	// 3 bits para banderas (DF - Don't fragment) y (MF - More Fragment) y
					// 13 bits para indicar la posición de los datos de un fragmento en relación con los datos de un datagrama IP original.
	byte ttl; 			// Indicación del número de notos por los que puede pasar un datagrama antes de ser eliminado.
	byte protocolo_ip;		// Protocolo de capa superior al que IP le está prestando servicio de transporte.
	byte checksum_encabezado[2];	// Verificación de la integridad del encabezado IP.
	byte ip_origen[4];		// Dirección IP del host de origen,  (unicast).
	byte ip_destino[4];		// Dirección IP del host de destino, (unicast, broadcast, multicast).
};
typedef struct Encabezado_IPv4 Encabezado_IPv4;
const byte IP_ETHERTYPE[] = {0x08, 0x00}; 	// La interfaz de red identifica al protocolo IP con el ethertype 0x0800.

/* -- Estos son campos específicos de los mensajes Echo de ICMP.
 */
struct Echo
{
	byte identificador[2];
	byte num_secuencia[2];
};
typedef struct Echo Echo;

/* -- Estructura que contiene los campos del mensaje ICMP.
 */
struct Mensaje_ICMP
{
	byte tipo;			// Especifica el tipo de mensaje de ICMP. Ej. 8, solicitud de ECHO. 0, respuesta de ECHO.
	byte codigo;			// Indica un mensaje ICMP específico de acuerdo al tipo.
	byte checksum[2];		// Verifica la integridad de los bits del mensaje de ICMP.
	union
	{
		byte resto[4];
		Echo echo;
	} resto;
};
typedef struct Mensaje_ICMP Mensaje_ICMP;


/* -- Estructura trama ECHO.
 * 	|Enc. MAC|Enc. IPv4|Mensaje ICMP|
 */
struct Trama_ICMP
{
	Encabezado_mac mac;
	Encabezado_IPv4 ipv4;
	Mensaje_ICMP icmp;
};
typedef struct Trama_ICMP Trama_ICMP;

/* - - - - - - - - - PROTOTIPOS DE FUNCIÓN
 */

/* -- Muestra en pantalla la forma correcta de ejecutar el programa.
 */
void ayuda();

/* -- Determina si el nodo destino está dentro de la red local o no.
 *
 * PARÁMETROS:
 * 	byte		ip_destino[4]	: arreglo de bytes que indica el destino final (Dirección IP dada por el usuario).
 * 	Terminal	terminal_origen	: estructura que contiene los datos de la interfaz de red (nombre, mac, ip, indice, mascara).
 *
 * RETORNO:
 * 	bool, true	si el nodo destino está dentro de la red local,
 * 	      false 	si el nodo destino no está dentro de la red local.
 *
 * FUNCIONES INTERNAS:
 *	-
 */
bool destino_es_local(byte ip_destino[4], Terminal terminal_origen);

/* -- Determina cuál es la Dirección MAC y la Dirección IP del siguiente nodo dentro de la red local al que se le enviará el paquete.
 *
 * PARÁMETROS:
 * 	byte	 	mac_nodo[6]	: arreglo de bytes en el que se guarda la dirección MAC del siguiente nodo.
 * 	byte 	 	ip_nodo[4]	: arreglo de bytes en el que se guarda la dirección IP del siguiente nodo.
 * 	int 	 	packet_socket 	: descriptor del socket por el que se realiza la comunicación.
 * 	byte 	 	ip_destino[4]	: arreglo de bytes que indica el destino final (Dirección IP dada por el usuario).
 * 	Terminal 	terminal_origen	: estructura que contiene los datos de la interfaz de red (nombre, mac, ip, indice, mascara).
 * RETORNO:
 * 	void
 *
 * FUNCIONES INTERNAS:
 * 	 destino_es_local
 * 	 obtener_puerta_de_enlace
 */
void siguiente_nodo(byte mac_nodo[6], byte ip_nodo[4], int packet_socket, byte ip_destino[4], Terminal terminal_origen);

/* -- Obtiene la dirección IP de la puerta de enlace de la red local, a partir del archivo /proc/net/route.
 *
 * PARÁMETROS:
 * 	byte*	puerta_de_enlace 		: apuntador a un arreglo de bytes en el que se guarda la dirección IP de la puerta de enlace.
 * 						  0.0.0.0 si no se encontró.
 * 	char* 	nombre_de_dispositivo_de_red	: cadena con el nombre de la interfaz de red. Ej. wlp1s0 o enp0s3
 * RETORNO:
 * 	void
 *
 * FUNCIONES INTERNAS:
 * 	-
 */
void obtener_puerta_de_enlace(byte* puerta_de_enlace, char* nombre_de_dispositivo_de_red);

/* -- Implementa el algoritmo de checksum de forma genérica: tanto para el checksum del protocolor IPv4 como para el ICMP. 
 *
 * PARÁMETROS: 
 * 	byte* 	trama		: apuntador al arreglo de bytes que se utilizan para realizar el checksum. 
 * 	int 	longitud	: tamaño de la trama (arreglo de bytes).  
 * RETORNO: 
 * 	uint16_t		: entero de 16 bits (2 bytes) resultado de aplicar el checksum. 
 *
 * FUNCIONES INTERNAS: 
 * 	-
 */
uint16_t checksum(byte* trama, int longitud);


/* -- Recibe una trama ICMP filtrada. (((NO NECESARIAMENTE DE RESPUESTA??)) 
 * 
 * PARÁMETROS: 
 * 	int 		descriptor_de_socket	: descriptor de socket por el que se realiza la comunicación. 
 * 	Terminal*	terminal_origen		: estructura que contiene información de la interfaz de red de la terminal.
 * 	Trama_ICMP*	trama 			: estructura que contiene los datos de la trama ICMP. 
 * RETORNO: 
 * 	int	: 1 si recibió una trama ICMP (ya filtrada), 0 si se agotó el tiempo de espera y no se recibió ninguna trama ICMP. 
 *
 * FUNCIONES INTERNAS: 
 * 	filtro_icmp
 */
int recibir_respuesta_icmp(int descriptor_de_socket, Terminal* terminal_origen, Trama_ICMP* trama);

/* -- Filtra tramas ICMP. 
 * 	En el Encabezado MAC, que la MAC destino sea nuestra MAC y que el ETHERTYPE sea el de IP. 
 * 	En el Encabezado IPv4, que la dirección IP destino sea nuestra IP y que el protocolo sea ICMP.
 *
 * PARÁMETROS: 
 * 	byte*		trama		:	apuntador a un arreglo de bytes que corresponde a la trama recibida a filtrar. 
 * 	Terminal*	terminal_origen : 	estructura que contiene información de la interfaz de red de la terminal. 
 * RETORNO: 
 * 	int 	: 0 si la trama interpretada era ICMP, 1 si la trama interpretada no era ICMP. 
 *
 * FUNCIONES INTERNAS:
 * 	- 
 */ 
int filtro_icmp(byte* trama, Terminal* terminal_origen);

/* -- Estructura una trama ICMP de ECHO. 
 *
 * PARÁMETROS:	
 * 	byte		mac_origen[6]	: arreglo de 6 bytes que contiene la dirección MAC origen (siempre la de la terminal). 
 * 	byte		mac_destino[6]	: arreglo de 6 bytes que contiene la dirección MAC destino 
 * 					  (puede ser la correspondiente a la ip_destino o la de la puerta de enlance). 
 * 	byte 		ip_origen[4] 	: arreglo de 4 bytes que contiene la dirección IP origen (siempre la de la terminal). 
 * 	byte 		ip_destino[4] 	: arreglo de 4 bytes que contiene la dirección IP destino final (la IP dada por el usuario). 
 * 	uint16_t 	id 		: identificador que corresponde al del protocolo IPV4.
 * 	uint16_t 	id_echo		: identificador que sirve para asociar solicitudes y respuestas ICMP. 
 * 	uint16_t 	num_secuencia	: número de sirve para asociar solicitudes y respuestas ICMP. 
 * RETORNO:
 * 	Trama_ICMP	: estructura que representa la trama ICMP de ECHO. 
 * 
 * FUNCIONES INTERNAS: 
 * 	checksum
 *
 * NOTA:
 * 	No confundir mac_destino (que corresponde a la mac del siguiente nodo)
 * 	con ip_destino (que es la IP del destino final).
 */
Trama_ICMP estructurar_solicitud_echo(byte mac_origen[6], byte mac_destino[6],
                                      byte ip_origen[4], byte ip_destino[4],
                                      uint16_t id, uint16_t id_echo, uint16_t num_secuencia);


/* - - - - - - - - - MAIN
 */
int main(int num_argumentos, const char* argumento[])
{
	if(num_argumentos <= 1)
	{
		ayuda();
		return 1;
	}
	srand(time(NULL)); // Para crear un número aleatorio para el indentificador.
	const char* ip_dada_str = argumento[1];
	byte ip_dada[4];
	char* dispositivo_de_red = pedir_dispositivo_red();
	int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	byte mac_siguiente_nodo[6], ip_siguiente_nodo[4];
	Terminal terminal;
	sscanf(ip_dada_str, "%hhu.%hhu.%hhu.%hhu",
	       ip_dada + 0,
	       ip_dada + 1,
	       ip_dada + 2,
	       ip_dada + 3);
	printf("IP destino: ");
	imprimir_ip(ip_dada);
	printf("\n");

	obtener_datos_de_la_interfaz(packet_socket, dispositivo_de_red, &terminal);
	siguiente_nodo(mac_siguiente_nodo, ip_siguiente_nodo,
	               packet_socket, ip_dada, terminal); // Aquí es donde se utiliza el protocolo ARP.
	printf("\nNodo vecino a quién enviar paquete: ");
	imprimir_ip(ip_siguiente_nodo);
	printf("\n");
	uint16_t identificador = rand(); // random
	uint16_t num_secuencia = -1;
	int num_ecos_fallidos = 0;
	int tiempo_minimo_respuesta = INT_MAX;
	int tiempo_maximo_respuesta = INT_MIN;
	int suma_tiempo_respuesta = 0;
	for(int i = 0; i < 4; i++)
	{
		/*
		 * ENVIAR ECO
		 */
		int ttl = -1;
		int tiempo_de_respuesta = -1;
		num_secuencia++;
		Trama_ICMP solicitud_eco = estructurar_solicitud_echo(terminal.mac, mac_siguiente_nodo,
		                           terminal.ip, ip_dada,
		                           0, identificador, num_secuencia);
		enviar_trama(packet_socket, terminal.indice, (byte*) &solicitud_eco, sizeof(Trama_ICMP));

		struct timeval start, end;
		gettimeofday(&start, NULL); // Para medir el tiempo de espera de la respuesta eco.
		Trama_ICMP respuesta_icmp;
		/*
		 * ESPERAR POR UNA RESPUESTA ICMP
		 */
Indefinido:
		gettimeofday(&end, NULL);
		if(end.tv_sec - start.tv_sec >= TIEMPO_DE_ESPERA)
		{
			goto Fallo_Eco;
		}
		if(!recibir_respuesta_icmp(packet_socket, &terminal, &respuesta_icmp))
			goto Fallo_Eco;

		/*
		 * PROCESAR LA RESPUESTA 
		 */
		
		if(!memcmp(respuesta_icmp.ipv4.ip_origen, ip_dada, 4))
			if(!memcmp(&respuesta_icmp.icmp.resto.echo, &solicitud_eco.icmp.resto.echo, sizeof(Echo)))
			{
				ttl = respuesta_icmp.ipv4.ttl;
				gettimeofday(&end, NULL);
				int milisegundos_inicio = start.tv_sec * 1000 + start.tv_usec / 1000;
				int milisegundos_final = end.tv_sec * 1000 + end.tv_usec / 1000;
				tiempo_de_respuesta = milisegundos_final - milisegundos_inicio;
				if (tiempo_de_respuesta < tiempo_minimo_respuesta)
					tiempo_minimo_respuesta = tiempo_de_respuesta;
				if (tiempo_de_respuesta > tiempo_maximo_respuesta)
					tiempo_maximo_respuesta = tiempo_de_respuesta;
				suma_tiempo_respuesta += tiempo_de_respuesta;
				goto Exito_Eco;
			}
		goto Indefinido;
		/*
		 * EL ECO FALLÓ
		 */
Fallo_Eco:
		num_ecos_fallidos++;
		printf("\nFallo una solicitud de Eco.\n");
		continue;
		/*
		 * EL ECO TUVO ÉXITO
		 */
Exito_Eco:
		printf("Respuesta desde ");
		imprimir_ip(ip_dada);
		if (tiempo_de_respuesta != 0)
			printf(":\ttiempo = %d ms", tiempo_de_respuesta);
		else
			printf(":\ttiempo < 1 ms");
		printf("\tTTL = %d\n", ttl);
		continue;
	}
	printf("Estadísticas de ping para ");
	imprimir_ip(ip_dada);
	printf("\n");
	printf("\tPaquetes: enviados = %d, recibidos = %d, perdidos = %d\n\t(%d%% perdidos),\n",
	       4, 4 - num_ecos_fallidos, num_ecos_fallidos, 100 * num_ecos_fallidos / 4);
	if (4 - num_ecos_fallidos >= 1)
	{
		printf("Tiempos aproximados de ida y vuelta en milisegundos:\n");
		printf("\tMínimo = %d ms, Máximo = %d ms, Media = %d ms\n",
		       tiempo_minimo_respuesta, tiempo_maximo_respuesta, suma_tiempo_respuesta / (4 - num_ecos_fallidos));
	}
	free(dispositivo_de_red);
	return 0;
}

/* - - - - - - - - DEFINICIONES DE FUNCIÓN
 */ 
void ayuda()
{
	printf("Uso : pingo [IP destino en formato x.y.z.w]\n");
}

bool destino_es_local(byte ip_destino[4], Terminal terminal_origen)
{
	byte* ip_origen = terminal_origen.ip;
	byte* mascara_de_subred = terminal_origen.mascara_de_subred;
	byte subred_origen[4];
	for(int i = 0; i < 4; i++)
		subred_origen[i] = ip_origen[i] & mascara_de_subred[i];
	byte subred_destino[4];
	for(int i = 0; i < 4; i++)
		subred_destino[i] = ip_destino[i] & mascara_de_subred[i];
	return memcmp(subred_destino, subred_origen, 4) == 0;
}

void siguiente_nodo(byte mac_nodo[6], byte ip_nodo[4], int packet_socket, byte ip_destino[4], Terminal terminal_origen)
{
	bool es_local = destino_es_local(ip_destino, terminal_origen);
	if (!es_local)
		obtener_puerta_de_enlace(ip_nodo, terminal_origen.dispositivo);
	else
		memcpy(ip_nodo, ip_destino, 4);

	Trama_ARP solicitud_arp;
	estructurar_solicitud_arp(&solicitud_arp, &terminal_origen, ip_nodo);
	enviar_trama(packet_socket, terminal_origen.indice, (byte*) &solicitud_arp, sizeof(Trama_ARP));

	struct timeval start, end;
	gettimeofday(&start, NULL);

	for(;;)
	{
		Trama_ARP respuesta_arp;
		recibir_respuesta_arp(packet_socket, &terminal_origen, &respuesta_arp);
		// Hasta antes de esto tenemos respuestas de ARP dirigidas a nosotros pero de diferentes IP.
		// Este filtro es para aquellas que tienen como IP origen, la IP que nos interesa.
		if (memcmp(ip_nodo, respuesta_arp.mensaje_arp.ip_origen, 4) == 0)
		{
			memcpy(mac_nodo, respuesta_arp.mensaje_arp.mac_origen, 6);
//			printf("MAC de siguiente nodo = ");
//			imprimir_mac(mac_nodo);
			return;
		}

		gettimeofday(&end, NULL);
		if(end.tv_sec - start.tv_sec >= 2)
		{
			printf("Tiempo de respuesta ARP excedido.\n");
			exit(1);
		}
	}
	return;
}

void obtener_puerta_de_enlace(byte* puerta_de_enlace, char* dispositivo_de_red)
{
	// valor por defecto si no se encuentra la puerta de enlace
	memcpy(puerta_de_enlace, (byte[4])
	{
		0, 0, 0, 0
	}, 4);

	FILE* archivo_route = fopen("/proc/net/route", "r");
	char linea[1024];
	fgets(linea, 1024, archivo_route);

	char gateway[100];
	while(fgets(linea, 1024, archivo_route))
	{
		char interfaz_linea[100], gateway_linea[100];
		if (sscanf(linea, "%s %*s %s", interfaz_linea, gateway_linea) != 2)
			break;
		if (strcmp(interfaz_linea, dispositivo_de_red) == 0 // interfaz = dispositivo de red dado
		        && strcmp(gateway_linea, "00000000") != 0) // puerta de enlace != 0
			strcpy(gateway, gateway_linea);
	}
	// Está al revés porque así viene en el archivo.
	sscanf(gateway, "%2hhx%2hhx%2hhx%2hhx",
	       puerta_de_enlace + 3,
	       puerta_de_enlace + 2,
	       puerta_de_enlace + 1,
	       puerta_de_enlace + 0);
	fclose(archivo_route);
}


uint16_t checksum(byte* trama, int longitud)
{
	int pares = longitud / 2;
	uint32_t suma = 0;
	uint32_t acarreo;
	for(int i = 0; i < pares; i++)
	{
		suma = suma + (((uint32_t)trama[i * 2] << 8) | trama[i * 2 + 1]);
	}
	acarreo = suma >> 16;
	suma = suma & 0xffff;
	while(acarreo)
	{
		suma = suma + acarreo;
		acarreo = suma >> 16;
		suma = suma & 0xffff;
	}
	return (uint16_t)(~suma);
}

Trama_ICMP estructurar_solicitud_echo(byte mac_origen[6], byte mac_destino[6],
                                      byte ip_origen[4], byte ip_destino[4],
                                      uint16_t id, uint16_t id_echo, uint16_t num_secuencia)
{
	Trama_ICMP trama_icmp;
// Encabezado MAC
	memcpy(trama_icmp.mac.mac_destino, mac_destino, 6);
	memcpy(trama_icmp.mac.mac_origen, mac_origen, 6);
	memcpy(trama_icmp.mac.ethertype, IP_ETHERTYPE, 2);
// Encabezado MAC
//
// Encabezado IP
	//  (00000000)
	//  (vvvvllll)
	//  (01000101)
	//                             (version)   (ihl)
	trama_icmp.ipv4.version_ihl = 0x45;
	trama_icmp.ipv4.tipo_de_servicio = 0;

	int longitud_total = sizeof(Encabezado_IPv4) + sizeof(Mensaje_ICMP);

	// (|00000001|000000000|)
	//  Signitivativo (- +)
	memcpy(trama_icmp.ipv4.longitud_total, (byte[])
	{
		// Enc. IP requiere que la significancia de los bytes sea (+ -)
		(longitud_total >> 8) & 0xff, longitud_total & 0xff
	}, 2);
	memcpy(trama_icmp.ipv4.identificacion, &id, 2);
	memset(trama_icmp.ipv4.banderas_offset, 0, 2);
	trama_icmp.ipv4.ttl = 80;
	trama_icmp.ipv4.protocolo_ip = PROTOCOLO_ICMP;
	memcpy(trama_icmp.ipv4.checksum_encabezado, (byte[])
	{
		0, 0
	}, 2);
	memcpy(trama_icmp.ipv4.ip_origen, ip_origen, 4);
	memcpy(trama_icmp.ipv4.ip_destino, ip_destino, 4);
	uint16_t checksum_ip = checksum((byte*) &trama_icmp.ipv4, sizeof(Encabezado_IPv4));
	memcpy(trama_icmp.ipv4.checksum_encabezado, (byte[])
	{
		(checksum_ip >> 8) & 0xff, checksum_ip & 0xff
	}, 2);
// Encabezado IP
//
// Mensaje ICMP
	trama_icmp.icmp.tipo = SOLICITUD_ECHO;
	trama_icmp.icmp.codigo = 0;
	memcpy(trama_icmp.icmp.checksum, (byte[])
	{
		0, 0
	}, 2);
	memcpy(trama_icmp.icmp.resto.echo.identificador, (byte[])
	{
		(id_echo >> 8) & 0xff, id_echo & 0xff
	}, 2);
	memcpy(trama_icmp.icmp.resto.echo.num_secuencia, (byte[])
	{
		(num_secuencia >> 8) & 0xff, num_secuencia & 0xff
	}, 2);
	uint16_t checksum_icmp = checksum((byte*) &trama_icmp.icmp, sizeof(Mensaje_ICMP));
	memcpy(trama_icmp.icmp.checksum, (byte[])
	{
		(checksum_icmp >> 8) & 0xff, checksum_icmp & 0xff
	}, 2);
// Mensaje ICMP
	return trama_icmp;
}

int recibir_respuesta_icmp(int descriptor_de_socket, Terminal* terminal_origen, Trama_ICMP* trama)
{
	const int TOLERANCIA_ICMP = 3;
	int bytes_recibidos;
	int bandera = 1;
	byte trama_bytes[MAX_LONGITUD_TRAMA_ETHERNET];

	struct timeval start, end;
	long mtime = 0;
	long seconds, useconds;
	gettimeofday(&start, NULL);

	while(mtime < TOLERANCIA_ICMP * 1000)
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
		bandera = filtro_icmp(trama_bytes, terminal_origen);
		if(!bandera)
		{
			// Recibimos un mensaje ICMP dirigido a nosotros.
			if (bytes_recibidos > sizeof(Trama_ICMP))
				bytes_recibidos = sizeof(Trama_ICMP);
			memcpy(trama, trama_bytes, bytes_recibidos);
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


int filtro_icmp(byte* trama, Terminal* terminal_origen)
{
	Encabezado_mac* encabezado_mac = (Encabezado_mac*) trama;
	if(!memcmp(encabezado_mac->mac_destino, terminal_origen -> mac, 6) &&
	        !memcmp(encabezado_mac->ethertype, IP_ETHERTYPE, 2))
	{
		// trama es un mensaje IP dirigido a nosotros
		Encabezado_IPv4* encabezado_ip = (Encabezado_IPv4*)(trama + sizeof(Encabezado_mac));
		if(!memcmp(encabezado_ip -> ip_destino, terminal_origen -> ip, 4) &&
		        encabezado_ip -> protocolo_ip == PROTOCOLO_ICMP)
		{
			// trama es un mensaje ICMP a nosotros
			Mensaje_ICMP* mensaje_icmp = (Mensaje_ICMP*)(trama + sizeof(Encabezado_mac) + sizeof(Encabezado_IPv4)); 
			if(mensaje_icmp -> tipo == RESPUESTA_ECHO) 
				// trama es un mensaje Respuesta Echo a nosotros 
				return 0; 
		}
	}
	return 1;
}
