#ifndef __TERMINAL_H_
#define __TERMINAL_H_


// Información de la interfaz de red de la terminal
struct Terminal
{
	int indice;
	unsigned char mac[6];
	unsigned char ip[4];
	unsigned char mascara_de_subred[4];
	char* dispositivo;
};

typedef struct Terminal Terminal;

void obtener_indice(int, char*, int*);
void obtener_mac(int, char*, unsigned char*);
void obtener_ip(int, char*, unsigned char*);
void obtener_mascara_de_subred(int, char*, unsigned char*);
void obtener_datos_de_la_interfaz(int, char*, Terminal*);
int obtener_todos_los_datos_de_la_interfaz(int, Terminal*);
void imprimir_informacion_de_terminal(Terminal);
int obtener_cantidad_de_hosts(Terminal);

#endif // __TERMINAL_H_
