#pragma once

typedef unsigned char byte;

void imprimir_ip(byte*);
void imprimir_arreglo(byte*, int);
void imprimir_mac(byte*);
void imprimir_trama(byte*, int);

void sumar_uno(byte* ip, int posicion_bit);

char* pedir_dispositivo_red();
