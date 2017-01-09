#include <stdint.h>
#include <iostream>
#include<pthread.h>
#include <ctime>
#include<iomanip>
#include<fstream>
#include<Windows.h>
#include <stdint.h>
#define TIMER_INIT \
    LARGE_INTEGER frequency; \
    LARGE_INTEGER t1,t2; \
    double elapsedTime; \
    QueryPerformanceFrequency(&frequency);
#define TIMER_START QueryPerformanceCounter(&t1);
#define TIMER_STOP \
    QueryPerformanceCounter(&t2); \
    elapsedTime=(float)(t2.QuadPart-t1.QuadPart)/frequency.QuadPart; \
    time_log(elapsedTime);
const int ENCRYPT = 1, DECRYPT = 0, NUM_THREADS = 4;
unsigned long mem[10000], y = 0;
long len = 0, clen, i, psize = 0, pos = 0, var = 0, flag;
uint32_t* Tkey, k[4];
using namespace std;
unsigned char *data = (unsigned char *)malloc(20971520);
uint32_t* TEAKey(char *key){
	int i = 0, j;
	char str[5] = "";
	while (i < strlen(key)) {

		for (j = 0; j < 4; j++, i++) {
			str[j] = key[i];
		}
		k[(i / 4) - 1] = (str[0] << 24) | (str[1] << 16) | (str[2] << 8) | str[3];
	}
	return k;
}

void encrypt(uint32_t* v, uint32_t* k) {
	uint32_t v0 = v[0], v1 = v[1], sum = 0, i; /* set up */
	uint32_t delta = 0x9e3779b9; /* a key schedule constant */
	uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3]; /* cache key */
	for (i = 0; i < 32; i++) { /* basic cycle start */
		sum += delta;
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
	} /* end cycle */
	v[0] = v0;
	v[1] = v1;
}

void decrypt(uint32_t* v, uint32_t* k) {
	uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i; /* set up */
	uint32_t delta = 0x9e3779b9; /* a key schedule constant */
	uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3]; /* cache key */
	for (i = 0; i < 32; i++) { /* basic cycle start */
		v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
		v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		sum -= delta;
	} /* end cycle */
	v[0] = v0;
	v[1] = v1;
}
void smpEncrypt(unsigned char * buffer)
{
	uint32_t datablock[2];
	datablock[0] = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3]);
	datablock[1] = (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | (buffer[7]);
	encrypt(datablock, Tkey);
	buffer[0] = (char)((datablock[0] >> 24) & 0xFF);
	buffer[1] = (char)((datablock[0] >> 16) & 0xFF);
	buffer[2] = (char)((datablock[0] >> 8) & 0xFF);
	buffer[3] = (char)((datablock[0]) & 0xFF);
	buffer[4] = (char)((datablock[1] >> 24) & 0xFF);
	buffer[5] = (char)((datablock[1] >> 16) & 0xFF);
	buffer[6] = (char)((datablock[1] >> 8) & 0xFF);
	buffer[7] = (char)((datablock[1]) & 0xFF);
}
void smpDecrypt(unsigned char * buffer)
{
	uint32_t datablock[2];
	datablock[0] = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3]);
	datablock[1] = (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | (buffer[7]);
	decrypt(datablock, Tkey);
	buffer[0] = (char)((datablock[0] >> 24) & 0xFF);
	buffer[1] = (char)((datablock[0] >> 16) & 0xFF);
	buffer[2] = (char)((datablock[0] >> 8) & 0xFF);
	buffer[3] = (char)((datablock[0]) & 0xFF);
	buffer[4] = (char)((datablock[1] >> 24) & 0xFF);
	buffer[5] = (char)((datablock[1] >> 16) & 0xFF);
	buffer[6] = (char)((datablock[1] >> 8) & 0xFF);
	buffer[7] = (char)((datablock[1]) & 0xFF);
}


void *BlockTEA(void *d)
{
	unsigned char str[9] = "", s[9] = "";
	long i = 0, j, m = 0;
	
	long start = (long)d*clen, end = start + clen;
	unsigned char *cdata = (unsigned char *)malloc(5242880);
	for (long k = start, m = 0; k < end; k++, m++)
		cdata[m] = data[k];
	while (i < clen)
	{
		for (j = 0; j < 8; j++, i++)
			str[j] = cdata[i];
		if (flag)
			smpEncrypt(str);
		else
			smpDecrypt(str);
		for (j = 0; j < 8; j++, m++)
		{
			if (str[j] == NULL) //compairing to null
			{
				//cout << "is_null" << endl;
				data[m] = '0';
				mem[pos] = m;
				pos++;
			}
			else
				cdata[m] = str[j];
		}
	}
	for (int k = start, m = 0; k < end; k++, m++)
		data[k] = cdata[m];
	pthread_exit(NULL);
	return (void *)cdata;
}

void getData(unsigned char *data, char *f)
{
	i = 0; char d;
	ifstream fin;
	fin.open(f);
	if (fin.is_open())
	{
		while (fin.get(d))
		{
			data[i] = d;
			i++;
		}
		if (flag)
			len = i;
	}
	else
		cout << "File could not be opened." << endl;
	//padding
	cout << "length::" << len << endl;
	cout << "flag::" << flag << endl;

	if (flag){
		if (len % 8)
		{
			psize = 8 - len % 8;
			cout << "padsize : " << psize << endl;
			for (int j = 0; j < psize; j++, i++)
				data[i] = '1';
			len += psize;
		}
	}
	fin.close();
}
void time_log(double p)
{
	ofstream t_log;
	t_log.open("Tlog.txt", std::ios::app);
	auto t = std::time(nullptr);
	auto tm = *std::localtime(&t);
	t_log << put_time(&tm, "%d-%m-%Y %H-%M-%S") << " :: " << flag << " length : " << len << " number of threads : " << NUM_THREADS << " time elapsed :" << p << endl;
}
void setData(unsigned char *data, char *f)
{
	ofstream fout; char d = ' '; int l;
	if (flag)
		l = len;
	else
		l = len - psize;
	fout.open(f);
	if (fout.is_open())
	{
		for (i = 0; i < l; i++)
		{

			fout.put(data[i]);
		}
	}
	else
		cout << "File could not be opened." << endl;
	fout.close();
}
void *prtData(void *d)
{
	int start = (int)d*clen, end = start + clen;
	unsigned char cdata[8];
	for (int k = start, m = 0; k < end; k++, m++)
		cdata[m] = data[k];
	pthread_exit((void *)cdata);
	return (void *)cdata;
}

int main() {
	pthread_t threads[NUM_THREADS];
	int j = 0, rc[NUM_THREADS];
	char *fname = "twentymb.txt";
	char  key[17] = "abcdefghijklmnop";
	Tkey = TEAKey(key);
	flag = ENCRYPT;
	getData(data, fname);
	TIMER_INIT
	{
		TIMER_START

	clen = len / NUM_THREADS;
		cout << "clen" << clen;
	for (int t = 0; t < NUM_THREADS; t++)
	{
		rc[t] = pthread_create(&threads[t], NULL, BlockTEA, (void *)t);
		if (rc[t]){
			printf("ERROR; return code from pthread_create() is %d\n", rc);
			exit(-1);
		}
	}
	for (int k = 0; k < NUM_THREADS; k++)
	{
		int rc = pthread_join(threads[k], NULL);
	}
	TIMER_STOP
	}
	//setData(data,"a.txt");


	//decrypting

//			getData(dat, "a.txt");
	{
		TIMER_START
	flag = DECRYPT;
	for (int t = 0; t < NUM_THREADS; t++)
	{
		rc[t] = pthread_create(&threads[t], NULL, BlockTEA, (void *)t);
		if (rc[t]){
			printf("ERROR; return code from pthread_create() is %d\n", rc);
			exit(-1);
		}
	}
	for (int k = 0; k < NUM_THREADS; k++)
	{
		int rc = pthread_join(threads[k], NULL);
	}
	TIMER_STOP
	}
	//setData(data, "a.txt");
	
	system("PAUSE");
	pthread_exit(NULL);
}