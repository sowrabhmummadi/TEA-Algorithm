#include <stdint.h>
#include <iostream>
#include <ctime>
#include<iomanip>
#include<mpi.h>
#include<fstream>
#include<Windows.h>
const int ENCRYPT = 1, DECRYPT = 0;
unsigned long mem[100000], y = 0;
int len = 0, i, psize = 0, pos = 0, var = 0, flag,np;
uint32_t* Tkey, k[4];
using namespace std;
class TEA
{
public:
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
	void BlockTEA(unsigned char *d, char flag, int l)
	{
		unsigned char str[9] = "", s[9] = "";
		int i = 0, j, m = 0;

		while (i < l) {
			for (j = 0; j < 8; j++, i++)
			{

				str[j] = d[i];
				s[j] = d[i];

			}
			if (flag)
				smpEncrypt(str);
			else
				smpDecrypt(str);
			for (j = 0; j < 8; j++, m++)
			{
				if (str[j] == NULL) //compairing to null
				{
					//cout << "is_null" << endl;
					d[m] = '0';
					mem[pos] = m;
					pos++;
				}
				else
					d[m] = str[j];
			}
		}
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

		if (flag){ //trixiiieeee
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
		t_log << put_time(&tm, "%d-%m-%Y %H-%M-%S") << " :: " << flag << " length : " << len << " num of processes : " << np << " time elapsed :" << p << endl;
	}
	void setData(unsigned char *data, char *f)
	{
		char d = ' '; int l;
		ofstream fout;
		if (flag)
			l = len;
		else
			l = len - psize;
		fout.open(f);
		if (fout.is_open())
		{
			for (int i = 0; i < l; i++)
			{

				fout.put(data[i]);
			}
		}
		else
			cout << "File could not be opened." << endl;
		fout.close();

	}
private:
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

};
int main() {
	TEA tea;
	int nop, rank;
	long clen = 0;
	double t1, t2;
	char *fname = "twentymb.txt";
	unsigned char *ldata=(unsigned char *)malloc(5242880);	
	MPI_Init(NULL, NULL);
	MPI_Comm_size(MPI_COMM_WORLD, &nop);
	np = nop;
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	char  key[17] = "abcdefghijklmnop";
	Tkey = tea.TEAKey(key);
	flag = ENCRYPT;
	if (rank == 0)
	{
		tea.getData(tea.data, fname);
		clen = len / nop;
	}
	t1 = MPI_Wtime();
	MPI_Bcast(&clen, 1, MPI_INT, 0, MPI_COMM_WORLD);
	cout << "clen :" << clen << endl;
	MPI_Scatter(tea.data, clen, MPI_UNSIGNED_CHAR, ldata, clen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
	tea.BlockTEA(ldata, flag, clen);
	MPI_Gather(ldata, clen, MPI_UNSIGNED_CHAR, tea.data, clen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
	t2 = MPI_Wtime();
	if (rank == 0)
	{
	//	tea.setData(tea.data, fname);
	}
	
	if (rank == 0)
		tea.time_log(t2 - t1);
	
	t1 = MPI_Wtime();
	flag = DECRYPT;
	MPI_Scatter(tea.data, clen, MPI_UNSIGNED_CHAR, ldata, clen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
	pos--;
	while (pos >= 0)
	{
		tea.data[mem[pos]] = NULL;
		pos--;
	}
	tea.BlockTEA(ldata, flag, clen);
	MPI_Gather(ldata, clen, MPI_UNSIGNED_CHAR, tea.data, clen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
	t2 = MPI_Wtime();
	if (rank == 0)
	{
	//	tea.setData(tea.data, fname);

	}
	//memset(tea.data, 0, 1000 * (sizeof tea.data[0]));
	cout << "done";	
	if (rank==0)
		tea.time_log(t2-t1);
	MPI_Finalize();
}