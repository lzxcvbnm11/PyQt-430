#include <stdio.h>
#include <stdlib.h>

#define PY_SERIAL_NAME "py_serial.py"
#define COM_TX_FILE "com_tx_data"
#define COM_RX_FILE "com_rx_data"


static char tx_buf[64] = {0xff, 0xff, 0xff,  0xfe, 0x00, 0x00, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x1f};
static char rx_buf[64] = {0xff, 0xff, 0xff,  0xfe, 0x00, 0x00, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x1f};

void get_tx_buf(char *py_tx_buf,int len)
{
	FILE *p_f_com_tx = NULL;
	int i = 0;
	p_f_com_tx = fopen("COM_TX_FILE","r");
	if( p_f_com_tx == NULL)
	{
		printf("open com_tx_data file fail\r\n");
		return;
	}
	fread(tx_buf,1,len,p_f_com_tx);
	fclose(p_f_com_tx);
	
	for(i=0;i<len;i++)
	{
		py_tx_buf[i] = tx_buf[i];
		//printf("--py_tx_buf[%d]-%x\r\n",i,py_tx_buf[i]);
	}
}
void set_rx_buf(char *py_rx_buf,int len)
{
	int i = 0;
	FILE *f = NULL,*p_f_com_rx = NULL ,*p_f_com_tx = NULL;
	p_f_com_rx = fopen("COM_RX_FILE","w");
	if( p_f_com_rx == NULL)
	{
		printf("open com_rx_data file fail\r\n");
		return;
	}
	
	for(i=0;i<len;i++)
	{
		rx_buf[i] = py_rx_buf[i];
	}
	
	fwrite(rx_buf,1,len,p_f_com_rx);
	fclose(p_f_com_rx);	
}

struct test_Tag
{
	int a;
	int b;
};

int add_int(int, int);
float add_float(float, float);

void test_change_int(int *a)
{
	a[0] = 5;
	a[1] = 6;
}

void add_test_st(struct test_Tag test_st_tmp)
{
	test_st_tmp.a = 0;
}

int add_test(int num1,int mum2)
{
	return (num1 + mum2);
}

int add_int(int num1, int num2){
	
	printf("test");
	num1 = add_test(num1,num2);
    return num1 + num2;

}

float add_float(float num1, float num2){
    return num1 + num2;

}

int py_serial_read(int reg)
{
	FILE *f = NULL,*p_f_com_rx = NULL ,*p_f_com_tx = NULL;
	char s[1024];
	int ret,len,i;
	char py_param[32] = {0};
	
	/**/
	tx_buf[5] = reg;
	tx_buf[13] = reg;
	len = 16;
	
	p_f_com_tx = fopen("COM_TX_FILE","w");
	if( p_f_com_tx == NULL)
	{
		printf("open com_tx_data file fail\r\n");
		return -1;
	}
	for(i=0;i<len;i++)
	{
		//printf("main tx_buf[%d] = %x\r\n",i,tx_buf[i]);
	}
	fwrite(tx_buf,1,len,p_f_com_tx);
	fclose(p_f_com_tx);
	
	sprintf(py_param,"%s %d",PY_SERIAL_NAME,len);
	printf("%s\r\n",py_param);
	f = popen(py_param, "r");
	if(f == NULL)
	{
		printf("open error\r\n");
		return -1;
	}
	
	while((ret=fread(s,1,1024,f))>0) {
			fwrite(s,1,ret,stdout);
	}
	
	p_f_com_rx = fopen("COM_RX_FILE","r");
	if( p_f_com_rx == NULL)
	{
		printf("open com_tx_data file fail\r\n");
		return -1;
	}
	len = fread(rx_buf,1,64,p_f_com_rx);
	fclose(p_f_com_rx);
	//printf("rx_buf len = %d\n",len);
	for(i = 0;i<len;i++)
	{
		printf("rx_buf[%d] = %x",i,rx_buf[i]);
	}
	
	
	fclose(f);

	return 0;
}