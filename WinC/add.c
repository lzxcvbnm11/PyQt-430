#include <stdio.h>
#include <stdlib.h>
#include <python.h>

#include<winsock2.h> 
#pragma comment(lib, "ws2_32.lib")
#define PY_SERIAL_NAME "py_serial.py"
#define COM_TX_FILE "com_tx_data"
#define COM_RX_FILE "com_rx_data"


static char tx_buf[64] = {0xff, 0xff, 0xff,  0xfe, 0x00, 0x00, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x1f};
static char rx_buf[64] = {0xff, 0xff, 0xff,  0xfe, 0x00, 0x00, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x1f};
static char host_ip[17] = {0};
static SOCKET client_socket_fd = -1;
static int open_socket_flag = 0; 
void py_udp_ip_set(unsigned char *ip_addr)
{
	int i = 0;
	sprintf(host_ip,"%d.%d.%d.%d",ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);
	printf("host ip = %s \r\n",host_ip);
}
int udp_test(char *buf,int len)
{
	
	
	WORD socketVersion = MAKEWORD(2,2);
    WSADATA wsaData; 
    if(WSAStartup(socketVersion, &wsaData) != 0)
    {
		printf("this is version not ok ---------\r\n");
        return 0;
    }
	{ 
 /* 服务端地址 */
	 struct sockaddr_in server_addr; 
	 memset(&server_addr, 0,sizeof(server_addr)); 
	 server_addr.sin_family = AF_INET; 
	 server_addr.sin_addr.s_addr = inet_addr(host_ip);//INADDR_ANY; 
	 server_addr.sin_port = htons(50007); 
	  
	 /* 创建socket */
	 if(open_socket_flag == 0)
	 {
		printf("creat udp socket \r\n");
		open_socket_flag = 1;
		client_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	 }
	 
	 printf("----sockfd = %d----------\r\n",client_socket_fd);
	 if(client_socket_fd < 0) 
	 { 
	  perror("Create Socket Failed:"); 
	  exit(1); 
	 } 
	  
	 /* 发送文件名 */
	 if(client_socket_fd > 0)
	 {
		 if(sendto(client_socket_fd, buf, len,0,(struct sockaddr*)&server_addr,sizeof(server_addr)) < 0) 
		 { 
		  perror("Send File Name Failed:"); 
		  exit(1); 
		 } 
	 }
	 
	  
	 return 0; 
	}
}
void run_python(void)
{
	printf("run_python\n");
	Py_Initialize();

	printf("Py_Initialize\n");
	//Py_SetProgramName("seri");

	printf("Py_SetProgramNameaaa\n");
	PyRun_SimpleString("import sys");
	printf("PyRun_SimpleString\n");
	PyRun_SimpleString("a = 1 + 2");
	PyRun_SimpleString("print(\"Hello Python! =\",a)");
	printf("PyRun_SimpleString\n");
	Py_Finalize();

	printf("Py_Finalize\n");
}


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
	udp_test(tx_buf,16);

	
	p_f_com_rx = fopen("COM_RX_FILE","r");
	if( p_f_com_rx == NULL)
	{
		printf("open com_tx_data file fail\r\n");
		return -1;
	}
	len = fread(rx_buf,1,64,p_f_com_rx);
	fclose(p_f_com_rx);
	//printf("rx_buf len = %d\n",len);
	if(client_socket_fd > 0)
	{
		ret = recv(client_socket_fd, s, 64, 0);
	}
	else
	{
		printf("recvfrom error sockfd is invild");
	}
	
	for(i = 0;i<16;i++)
	{
		printf("--rx_buf[%d]-- = %02x\r\n",i,s[i]);
	}

	return 0;
}