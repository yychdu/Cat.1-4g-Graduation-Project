/*
 * @Author: your name
 * @Date: 2020-05-19 14:05:32
 * @LastEditTime: 2020-05-31 18:58:02
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: \RDA8910_CSDK\USER\user_main.c
 * 下载成功jpg
 * 
 */

#include "string.h"
#include "cs_types.h"

#include "osi_log.h"
#include "osi_api.h"

#include "am_openat.h"
#include "am_openat_vat.h"
#include "am_openat_common.h"

#include "iot_debug.h"
#include "iot_uart.h"
#include "iot_os.h"
#include "iot_gpio.h"
#include "iot_pmd.h"
#include "iot_adc.h"
#include "iot_vat.h"
#include "iot_network.h"
#include "iot_socket.h"

#include "http_client.h"
#include "iot_fs.h"
#include "iot_flash.h"
#include <stdio.h>
#include "string.h"
#include "at_process.h"
#include "at_tok.h"


#include "HTTPClient.h"
#include "am_openat_httpclient.h"

#define fs_print iot_debug_print
#define DEMO_FS_FILE_PATH "demo_file"
#define DEMO_FS_FILE_PATH_SDCARD "/sdcard0/demo_file.mp3"
HANDLE TestTask_HANDLE = NULL;
uint8 NetWorkCbMessage = 0;
int socketfd = -1;
int ConnectionFlags = 0;
http_client_handle_t client_handle_t = {0};


#define SOCKET_MSG_NETWORK_READY (0)
#define SOCKET_MSG_NETWORK_LINKED (1)
#define HEAD_ACCEPT_KEY "Accept"
#define HEAD_ACCEPT_VALUE "*/*"
#define HEAD_ACCEPT_L_KEY "Accept-Language"
#define HEAD_ACCEPT_L_VALUE "cn"
#define HEAD_USER_KEY "User-Agent"
#define HEAD_USER_VALUE "*Mozilla/4.0"
#define HEAD_CONNECTION_KEY "Connection"
#define HEAD_CONNECTION_VALUE "Keep-Alive"


#define TCP_SERVER_IP "106.13.16.6"
#define TCP_SERVER_PORT 3200

typedef struct {
    UINT8 type;
    UINT8 data;
}DEMO_NETWORK_MESSAGE;


typedef struct {
  UINT8 num;
  char log[100];
} WIFILOG;

static HANDLE g_s_http_task;
static char WIFILOC_IMEI[16] = {0};
static int cellid;  //cell ID
static int lac;  //LAC
static int mcc;  //MCC
static int mnc;  //MNC
bool NetLink = FALSE;
CHAR readBuff[1460];
WIFILOG wifi_log[10] = {0};


HANDLE uart_task_handle;

#define uart_print iot_debug_print
#define UART_PORT1 OPENAT_UART_1
#define UART_PORT2 OPENAT_UART_2
#define UART_USB   OPENAT_UART_USB
#define UART_RECV_TIMEOUT (5 * 1000) // 2S

typedef enum
{
    UART_RECV_MSG = 1,

}TASK_MSG_ID;

typedef struct
{
    TASK_MSG_ID id;
    UINT32 len;
    char *param;
}TASK_MSG;

char HexChar(char c)
{

	if ((c >= '0') && (c <= '9'))
		return c-'0';//16进制中的，字符0-9转化成10进制，还是0-9
	else if ((c >= 'A') && (c <= 'F'))
		return c-'A'+10;//16进制中的A-F，分别对应着11-16
	else if ((c >= 'a') && (c <= 'f'))
		return c - 'a' + 10; //16进制中的a-f，分别对应也是11-16，不区分大小写
	else
        return 0x10;   // 其他返回0x10
}

int Str2Hex(char* str, char *data)

{
	int t, t1;
	int rlen = 0, len = strlen(str);
	if (len == 1)
	{
		char h = str[0];
		t = HexChar(h);
		data[0] = (char)t;
		rlen++;
	}
	for (int i = 0; i < len;)
	{
		char l, h = str[i];//高八位和低八位
		i++;
		if (h == ' ')
            continue;
		if (i >= len)
			break;
		l = str[i];
		// if (str[i] == '0' && str[i - 1] == '0')
		// {
		// 	data[rlen++] = 0;//0 也是 '\0'到这里就结束了
		// 	i++;
		// 	continue;
		// }
		t = HexChar(h);
		t1 = HexChar(l);
		if ((t == 0x10) || (t1 == 0x10)) //判断为非法的16进制数
			break;
        else
			t = t * 16 + t1;
		i++;
		data[rlen] = (char)t;
		rlen++;
	}
	return rlen;
}

 
VOID uart_msg_send(HANDLE hTask, TASK_MSG_ID id, VOID *param, UINT32 len)
{
    TASK_MSG *msg = NULL;

    msg = (TASK_MSG *)iot_os_malloc(sizeof(TASK_MSG));
    msg->id = id;
    msg->param = param;
    msg->len = len;

    iot_os_send_message(hTask, msg);
}

//中断方式读串口1数据
//注: 中断中有复杂的逻辑,要发送消息到task中处理
void uart_recv_handle(T_AMOPENAT_UART_MESSAGE* evt)
{
	INT8 *recv_buff = NULL;
    int32 recv_len;
    int32 dataLen = evt->param.dataLen;
	if(dataLen)
	{
		recv_buff = iot_os_malloc(dataLen);
		if(recv_buff == NULL)
		{
			iot_debug_print("uart_recv_handle_0 recv_buff malloc fail %d", dataLen);
		}	
		switch(evt->evtId)
		{
		    case OPENAT_DRV_EVT_UART_RX_DATA_IND:

		        recv_len = iot_uart_read(UART_PORT2, (UINT8*)recv_buff, dataLen , UART_RECV_TIMEOUT);
		        iot_debug_print("uart_recv_handle_1:recv_len %d", recv_len);
				uart_msg_send(uart_task_handle, UART_RECV_MSG, recv_buff, recv_len);
		        break;

		    case OPENAT_DRV_EVT_UART_TX_DONE_IND:
		        iot_debug_print("uart_recv_handle_2 OPENAT_DRV_EVT_UART_TX_DONE_IND");
		        break;
		    default:
		        break;
		}
	}
}

VOID uart_write(VOID)
{
	
    char write_buff[] = "01 03 00 00 00 02 C4 0B";
	char trans_buff[100] = {0};
	int32 write_len = Str2Hex(write_buff, trans_buff);
	iot_uart_write(UART_PORT2, (UINT8 *)trans_buff, 8);
	// iot_debug_print("[uart]send ok");
}

VOID uart_open(VOID)
{
    BOOL err;
    T_AMOPENAT_UART_PARAM uartCfg;
    
    memset(&uartCfg, 0, sizeof(T_AMOPENAT_UART_PARAM));
    uartCfg.baud = OPENAT_UART_BAUD_9600; //波特率
    uartCfg.dataBits = 8;   //数据位
    uartCfg.stopBits = 1; // 停止位
    uartCfg.parity = OPENAT_UART_NO_PARITY; // 无校验
    uartCfg.flowControl = OPENAT_UART_FLOWCONTROL_NONE; //无流控
    uartCfg.txDoneReport = TRUE; // 设置TURE可以在回调函数中收到OPENAT_DRV_EVT_UART_TX_DONE_IND
    uartCfg.uartMsgHande = uart_recv_handle; //回调函数

    // 配置uart1 使用中断方式读数据
    err = iot_uart_open(UART_PORT2, &uartCfg);
	iot_debug_print("[uart] uart_open_2 err: %d", err);

	uartCfg.txDoneReport = FALSE;
	uartCfg.uartMsgHande = NULL;
	err = iot_uart_open(UART_USB, &uartCfg);
	iot_debug_print("[uart] uart_open_usb err: %d", err);
}

VOID uart_close(VOID)
{
    iot_uart_close(UART_PORT2);
    iot_uart_close(UART_USB);
    iot_debug_print("[uart] uart_close_1");
}

VOID uart_init(VOID)
{   
    uart_open(); // 打开串口1和串口2 (串口1中断方式读数据, 串口2轮训方式读数据)
}

static VOID uart_task_main(PVOID pParameter)
{
	TASK_MSG *msg = NULL;
	bool flag = TRUE;
	char res[1024] = "";
	char *message = res;
	char *head = res;
	float temp, Hum;
  char str[1024];
	while(1)
	{
		if (flag)
		{
			int i = 10;
			while (--i)
				{
					uart_write();
					iot_os_sleep(1000);
				}
			flag = FALSE;
		}
		iot_os_wait_message(uart_task_handle, (PVOID*)&msg);
		switch(msg->id)
	    {
	        case UART_RECV_MSG:
				memset(res, 0, sizeof(res));
				message = head;
				// iot_debug_print("[uart] uart_task_main_1 recv_len %s", msg->param);
				for (int i = 0; i < 9; i++)
				{
					sprintf(message,"%02x ", msg->param[i]);
					message += 2;
				}
				*message = '\0';
				iot_debug_print("[uart] recv_msg %s", head);
				temp = (HexChar(head[6])) * 16 * 16 * 16 + (HexChar(head[7])) * 16 * 16 + (HexChar(head[8]))* 16 + HexChar(head[9]);
				temp /= 100;
				Hum = HexChar(head[10]) * 16 * 16 * 16 + HexChar(head[11]) * 16 * 16 + HexChar(head[12] - 0)* 16 + HexChar(head[13]);
				Hum /= 100;
				iot_debug_print("[uart] temp = %.2f, Hum = %.2f", temp, Hum);
				memset(str, 0, sizeof(str));
				sprintf(str, "temp = %.2f, Hum = %.2f", temp, Hum);
				if (ConnectionFlags)
					send(socketfd, str, strlen(str), 0);
				break;
	        default:
	            break;
	    }

	    if(msg)
	    {
	        if(msg->param)
	        {
	            iot_os_free(msg->param);
	            msg->param = NULL;
	        }
	        iot_os_free(msg);
	        msg = NULL;
			iot_debug_print("[uart] uart_task_main_2 uart free");
	    }
		uart_write(); //串口2 写数据
	}
}
//Tcp Client Demo
bool Play = FALSE;


static void SentTask(void *param)
{
	uint8 num = 0;
	int len = 0;
	char data[512] = {0};
  send(socketfd, readBuff, strlen(readBuff) + 1, 0);
  for (int i = 0; i < 10; i++)
  {
    send(socketfd, wifi_log[i].log, 100, 0);
    iot_os_sleep(500);
  }

	// while (1)
	// {
	// 	if (socketfd >= 0)
	// 	{
	// 		len = sprintf(data, "RDA8910 Sent:%d", num);
	// 		data[len] = '\0';
	// 		iot_debug_print(data);
	// 		if (len > 0)
	// 		{
	// 			// TCP 发送数据
	// 			len = send(socketfd, data, len + 1, 0);
	// 			if (len < 0)
	// 				iot_debug_print("[socket] tcp send data False");
	// 			else
	// 			{
	// 				// iot_debug_print("[socket] tcp send data Len = %d", len);
	// 				num += 1;
	// 			}
	// 		}
	// 	}
	// 	iot_os_sleep(3000);
	// }
}

static void RecvTask(void *param)
{
	int len = 0;
	unsigned char data[512] = {0};
	while (1)
	{
		if (socketfd >= 0)
		{
			// TCP 接受数据
			len = recv(socketfd, data, sizeof(data), 0);
			if (len < 0)
			{
				iot_debug_print("[socket] tcp send data False");
			}
			else
			{
				iot_debug_print("[socket] tcp Recv data result = %s", data);
        if (strncmp(data, "play", 4) == 0)
          Play = TRUE;
			}
		}
	}
}
static void TcpConnect()
{
	//创建套接字
	socketfd = socket(OPENAT_AF_INET, OPENAT_SOCK_STREAM, 0);
	while (socketfd < 0)
	{
		iot_debug_print("[socket] create tcp socket error");
		iot_os_sleep(3000);
	}
	// 建立TCP链接
	struct openat_sockaddr_in tcp_server_addr = {0};
	//AF_INET 的目的就是使用 IPv4 进行通信
	tcp_server_addr.sin_family = OPENAT_AF_INET;
	//远端端口，主机字节顺序转变成网络字节顺序
	tcp_server_addr.sin_port = htons((unsigned short)TCP_SERVER_PORT);
	//字符串远端ip转化为网络序列ip
	inet_aton(TCP_SERVER_IP, &tcp_server_addr.sin_addr);
	iot_debug_print("[socket] tcp connect to addr %s", TCP_SERVER_IP);
	int connErr = connect(socketfd, (const struct openat_sockaddr *)&tcp_server_addr, sizeof(struct openat_sockaddr));
	if (connErr < 0)
	{
		iot_debug_print("[socket] tcp connect error %d", socket_errno(socketfd));
		close(socketfd);
	}
  ConnectionFlags = 1;
  iot_debug_print("[socket] tcp connect success");

	iot_os_create_task(SentTask, NULL, 2048, 10, OPENAT_OS_CREATE_DEFAULT, "SentTask");
	iot_os_create_task(RecvTask, NULL, 2048, 10, OPENAT_OS_CREATE_DEFAULT, "RecvTask");
}

static bool gsmGetIMEI(char* imeiOut)
{
    int err;
    ATResponse *p_response = NULL;
    char* line = NULL;
    //UINT8 index = 0;
    bool result = FALSE;
    if(!imeiOut)
    {
      return result;
    }

    err = at_send_command_numeric("AT+GSN", &p_response);
    if (err < 0 || p_response->success == 0){
      result = FALSE;
      goto end;
    }

    line = p_response->p_intermediates->line;

    {
      strcpy(imeiOut,line);
    }
    result = TRUE;
  end:
    at_response_free(p_response);
    return result;

}

static BOOL gsmGetCellInfo(int* mcc,int* mnc,int* lac,int* ci)
{
    ATResponse *p_response = NULL;
    bool result = FALSE;
	bool   lte;
	int i;
	char* out;

	//+CCED:GSM current cell info:460,00,550b,3c94,26,37,37,13
	//+CCED:LTE current cell:460,00,460045353407374,0,8,n50,3683,139024552,57,19,21771,42,471
	
    int err = at_send_command_singleline("AT+CCED=0,1", "+CCED:", &p_response);
    if (err < 0 || p_response->success == 0)
    {
        iot_debug_print("[iot_network] at_send_command_singleline error %d",__LINE__);
        goto end;
    }
    char* line = p_response->p_intermediates->line;  
    err = at_tok_start(&line);
    if (err < 0)
        goto end;
	if(strstr(line, "GSM"))
	{
		lte = FALSE;
	}
	else
	{
		lte = TRUE;
	}
    err = at_tok_start(&line);
	if (err < 0)
        goto end;
	err = at_tok_nextint(&line, mcc);
    if (err < 0)
        goto end;
	err = at_tok_nextint(&line, mnc);
    if (err < 0)
        goto end;
	if(lte)
	{			
		for(i = 0; i < 5; i++)
		{
			at_tok_nextstr(&line, &out);
		}
		err = at_tok_nextint(&line, ci);
		if (err < 0)
        	goto end;
		for(i = 0; i < 2; i++)
		{
			at_tok_nextstr(&line, &out);
		}
		err = at_tok_nextint(&line, lac);
		if (err < 0)
        	goto end;
	}
	else
	{			
		err = at_tok_nexthexint(&line, &lac);
	    if (err < 0)
        	goto end;
		err = at_tok_nexthexint(&line, &ci);
	    if (err < 0)
        	goto end;
	}
    result = TRUE;
end:              
    if(p_response!=NULL)
    {
        at_response_free(p_response);
        p_response=NULL;
    }  
    return result;
}

static void get_wifilocinfo(CHAR* http_url)
{
	CHAR* p = NULL;
  char str[100] = {0};
	p = http_url;
	p += sprintf(p,"http://bs.openluat.com/cps_all?cell=%d,%d,%d,%d,%d&macs=", mcc, mnc, lac, cellid, 0);
//---------------------------------------------WIFI------------------------------//
	OPENAT_wifiScanRequest wreq = {0};
	wreq.max = 10;
	wreq.maxtimeout = 300;
	OPENAT_wifiApInfo* aps = (OPENAT_wifiApInfo*)iot_os_malloc(wreq.max * sizeof(OPENAT_wifiApInfo));
	wreq.aps = aps;
	iot_wifi_scan(&wreq);
	for (u32 i = 0; i < wreq.found; i++)
	{
		OPENAT_wifiApInfo *w = &wreq.aps[i];
		iot_debug_print("[wifiloc] found ap - {mac address: %x%lx, rssival: %d dBm, channel: %u}",
			 w->bssid_high, w->bssid_low, w->rssival, w->channel);
    sprintf(str, "[wifiloc] found ap - {mac address: %x%lx, rssival: %d dBm, channel: %u}",
            w->bssid_high, w->bssid_low, w->rssival, w->channel);
    wifi_log[i].num = i;
    strcpy(wifi_log[i].log, str);
    memset(str, 0, sizeof(str));
    p += sprintf(p,"%x%lx,%d,;",w->bssid_high, w->bssid_low, w->rssival);
	}
	iot_os_free(aps);
	p = p - 1; 
	p += sprintf(p,"&imei=%s",WIFILOC_IMEI);
  
    //----------------------------------------------------------------------------------------//
    iot_debug_print("[wifiloc] data = %s", http_url);
}

static void wifiloc_print(char* pData)
{
	int status = -1;
	char* p = NULL;
	p = pData;
	if(!strncmp(p, "status=", strlen("status=")))
	{
		p +=  strlen("status=");
		status = atoi(&p[0]);
	}
	p += 2;
	if(0 == status )
	{
		iot_debug_print("[wifiloc]info: %s", p);
	}
	else
	{
		iot_debug_print("[wifiloc]error: %d", status);
	}

	
}

static void demo_network_connetck(void)
{
    T_OPENAT_NETWORK_CONNECT networkparam;
    
    memset(&networkparam, 0, sizeof(T_OPENAT_NETWORK_CONNECT));
    memcpy(networkparam.apn, "CMNET", strlen("CMNET"));

    iot_network_connect(&networkparam);

}

static void demo_networkIndCallBack(E_OPENAT_NETWORK_STATE state)
{
    DEMO_NETWORK_MESSAGE* msgptr = iot_os_malloc(sizeof(DEMO_NETWORK_MESSAGE));
    iot_debug_print("[wifiloc] network ind state %d", state);
    if(state == OPENAT_NETWORK_LINKED)
    {
        msgptr->type = SOCKET_MSG_NETWORK_LINKED;
        iot_os_send_message(g_s_http_task, (PVOID)msgptr);
        return;
    }
    else if(state == OPENAT_NETWORK_READY)
    {
        msgptr->type = SOCKET_MSG_NETWORK_READY;
        iot_os_send_message(g_s_http_task,(PVOID)msgptr);
        return;
    }
    iot_os_free(msgptr);
}

void http_debug(const char * fun,const char* data,UINT32 len ,char * fmt, ...)
{
  va_list ap;
  char fmtString[128] = {0};
  UINT16 fmtStrlen;
  strcat(fmtString, "[http]--");
  strcat(fmtString, fun);
  strcat(fmtString, "--");

  fmtStrlen = strlen(fmtString);
  va_start (ap, fmt);
  fmtStrlen += vsnprintf(fmtString+fmtStrlen, sizeof(fmtString)-fmtStrlen, fmt, ap);
  va_end (ap);

  if(fmtStrlen != 0)
  {
      iot_debug_print("%s", fmtString);
  }
}



void get_wifiloc(void)
{
  HTTP_SESSION_HANDLE pHTTP;
  
  UINT32 readSize = 0;
  UINT32 readTotalLen = 0;
  CHAR token[32];
  UINT32 tokenSize=32;
  UINT32 nRetCode;
  CHAR http_url[256] = {0};


  pHTTP = HTTPClientOpenRequest(0);
  
  HTTPClientSetDebugHook(pHTTP, http_debug);

  if (HTTPClientSetVerb(pHTTP,VerbGet) != HTTP_CLIENT_SUCCESS)
  {
    iot_debug_print("[wifiloc] HTTPClientSetVerb error");
    return;
  }

  if((nRetCode = HTTPClientAddRequestHeaders(pHTTP, HEAD_ACCEPT_KEY, HEAD_ACCEPT_VALUE, TRUE)) != HTTP_CLIENT_SUCCESS)
  {
    return;
  }
  if((nRetCode = HTTPClientAddRequestHeaders(pHTTP, HEAD_ACCEPT_L_KEY, HEAD_ACCEPT_L_VALUE, TRUE)) != HTTP_CLIENT_SUCCESS)
  {
    return;
  }
  if((nRetCode = HTTPClientAddRequestHeaders(pHTTP, HEAD_USER_KEY, HEAD_USER_VALUE, TRUE)) != HTTP_CLIENT_SUCCESS)
  {
    return;
  }
  if((nRetCode = HTTPClientAddRequestHeaders(pHTTP, HEAD_CONNECTION_KEY, HEAD_CONNECTION_VALUE, TRUE)) != HTTP_CLIENT_SUCCESS)
  {
    return;
  }

  get_wifilocinfo(http_url);
  
  iot_debug_print("[wifiloc] HTTPClientSendRequest enter");
  if (HTTPClientSendRequest(pHTTP,http_url, NULL, 0,TRUE,0,0) != HTTP_CLIENT_SUCCESS ) 
  {
    iot_debug_print("[wifiloc] HTTPClientSendRequest error");
    return;
  }
  iot_debug_print("[wifiloc] HTTPClientRecvResponse enter");

  if(HTTPClientRecvResponse(pHTTP,20000) != HTTP_CLIENT_SUCCESS)
  {
    iot_debug_print("[wifiloc] HTTPClientRecvResponse error");
    return;
  }
  
  if((nRetCode = HTTPClientFindFirstHeader(pHTTP, "content-length", token, &tokenSize)) != HTTP_CLIENT_SUCCESS)
  {
    iot_debug_print("[wifiloc] HTTPClientFindFirstHeader error");
    return;
  }
  else
  {
    iot_debug_print("[wifiloc] HTTPClientFindFirstHeader %d,%s", tokenSize, token);
  }
  HTTPClientFindCloseHeader(pHTTP);

  while(nRetCode == HTTP_CLIENT_SUCCESS || nRetCode != HTTP_CLIENT_EOS)
  {
      // Set the size of our buffer
      
      // Get the data
      nRetCode = HTTPClientReadData(pHTTP,readBuff,sizeof(readBuff),300,&readSize);

      readTotalLen += readSize;
      if(nRetCode != HTTP_CLIENT_SUCCESS || nRetCode == HTTP_CLIENT_EOS)
      {
        iot_debug_print("[wifiloc] HTTPClientReadData end nRetCode %d", nRetCode);
		    wifiloc_print(readBuff);
        TcpConnect();
        break;
      }

      iot_debug_print("[wifiloc] HTTPClientReadData readTotalLen %d, %d, nRetCode %d", readTotalLen, readSize, nRetCode);
  }

  if(HTTPClientCloseRequest(&pHTTP) != HTTP_CLIENT_SUCCESS)
  {
    iot_debug_print("[wifiloc] HTTPIntrnConnectionClose error");
    return;
  }
}


static void demo_http_task(PVOID pParameter)
{
    DEMO_NETWORK_MESSAGE*    msg;
    iot_debug_print("[wifiloc] wait network ready....");

    while(1)
    {
        // iot_os_wait_message(g_s_http_task, (PVOID)&msg);

        // switch(msg->type)
        switch(1)
        {
            case SOCKET_MSG_NETWORK_READY:
                iot_debug_print("[wifiloc] network connecting....");
                // demo_network_connetck();
                break;
            case SOCKET_MSG_NETWORK_LINKED:
                iot_debug_print("[wifiloc] network connected");
                gsmGetCellInfo(&mcc, &mnc, &lac, &cellid);
                iot_debug_print("[wifiloc] mnc: %d, mcc: %d, la:%d, ci:%d",mcc, mnc, lac, cellid);
                gsmGetIMEI(WIFILOC_IMEI);
                iot_debug_print("[wifiloc] WIFILOC_IMEI: %s",WIFILOC_IMEI);
                get_wifiloc();
                break;
        }

        iot_os_free(msg);
    }
}



VOID demo_fs_write(char* file, char *buf, UINT32 dataLen)
{
    INT32 fd;
    // char *write_buff = "hello world";
    INT32 write_len;
    
    fd = iot_fs_open_file(file, FS_O_RDWR);

    if (fd < 0)
    {
		fs_print("[http] write error1");
		return;
	}
	iot_fs_seek_file(fd, 0, FS_SEEK_END);
	write_len = iot_fs_write_file(fd, (UINT8 *)buf, dataLen);

    if (write_len < 0)
    {
		fs_print("[http]write error2");
		return;
	}
    
    fs_print("[http] write_len %d, write_buff %s", write_len, buf);

    iot_fs_close_file(fd);
}



BOOL fs_create_file(char *filename)
{
	INT32 fd = iot_fs_open_file(filename, FS_O_RDONLY);
    if (fd >= 0) //DEMO_FS_FILE_PATH文件存在
    {
		INT32 ret = iot_fs_delete_file(filename);
		if (ret < 0)
		{
			fs_print("[http] create error2");
			return FALSE;
		}
	}
	// 创建文件DEMO_FS_FILE_PATH
	iot_fs_create_file(filename);
	fs_print("[http] create demo_file");
	iot_fs_close_file(fd);
	return TRUE;
}


void http_cb(http_client_event *evt)
{

	demo_fs_write(DEMO_FS_FILE_PATH_SDCARD, evt->data, evt->datalen);
}

static void TestTask(void *param)
{
	// 
	while (NetLink == FALSE)
	{
		T_OPENAT_NETWORK_CONNECT networkparam = {0};
		switch (NetWorkCbMessage)
		{
		case OPENAT_NETWORK_DISCONNECT: //网络断开 表示GPRS网络不可用澹，无法进行数据连接，有可能可以打电话
			iot_debug_print("[http] OPENAT_NETWORK_DISCONNECT");
			iot_os_sleep(1000);
			break;
		case OPENAT_NETWORK_READY: //网络已连接 表示GPRS网络可用，可以进行链路激活
			iot_debug_print("[http] OPENAT_NETWORK_READY");
			memcpy(networkparam.apn, "CMNET", strlen("CMNET"));
			//建立网络连接，实际为pdp激活流程
			iot_network_connect(&networkparam);
			iot_os_sleep(500);
			break;
		case OPENAT_NETWORK_LINKED: //链路已经激活 PDP已经激活，可以通过socket接口建立数据连接
			iot_debug_print("[http] OPENAT_NETWORK_LINKED");
			NetLink = TRUE;
			break;
		}
	}
	if (!fs_create_file(DEMO_FS_FILE_PATH_SDCARD))
	{
		fs_print("[http]create file ERR");
	}
	if (NetLink == TRUE)
	{
     gsmGetCellInfo(&mcc, &mnc, &lac, &cellid);
    iot_debug_print("[wifiloc] mnc: %d, mcc: %d, la:%d, ci:%d",mcc, mnc, lac, cellid);
    gsmGetIMEI(WIFILOC_IMEI);
    iot_debug_print("[wifiloc] WIFILOC_IMEI: %s",WIFILOC_IMEI);
    get_wifiloc();
    // 
    http_client_config_t config = {0};

		config.url = "http://106.13.16.6/play.mp3";
		config.method = HTTP_METHOD_GET;

		config.event_handler = http_cb;
		//创建对象
		client_handle_t = http_client_new(&config);

		iot_debug_print("[http_client] init_state:%d", http_get_init_state(&client_handle_t));
		if (http_get_init_state(&client_handle_t) == HTTP_INIT_OK)
		{
			iot_debug_print("[http_client] perform");
			http_client_perform(&client_handle_t);//跳转播放
		}
	}
	// fs_print("[http]file size = %d", iot_fs_file_size(DEMO_FS_FILE_PATH_SDCARD));
	iot_os_delete_task(TestTask_HANDLE);
}
static void NetWorkCb(E_OPENAT_NETWORK_STATE state)
{
	NetWorkCbMessage = state;
}

void demo_http_init(void)
{ 
  iot_debug_print("[wifiloc] demo_http_init");

  //注册网络状态回调函数
  iot_network_set_cb(demo_networkIndCallBack);
 iot_debug_print("[wifiloc] demo_http_init2");
  g_s_http_task = iot_os_create_task(demo_http_task,
                      NULL,
                      4096,
                      5,
                      OPENAT_OS_CREATE_DEFAULT,
                      "demo_http");
}



//main函数
int appimg_enter(void *param)
{
  	//注册网络状态回调函数
	  iot_network_set_cb(NetWorkCb);
    //关闭看门狗，死机不会重启。默认打开
    iot_debug_set_fault_mode(OPENAT_FAULT_HANG);
    //打开调试信息，默认关闭
    iot_vat_send_cmd("AT^TRACECTRL=0,1,3\r\n", sizeof("AT^TRACECTRL=0,1,3\r\n"));
    uart_init();
    uart_task_handle =  iot_os_create_task(uart_task_main, NULL, 4096, 1, OPENAT_OS_CREATE_DEFAULT, "uart_task");       //创建串口发送和接收任务
    TestTask_HANDLE = iot_os_create_task(TestTask, NULL, 4096, 1, OPENAT_OS_CREATE_DEFAULT, "TestTask");                //创建网络服务相关任务
	  return 0;
}

//退出提示
void appimg_exit(void)
{
	OSI_LOGI(0, "application image exit");
}
