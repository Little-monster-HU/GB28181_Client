#include <eXosip2/eXosip.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
 
int main(int argc, char *argv[])
{
 
	struct eXosip_t *context_eXosip;
 
	eXosip_event_t *je;
	osip_message_t *reg = NULL;
	osip_message_t *invite = NULL;
	osip_message_t *ack = NULL;
	osip_message_t *info = NULL;
	osip_message_t *message = NULL;
 
	int call_id, dialog_id;
	int i, flag;
	int flag1 = 1;
 
	char *identity = "sip:140@192.168.0.115";   //UAC1，端口是15060
	char *registar = "sip:133@192.168.0.115:15061"; //UAS,端口是15061
	char *source_call = "sip:140@192.168.0.115";
	char *dest_call = "sip:814@192.168.0.103:15061";
	//identify和register这一组地址是和source和destination地址相同的
	//在这个例子中，uac和uas通信，则source就是自己的地址，而目的地址就是uac1的地址
	char command;
	char tmp[4096];
 
	printf("r   向服务器注册\n\n");
	printf("c   取消注册\n\n");
	printf("i   发起呼叫请求\n\n");
	printf("h   挂断\n\n");
	printf("q   推出程序\n\n");
	printf("s   执行方法INFO\n\n");
	printf("m   执行方法MESSAGE\n\n");
 
	//初始化
	struct eXosip_t *excontext;
	excontext = eXosip_malloc();
	i = eXosip_init(excontext);
 
	if (i != 0)
	{
		printf("Couldn't initialize eXosip!\n");
		osip_free(excontext);
		return -1;
	}
	else
	{
		printf("eXosip_init successfully!\n");
	}
 
	//绑定uac自己的端口15060，并进行端口监听
	i = eXosip_listen_addr(excontext, IPPROTO_UDP, NULL, 15060, AF_INET, 0);
	if (i != 0)
	{
		eXosip_quit(excontext);
		fprintf(stderr, "Couldn't initialize transport layer!\n");
		osip_free(excontext);
		return -1;
	}
	flag = 1;
 
	while (flag)
	{
		//输入命令
		printf("Please input the command:\n");
		scanf_s("%c", &command);
		getchar();
 
		switch (command)
		{
		case 'r':
			printf("This modal is not completed!\n");
			break;
		case 'i'://INVITE，发起呼叫请求
			i = eXosip_call_build_initial_invite(excontext, &invite, dest_call, source_call, NULL, "This is a call for conversation");
			if (i != 0)
			{
				printf("Initial INVITE failed!\n");
				break;
			}
			//符合SDP格式，其中属性a是自定义格式，也就是说可以存放自己的信息，
			//但是只能有两列，比如帐户信息
			//但是经过测试，格式vot必不可少，原因未知，估计是协议栈在传输时需要检查的
			_snprintf_s(tmp, 4096,
				"v=0\r\n"
				"o=anonymous 0 0 IN IP4 0.0.0.0\r\n"
				"t=0 0\r\n"
				"m=audio 62100 RTP/AVP 114 0 8 101\r\n"
				"a=rtpmap:114 AMR/8000\r\n"
				"a=fmtp:114 octet-align=1;mode-set=7,0\r\n"
				"a=rtpmap:0 PCMU/8000\r\n"
				"a=rtpmap:8 PCMA/8000\r\n"
				"m=video 62102 RTP/AVP 102 99\r\n"
				"a=rtpmap:102 H264/90000\r\n"
				"a=rtpmap:99 MP4V-ES/90000\r\n"
				);
 
			osip_message_set_body(invite, tmp, strlen(tmp));
			osip_message_set_content_type(invite, "application/sdp");
 
			eXosip_lock(excontext);
			i = eXosip_call_send_initial_invite(excontext, invite); //invite SIP INVITE message to send
			eXosip_unlock(excontext);
 
			//发送了INVITE消息，等待应答
			flag1 = 1;
			while (flag1)
			{
				je = eXosip_event_wait(excontext, 0, 200); //Wait for an eXosip event
				//(超时时间秒，超时时间毫秒) 
				if (je == NULL)
				{
					printf("No response or the time is over!\n");
					break;
				}
				switch (je->type)   //可能会到来的事件类型
				{
				case EXOSIP_CALL_INVITE:   //收到一个INVITE请求
					printf("a new invite received!\n");
					break;
				case EXOSIP_CALL_PROCEEDING: //收到100 trying消息，表示请求正在处理中
					printf("proceeding!\n");
					break;
				case EXOSIP_CALL_RINGING:   //收到180 Ringing应答，表示接收到INVITE请求的UAS正在向被叫用户振铃
					printf("ringing!\n");
					printf("call_id is %d,dialog_id is %d \n", je->cid, je->did);
					break;
				case EXOSIP_CALL_ANSWERED: //收到200 OK，表示请求已经被成功接受，用户应答
					printf("ok!connected!\n");
					call_id = je->cid;
					dialog_id = je->did;
					printf("call_id is %d,dialog_id is %d \n", je->cid, je->did);
 
					//回送ack应答消息
					eXosip_call_build_ack(excontext, je->did, &ack);
					eXosip_call_send_ack(excontext, je->did, ack);
					flag1 = 0; //推出While循环
					break;
				case EXOSIP_CALL_CLOSED: //a BYE was received for this call
					printf("the other sid closed!\n");
					break;
				case EXOSIP_CALL_ACK: //ACK received for 200ok to INVITE 
					printf("ACK received!\n");
					break;
				default: //收到其他应答
					printf("other response!\n");
					break;
				}
				eXosip_event_free(je); //Free ressource in an eXosip event
			}
			break;
 
		case 'h':   //挂断
			printf("Holded!\n");
 
			eXosip_lock(excontext);
			eXosip_call_terminate(excontext, call_id, dialog_id);
			eXosip_unlock(excontext);
			break;
 
		case 'c':
			printf("This modal is not commpleted!\n");
			break;
 
		case 's': //传输INFO方法
			eXosip_call_build_info(excontext, dialog_id, &info);
			_snprintf_s(tmp, 4096, "\nThis is a sip message(Method:INFO)");
			osip_message_set_body(info, tmp, strlen(tmp));
			//格式可以任意设定，text/plain代表文本信息;
			osip_message_set_content_type(info, "text/plain");
			eXosip_call_send_request(excontext, dialog_id, info);
			break;
 
		case 'm':
			//传输MESSAGE方法，也就是即时消息，和INFO方法相比，我认为主要区别是：
			//MESSAGE不用建立连接，直接传输信息，而INFO消息必须在建立INVITE的基础上传输
			printf("the method : MESSAGE\n");
			eXosip_message_build_request(excontext, &message, "MESSAGE", dest_call, source_call, NULL);
			//内容，方法，      to       ，from      ，route
			_snprintf_s(tmp, 4096, "This is a sip message(Method:MESSAGE)");
			osip_message_set_body(message, tmp, strlen(tmp));
			//假设格式是xml
			osip_message_set_content_type(message, "text/xml");
			eXosip_message_send_request(excontext, message);
			break;
 
		case 'q':
			eXosip_quit(excontext);
			printf("Exit the setup!\n");
			flag = 0;
			break;
		}
	}
	osip_free(excontext);
	return(0);
}
 
 
