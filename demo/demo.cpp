

#include <iostream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <string.h>

#include <eXosip2/eXosip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

using namespace std;

//本地监听IP
#define LISTEN_ADDR ("192.168.35.165")
//本地监听端口
#define UAC_PORT ("5080")
#define UAC_PORTINT (5080)
#define UAS_PORT ("5080")
#define UAS_PORTINT (5080)
//本UAC地址编码
#define UACCODE ("34020000002000000001")
#define UASCODE ("34020000002000000002")
//本地UAC密码
#define UACPWD ("12345678")
//远程UAS IP
#define UAC_ADDR ("192.168.35.165")
#define UAS_ADDR ("192.168.35.106")
//远程UAS 端口
#define UAS_PORT ("5080")
//超时
#define EXPIS 300

//当前服务状态 1 已经注册 0 未注册
static int iCurrentStatus;
//注册成功HANDLE
static int iHandle = -1;
struct eXosip_t *g_exctx = NULL;

// osip_message_t *answer = NULL;
// sdp_message_t *remote_sdp = NULL;
// int call_id, dialog_id;
// char tmp[4096] = {0};

//SIP From/To 头部
class CSipFromToHeader
{
public:
    CSipFromToHeader()
    {
    }
    ~CSipFromToHeader()
    {
    }
    void SetHeader(string addrCod, string addrI, string addrPor)
    {
        addrCode = addrCod;
        addrIp = addrI;
        addrPort = addrPor;
    }
    string GetFormatHeader()
    {
        std::stringstream stream;
        stream << "sip:" << addrCode << "@" << addrIp << ":" << addrPort;
        return stream.str();
    }
    //主机名称
    string GetCode()
    {
        std::stringstream stream;
        stream << addrCode;
        return stream.str();
    }
    //主机地址
    string GetAddr()
    {
        std::stringstream stream;
        stream << addrIp;
        return stream.str();
    }
    //端口
    string GetPort()
    {
        std::stringstream stream;
        stream << addrPort;
        return stream.str();
    }

private:
    string addrCode;
    string addrIp;
    string addrPort;
};

//SIP Contract头部
class CContractHeader : public CSipFromToHeader
{
public:
    CContractHeader()
    {
    }
    ~CContractHeader()
    {
    }
    void SetContractHeader(string addrCod, string addrI, string addrPor)
    {
        SetHeader(addrCod, addrI, addrPor);
    }
    string GetContractFormatHeader()
    {

        std::stringstream stream;
        stream << "<sip:" << GetCode() << "@" << GetAddr() << "：" << GetPort()
               << ">";
        return stream.str();
    }
};

//发送注册信息
int SendRegister(int &registerId, CSipFromToHeader &from, CSipFromToHeader &to,
                 CContractHeader &contact, const string &userName, const string &pwd,
                 const int expires, int iType)
{
    cout << "=============================================" << endl;
    if (iType == 0)
    {
        cout << "注册请求信息：" << endl;
    }
    else if (iType == 1)
    {
        cout << "刷新注册信息：" << endl;
    }
    else
    {
        cout << "注销信息:" << endl;
    }
    cout << "registerId " << registerId << endl;
    cout << "from " << from.GetFormatHeader() << endl;
    cout << "to " << to.GetFormatHeader() << endl;
    cout << "contact" << contact.GetContractFormatHeader() << endl;
    cout << "userName" << userName << endl;
    cout << "pwd" << pwd << endl;
    cout << "expires" << expires << endl;
    cout << "=============================================" << endl;
    //服务器注册
    static osip_message_t *regMsg = 0;
    int ret;

    ::eXosip_add_authentication_info(g_exctx, userName.c_str(), userName.c_str(), pwd.c_str(), "MD5", NULL);
    eXosip_lock(g_exctx);
    //发送注册信息 401响应由eXosip2库自动发送
    if (0 == registerId)
    {
        // 注册消息的初始化
        registerId = ::eXosip_register_build_initial_register(g_exctx,
                                                              from.GetFormatHeader().c_str(), to.GetFormatHeader().c_str(),
                                                              contact.GetContractFormatHeader().c_str(), expires, &regMsg);
        if (registerId <= 0)
        {
            return -1;
        }
    }
    else
    {
        // 构建注册消息
        ret = ::eXosip_register_build_register(g_exctx, registerId, expires, &regMsg);
        if (ret != OSIP_SUCCESS)
        {
            printf("[%s:%d] build register failed.\n", __func__, __LINE__);
            return ret;
        }
        //添加注销原因
        if (expires == 0)
        {
            osip_contact_t *contact = NULL;
            char tmp[128];

            osip_message_get_contact(regMsg, 0, &contact);
            {
                sprintf(tmp, "<sip:%s@%s:%s>;expires=0",
                        contact->url->username, contact->url->host,
                        contact->url->port);
            }
            printf("[%s:%d] tmp:%s\n", __func__, __LINE__, tmp);
            //osip_contact_free(contact);
            //reset contact header
            osip_list_remove(&regMsg->contacts, 0);
            osip_message_set_contact(regMsg, tmp);
            osip_message_set_header(regMsg, "Logout-Reason", "logout");
        }
    }
    // 发送注册消息
    ret = ::eXosip_register_send_register(g_exctx, registerId, regMsg);
    if (ret != OSIP_SUCCESS)
    {
        registerId = 0;
    }
    eXosip_unlock(g_exctx);

    return ret;
}

//注册
void Register()
{
    if (iCurrentStatus == 1)
    {
        cout << "当前已经注册" << endl;
        return;
    }
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UASCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UASCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UASCODE, LISTEN_ADDR, UAS_PORT);
    //发送注册信息
    int registerId = 0;
    if (0 != SendRegister(registerId, stFrom, stTo, stContract, UACCODE, UACPWD,
                          3000, 0))
    {
        cout << "发送注册失败" << endl;
        return;
    }
    iCurrentStatus = 1;
    iHandle = registerId;
}
//刷新注册
void RefreshRegister()
{
    if (iCurrentStatus == 0)
    {
        cout << "当前未注册，不允许刷新" << endl;
        return;
    }
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UASCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UASCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UAC_PORT);
    CSipFromToHeader stRoute;
    stRoute.SetHeader(UACCODE, LISTEN_ADDR, UAC_PORT);
    //发送注册信息
    if (0 > SendRegister(iHandle, stFrom, stTo, stContract, UACCODE, UACPWD,
                         3000, 1))
    {
        cout << "发送刷新注册失败" << endl;
        return;
    }
}
//注销
void UnRegister()
{
    if (iCurrentStatus == 0)
    {
        cout << "当前未注册，不允许注销" << endl;
        return;
    }
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, UAC_ADDR, UAC_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAC_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UASCODE, LISTEN_ADDR, UAS_PORT);
    //发送注册信息
    if (0 > SendRegister(iHandle, stFrom, stTo, stContract, UASCODE, UACPWD,
                         0, 2))
    {
        cout << "发送注销失败" << endl;
        return;
    }
    iCurrentStatus = 0;
    iHandle = -1;
}
static void help()
{
    const char
        *b =
            "-------------------------------------------------------------------------------\n"
            "\n"
            "              0:Register\n"
            "              1:RefreshRegister\n"
            "              2:UnRegister\n"
            "              3:clear scream\n"
            "              4:exit\n"
            "-------------------------------------------------------------------------------\n"
            "\n";
    fprintf(stderr, b, strlen(b));
    cout << "please select method :";
}
//服务处理线程
void *serverHandle(void *pUser)
{
    sleep(3);
    help();
    char ch = getchar();
    getchar();
    while (1)
    {
        switch (ch)
        {
        case '0':
            //注册
            Register();
            break;
        case '1':
            //刷新注册
            RefreshRegister();
            break;
        case '2':
            //注销
            UnRegister();
            break;
        case '3':
            if (system("clear") < 0)
            {
                cout << "clear scream error" << endl;
                exit(1);
            }
            break;
        case '4':
            cout << "exit sipserver......" << endl;
            getchar();
            exit(0);
        default:
            cout << "select error" << endl;
            break;
        }
        cout << "press any key to continue......" << endl;
        getchar();
        help();
        ch = getchar();
        getchar();
    }
    return NULL;
}

//事件处理线程
void *eventHandle(void *pUser)
{
    eXosip_event_t *osipEventPtr = (eXosip_event_t *)pUser;
    osip_message_t *answer = NULL;
    osip_message_t *answer1 = NULL;
    osip_message_t *answer2 = NULL;
    osip_message_t *answer3 = NULL;
    osip_message_t *answer4 = NULL;
    osip_message_t *answer5 = NULL;
    osip_message_t *answer6 = NULL;
    osip_message_t *answer7 = NULL;
    osip_message_t *answer8 = NULL;
    sdp_message_t *remote_sdp = NULL;
    int call_id, dialog_id;
    static int count1 = 0;
    static int count2 = 0;
    static int count3 = 0;
    static int count4 = 0;
    char tmp[4096] = {0};
    char tmp1[4096] = {0};
    char tmp2[4096] = {0};
    char tmp3[4096] = {0};
    char tmp4[4096] = {0};
    int i;
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UASCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UASCODE, UAS_ADDR, UAS_PORT);
    std::string From = stFrom.GetFormatHeader();
    std::string To = stTo.GetFormatHeader();

    switch (osipEventPtr->type)
    {

    //需要继续验证REGISTER是什么类型
    case EXOSIP_REGISTRATION_SUCCESS:
        break;
    case EXOSIP_REGISTRATION_FAILURE:
    {
        // cout << "收到状态码:" << osipEventPtr->response->status_code << "报文" << endl;
        if (osipEventPtr->response->status_code == 401)
        {
            cout << "发送鉴权报文" << endl;
        }
        else if (osipEventPtr->response->status_code == 200)
        {
            cout << "接收成功" << endl;
        }
        else
        {
        }
    }
    break;
    case EXOSIP_CALL_INVITE:
    {
        //     printf("Received a INVITE msg from %s:%s, UserName is %s, password is %s\n", osipEventPtr->request->req_uri->host,
        //            osipEventPtr->request->req_uri->port, osipEventPtr->request->req_uri->username, osipEventPtr->request->req_uri->password);
        //     //得到消息体,认为该消息就是SDP格式.
        //     remote_sdp = eXosip_get_remote_sdp(g_exctx, osipEventPtr->did);
        //     call_id = osipEventPtr->cid;
        //     dialog_id = osipEventPtr->did;
        //     printf("******************************************\n");
        //     printf("remote sdp: \n");
        //   //  printf("v:%s \n", remote_sdp->v_version);
        //     printf("o:%s %s %s %s %s\n", remote_sdp->o_sess_id, remote_sdp->o_sess_version, remote_sdp->o_nettype, remote_sdp->o_addrtype, remote_sdp->o_addr);
        //     printf("s:%s \n", remote_sdp->s_name);
        //     printf("c:%s %s %s\n", remote_sdp->c_connection->c_nettype, remote_sdp->c_connection->c_addrtype, remote_sdp->c_connection->c_addr);
        //     //printf("m:%s \n",remote_sdp->m_medias, remote_sdp->m_medias.);
        //     printf("******************************************\n");

        osip_body_t *body;
        osip_message_get_body(osipEventPtr->request, 0, &body);
        printf("I get the msg is: %s\n", body->body);
        printf("******************************************\n");
        printf("******************************************\n");
        printf("******************************************\n");
        remote_sdp = eXosip_get_remote_sdp(g_exctx, osipEventPtr->did);
        if (NULL == remote_sdp)
        {
            printf("Null-----");
        }
        call_id = osipEventPtr->cid;
        printf("%d\n", call_id);
        dialog_id = osipEventPtr->did;
        //  printf("%d\n",dialog_id);
        //   printf("%d \n",remote_sdp->m_medias->port);

        //printf("%s\n",remote_sdp->m_medias);

        eXosip_lock(g_exctx);
        eXosip_call_send_answer(g_exctx, osipEventPtr->tid, 180, NULL);
        i = eXosip_call_build_answer(g_exctx, osipEventPtr->tid, 200, &answer);
        if (i != 0)
        {
            printf("This request msg is invalid!Cann't response!\n");
            eXosip_call_send_answer(g_exctx, osipEventPtr->tid, 400, NULL);
        }
        else
        {
            snprintf(tmp, sizeof(tmp),
                     "v=0\r\n"
                     "o=34020000002000000001 0 0 IN IP4 192.168.35.165\r\n"
                     "t=0 0\r\n"
                     "s=Play\r\n"
                     "i=VCam Live Video\r\n"
                     "c=IN IP4 192.168.35.165\r\n"
                     "m=video 9999  RTP/AVP 96\r\n"
                     "a=sendonly\r\n"
                     "a=rtpmap:96 PS/90000\r\n"
                     "a=streamprofile:0\r\n"
                     "y=0000001024\r\n"
                     "f=v/0/0/0/0/0a/0/0/0\r\n");

            //设置回复的SDP消息体,下一步计划分析消息体
            //没有分析消息体，直接回复原来的消息，这一块做的不好。
            osip_message_set_body(answer, tmp, strlen(tmp));
            osip_message_set_content_type(answer, "application/sdp");

            eXosip_call_send_answer(g_exctx, osipEventPtr->tid, 200, answer);
            printf("send 200 over!\n");
        }
        eXosip_unlock(g_exctx);
    }
    break;
    case EXOSIP_CALL_ACK:
        printf("ACK recieved!\n");
        // printf ("the cid is %s, did is %s/n", je->did, je->cid);
        break;
    case EXOSIP_MESSAGE_NEW:
    {
        printf(" EXOSIP_MESSAGE_NEW!\n");
        if (MSG_IS_MESSAGE(osipEventPtr->request)) //如果接受到的消息类型是MESSAGE
        {
            {
                osip_body_t *body;
                osip_message_get_body(osipEventPtr->request, 0, &body);
                //printf("I get the msg is: %s\n", body->body);
                //printf ("the cid is %s, did is %s/n", je->did, je->cid);

                string messagesbody = body->body;
                string Catalog = "Catalog";

                int ans1 = messagesbody.find(Catalog);

                if (ans1 != -1)
                {
                    //eXosip_message_build_request(g_exctx, &answer, "MESSAGE", To.c_str(), From.c_str(), NULL);
                    count1++;
                    eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer1);
                    eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer1);
                    if (count1 == 1)
                    {

                        snprintf(tmp1, sizeof(tmp1),
                                 "<?xml version=\"1.0\"?>\r\n"
                                 "<Response>\r\n"
                                 "<CmdType>Catalog</CmdType>\r\n"
                                 "<SN>1</SN>\r\n"
                                 "<DeviceID>34020000002000000002</DeviceID>\r\n"
                                 "<SumNum>1</SumNum>\r\n"
                                 "<DeviceList Num=\" 1 \">\r\n"
                                 "<Item>\r\n"
                                 "<DeviceID>34020000002000000002</DeviceID>\r\n"
                                 "<Name>IPC</Name>\r\n"
                                 "<Manufacturer>ABCD</Manufacturer>\r\n"
                                 "<Model>TEST001</Model>\r\n"
                                 "<Owner>Owner1</Owner>\r\n"
                                 "<CivilCode>CivilCode1</CivilCode>\r\n"
                                 "<Block>Block1</Block>\r\n"
                                 "<Address>Address1</Address>\r\n"
                                 "<Parental>0</Parental>\r\n"
                                 "<ParentID>34020000002000000002</ParentID>\r\n"
                                 "<SafetyWay>0</SafetyWay>\r\n"
                                 "<RegisterWay>1</RegisterWay>\r\n"
                                 "<CertNum>CertNum1</CertNum>\r\n"
                                 "<Certifiable>0</Certifiable>\r\n"
                                 "<ErrCode>400</ErrCode>\r\n"
                                 "<EndTime>2050-12-31T23:59:59</EndTime>\r\n"
                                 "<Secrecy>0</Secrecy>\r\n"
                                 "<IPAddress>192.168.35.63</IPAddress>\r\n"
                                 "<Port>5080</Port>\r\n"
                                 "<Password>Password1</Password>\r\n"
                                 "<Status>OK</Status>\r\n"
                                 "<Longitude></Longitude>\r\n"
                                 "<Latitude></Latitude>\r\n"
                                 "</Item>\r\n"
                                 "</DeviceList>\r\n"
                                 "</Response>\r\n");

                        //printf(">>>>>>msg len:%d, size:%d\n", strlen(tmp1), sizeof(tmp1));
                        eXosip_message_build_request(g_exctx, &answer2, "MESSAGE", To.c_str(), From.c_str(), NULL);
                        //eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer);

                        osip_message_set_body(answer2, tmp1, strlen(tmp1));
                        osip_message_set_content_type(answer2, "Application/MANSCDP+xml");
                        //  eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer);
                        eXosip_message_send_request(g_exctx, answer2);
                    }
                }

                string DeviceInfo = "DeviceInfo";
                int ans2 = messagesbody.find(DeviceInfo);

                if (ans2 != -1)
                {
                    //eXosip_message_build_request(g_exctx, &answer2, "MESSAGE", To.c_str(), From.c_str(), NULL);
                    count2++;
                    eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer3);
                    eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer3);

                    if (count2 == 1)
                    {

                        snprintf(tmp2, sizeof(tmp2),
                                 "<?xml version=\"1.0\"?>\r\n"
                                 "<Response>\r\n"
                                 "<CmdType>DeviceInfo</CmdType>\r\n"
                                 "<SN>2</SN>\r\n"
                                 "<DeviceID>34020000002000000002</DeviceID>\r\n"
                                 "<Result>OK</Result>\r\n"
                                 "<Manufacturer>ABCD</Manufacturer>\r\n"
                                 "<Model>TEST001</Model>\r\n"
                                 "<Firmware>V1.0</Firmware>\r\n"
                                 "</Response>\r\n");
                        eXosip_message_build_request(g_exctx, &answer4, "MESSAGE", To.c_str(), From.c_str(), NULL);
                        // eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer2);
                        osip_message_set_body(answer4, tmp2, strlen(tmp2));
                        osip_message_set_content_type(answer4, "Application/MANSCDP+xml");
                        // eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer2);
                        eXosip_message_send_request(g_exctx, answer4);

                        // count2++;
                    }
                }

                string DeviceStatus = "DeviceStatus";
                int ans3 = messagesbody.find(DeviceStatus);

                if (ans3 != -1)
                {
                    //eXosip_message_build_request(g_exctx, &answer3, "MESSAGE", To.c_str(), From.c_str(), NULL);
                    count3++;
                    eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer5);
                    eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer5);

                    if (count3 == 1)
                    {
                        //        eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer);
                        //        eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer);
                        //   }
                        //    else if (count3 == 2)
                        //    {
                        snprintf(tmp3, sizeof(tmp3),
                                 "<?xml version=\"1.0\"?>\r\n"
                                 "<Response>\r\n"
                                 "<CmdType>DeviceStatus</CmdType>\r\n"
                                 "<SN>3</SN>\r\n"
                                 "<DeviceID>34020000002000000002</DeviceID>\r\n"
                                 "<Result>OK</Result>\r\n"
                                 "<Online>ONLINE</Online>\r\n"
                                 "<Status>OK</Status>\r\n"
                                 "<Encode>ON</Encode>\r\n"
                                 "<Record>OFF</Record>\r\n"
                                 "<DeviceTime>2019-09-08T11:12:20</DeviceTime>\r\n"
                                 "<Alarmstatus Num=\"1\">\r\n"
                                 "<Item>\r\n"
                                 "<DeviceID>34020000002000000002</DeviceID>\r\n"
                                 "<DutyStatus>OFFDUTY</DutyStatus>\r\n"
                                 "</Item>\r\n"
                                 "</Alarmstatus>\r\n"
                                 "</Response>\r\n");
                        eXosip_message_build_request(g_exctx, &answer6, "MESSAGE", To.c_str(), From.c_str(), NULL);
                        //  eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer3);
                        osip_message_set_body(answer6, tmp3, strlen(tmp3));
                        osip_message_set_content_type(answer6, "Application/MANSCDP+xml");
                        //  eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer3);
                        eXosip_message_send_request(g_exctx, answer6);

                        //   count3++;
                    }
                }

                string Keepalive = "Keepalive";
                int ans4 = messagesbody.find(Keepalive);
                if (ans4 != -1)
                {
                    count4++;
                    eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer7);
                    eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer7);
                    if (count4 == 1)
                    {
                        snprintf(tmp4, sizeof(tmp4),
                                 "<?xml version=\"1.0\"?>\r\n"
                                 "<Notify>\r\n"
                                 "<CmdType>Keepalive</CmdType>\r\n"
                                 "<SN>4</SN>\r\n"
                                 "<DeviceID>34020000002000000002</DeviceID>\r\n"
                                 "<Status>OK</Status>\r\n"
                                 "</Notify>\r\n");
                        eXosip_message_build_request(g_exctx, &answer8, "MESSAGE", To.c_str(), From.c_str(), NULL);
                        //  eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer3);
                        osip_message_set_body(answer8, tmp4, strlen(tmp4));
                        osip_message_set_content_type(answer8, "Application/MANSCDP+xml");
                        //  eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer3);
                        eXosip_message_send_request(g_exctx, answer8);
                    }
                }
            }
            //按照规则，需要回复OK信息
            //判断方式（）（）（）

            // eXosip_message_build_answer(g_exctx, osipEventPtr->tid, 200, &answer);
            // eXosip_message_send_answer(g_exctx, osipEventPtr->tid, 200, answer);
        }
    }
    break;
    case EXOSIP_CALL_CLOSED:
    {
        printf("the remote hold the session!\n");
        // eXosip_call_build_ack(dialog_id, &ack);
        //eXosip_call_send_ack(dialog_id, ack);
        i = eXosip_call_build_answer(g_exctx, osipEventPtr->tid, 200, &answer);
        if (i != 0)
        {
            printf("This request msg is invalid!Cann't response!\n");
            eXosip_call_send_answer(g_exctx, osipEventPtr->tid, 400, NULL);
        }
        else
        {
            eXosip_call_send_answer(g_exctx, osipEventPtr->tid, 200, answer);
            printf("bye send 200 over!\n");
        }
    }
    break;
    case EXOSIP_CALL_MESSAGE_NEW:
    {
        printf(" EXOSIP_CALL_MESSAGE_NEW\n");
        if (MSG_IS_INFO(osipEventPtr->request)) //如果传输的是INFO方法
        {
            eXosip_lock(g_exctx);
            i = eXosip_call_build_answer(g_exctx, osipEventPtr->tid, 200, &answer);
            if (i == 0)
            {
                eXosip_call_send_answer(g_exctx, osipEventPtr->tid, 200, answer);
            }
            eXosip_unlock(g_exctx);
            {
                osip_body_t *body;
                osip_message_get_body(osipEventPtr->request, 0, &body);
                printf("the body is %s\n", body->body);
            }
        }
    }
    break;
    default:
        cout << "The sip event type that not be precessed.the event "
                "type is : "
             << osipEventPtr->type << endl;
        break;
    }
    eXosip_event_free(osipEventPtr);
    return NULL;
}

int main()
{
    iCurrentStatus = 0;
    char userAgent[64] = "SIP UAS V3.0.0.828177";

    //char userAgent[64] = "eXosip/4.0.0";
    //库处理结果
    int result = OSIP_SUCCESS;
    //初始化库

    g_exctx = eXosip_malloc();
    if (OSIP_SUCCESS != (result = eXosip_init(g_exctx)))
    {
        printf("eXosip_init failure.\n");
        return 1;
    }
    cout << "eXosip_init success." << endl;
    eXosip_set_user_agent(g_exctx, userAgent);
    //监听
    if (OSIP_SUCCESS != eXosip_listen_addr(g_exctx, IPPROTO_UDP, NULL, UAC_PORTINT,
                                           AF_INET, 0))
    {
        printf("eXosip_listen_addr failure.\n");
        return 1;
    }
    //设置监听网卡
    if (OSIP_SUCCESS != eXosip_set_option(g_exctx,
                                          EXOSIP_OPT_SET_IPV4_FOR_GATEWAY,
                                          LISTEN_ADDR))
    {
        return -1;
    }
    //开启服务线程
    pthread_t pthser;
    if (0 != pthread_create(&pthser, NULL, serverHandle, NULL))
    {
        printf("创建主服务失败\n");
        return -1;
    }
    //事件用于等待
    eXosip_event_t *osipEventPtr = NULL;
    //开启事件循环
    while (true)
    {
        //等待事件 0的单位是秒，500是毫秒
        osipEventPtr = ::eXosip_event_wait(g_exctx, 0, 200);
        //处理eXosip库默认处理
        {
            usleep(500 * 1000);
            eXosip_lock(g_exctx);
            //一般处理401/407采用库默认处理
            eXosip_default_action(g_exctx, osipEventPtr);
            eXosip_unlock(g_exctx);
        }
        //事件空继续等待
        if (NULL == osipEventPtr)
        {
            continue;
        }
        //开启线程处理事件并在事件处理完毕将事件指针释放
        pthread_t pth;
        if (0 != pthread_create(&pth, NULL, eventHandle, (void *)osipEventPtr))
        {
            printf("创建线程处理事件失败\n");
            continue;
        }
        osipEventPtr = NULL;
    }
}
