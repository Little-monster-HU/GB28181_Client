

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
#define UACPORT ("5061")
#define UACPORTINT (5061)
//本UAC地址编码
#define UACCODE ("100110000201000000")
//本地UAC密码
#define UACPWD ("12345")
//远程UAS IP
#define UAS_ADDR ("192.168.35.165")
//远程UAS 端口
#define UAS_PORT ("5060")
//超时
#define EXPIS 300

//当前服务状态 1 已经注册 0 未注册
static int iCurrentStatus;
//注册成功HANDLE
static int iHandle = -1;
struct eXosip_t *g_exctx = NULL;

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
        stream << "sip: " << addrCode << "@" << addrIp << ":" << addrPort;
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
        stream << "<sip:" << GetCode() << "@" << GetAddr() << ":" << GetPort()
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
    stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //发送注册信息
    int registerId = 0;
    if (0 > SendRegister(registerId, stFrom, stTo, stContract, UACCODE, UACPWD,
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
    stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
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
    stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //发送注册信息
    if (0 != SendRegister(iHandle, stFrom, stTo, stContract, UACCODE, UACPWD,
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
            "SIP Library test process - uac v 1.0 (June 13, 2014)\n\n"
            "SIP UAC端 注册,刷新注册,注销实现\n\n"
            "Author: 程序人生\n\n"
            "博客地址:http://blog.csdn.net/hiwubihe QQ:1269122125\n\n"
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
    if(pUser == NULL)
    {
        printf("[%s:%d] pUser is null! \n",__func__,__LINE__);
        return NULL;
    }
    eXosip_event_t *osipEventPtr = (eXosip_event_t *)pUser;
    if(osipEventPtr->response == NULL)
    {
        printf("[%s:%d] response is null! \n",__func__,__LINE__);
        return NULL;
    }
    switch (osipEventPtr->type)
    {
    //需要继续验证REGISTER是什么类型
    case EXOSIP_REGISTRATION_SUCCESS:
    case EXOSIP_REGISTRATION_FAILURE:
    {
        cout << "收到状态码:" << osipEventPtr->response->status_code << "报文" << endl;
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
    //eXosip_set_user_agent(NULL);
    //监听
    if (OSIP_SUCCESS != eXosip_listen_addr(g_exctx, IPPROTO_UDP, NULL, UACPORTINT,
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