
// YSnifferDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include <pcap.h>
#include <string>
#include "YSniffer.h"
#include "YSnifferDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CYSnifferDlg 对话框

CYSnifferDlg::CYSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_YSNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CYSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PACKETS, m_listPackets);
	DDX_Control(pDX, IDC_COMBO_ADAPTER, m_comboAdapter);
	DDX_Control(pDX, IDC_EDIT_DETAIL, m_editDetail);
	DDX_Control(pDX, IDC_EDIT_HEX, m_editHex);
}

BEGIN_MESSAGE_MAP(CYSnifferDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_START, &CYSnifferDlg::OnBnClickedButtonStart)
	ON_BN_CLICKED(IDC_BUTTON_REFRESH, &CYSnifferDlg::OnBnClickedButtonRefresh)
	ON_MESSAGE(WM_PACKET_RECEIVED, &CYSnifferDlg::OnPacketReceived)
	ON_BN_CLICKED(IDC_BUTTON_CLEAR, &CYSnifferDlg::OnBnClickedButtonClear)
	ON_BN_CLICKED(IDC_BUTTON_FOLLOW, &CYSnifferDlg::OnBnClickedButtonFollow)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_PACKETS, &CYSnifferDlg::OnLvnItemchangedListPackets)
	ON_BN_CLICKED(IDC_CHECK_IPV4, &CYSnifferDlg::OnBnClickedCheckIpv4)
	ON_BN_CLICKED(IDC_CHECK_IPV6, &CYSnifferDlg::OnBnClickedCheckIpv6)
	ON_BN_CLICKED(IDC_CHECK_TCP, &CYSnifferDlg::OnBnClickedCheckTcp)
	ON_BN_CLICKED(IDC_CHECK_UDP, &CYSnifferDlg::OnBnClickedCheckUdp)
	ON_BN_CLICKED(IDC_CHECK_HTTP, &CYSnifferDlg::OnBnClickedCheckHttp)
	ON_BN_CLICKED(IDC_CHECK_ICMP, &CYSnifferDlg::OnBnClickedCheckIcmp)
END_MESSAGE_MAP()


// CYSnifferDlg 消息处理程序

BOOL CYSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	SkinH_Attach();//加载皮肤
	//创建等宽字体
	m_fontHex.CreateFont(
		14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, 0,
		ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, _T("Consolas"));

	//把字体应用到你的十六进制编辑框上
	GetDlgItem(IDC_EDIT_HEX)->SetFont(&m_fontHex);
	//设置列表的扩展风格
	m_listPackets.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	//插入表头
	m_listPackets.InsertColumn(0, _T("序号"), LVCFMT_LEFT, 50);
	m_listPackets.InsertColumn(1, _T("时间"), LVCFMT_LEFT, 100);
	m_listPackets.InsertColumn(2, _T("源 IP"), LVCFMT_LEFT, 250);
	m_listPackets.InsertColumn(3, _T("目的 IP"), LVCFMT_LEFT, 250);
	m_listPackets.InsertColumn(4, _T("协议"), LVCFMT_LEFT, 60);
	m_listPackets.InsertColumn(5, _T("长度"), LVCFMT_LEFT, 60);
	m_listPackets.InsertColumn(6, _T("内容提要"), LVCFMT_LEFT, 250);
	return TRUE;
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。
void CYSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CYSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//IPV4协议识别
CString GetProtocolName(u_char protocol)
{
	switch (protocol)
	{
	case 1:   return _T("ICMP");//互联网控制消息协议
	case 2:   return _T("IGMP");//互联网组管理协议
	case 6:   return _T("TCP"); //传输控制协议
	case 8:   return _T("EGP"); //外部网关协议
	case 9:   return _T("IGP"); //内部网关协议
	case 17:  return _T("UDP"); //用户数据报协议
	case 89:  return _T("OSPF");//开放最短路径优先
	default:  return _T("其他");
	}
}

volatile bool m_bIsFollowing = false; //追踪标志位
CString m_lockSrcIp = _T("");//追踪IP1
CString m_lockDstIp = _T("");//追踪IP2
//追踪过滤：返回 true 表示保留该包，返回 false 表示过滤掉该包
bool CYSnifferDlg::ShouldPassFilter(const CString& strProtocol, u_short eth_type, const CString& strSrc, const CString& strDst)
{
	if (m_bIsFollowing&&m_lockSrcIp.GetLength()>0&&m_lockDstIp.GetLength() > 0)
	{
		// 双向匹配：A->B 或者 B->A
		if ((strSrc == m_lockSrcIp && strDst == m_lockDstIp) ||
			(strSrc == m_lockDstIp && strDst == m_lockSrcIp))
		{
			return true;
		}
		return false;
	}
	return true;
}


volatile bool g_bStopSniffing = false;//控制线程停止
pcap_t* g_adhandle = NULL; //网卡句柄
//抓包的回调函数（由Npcap在后台自动调用）
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	if (g_bStopSniffing) return;//停止抓包状态下不处理数据

	//读取以太网类型
	u_short eth_type = ntohs(*(u_short*)(pkt_data + 12));
	int eth_header_len = 14;
	CString strSrc = _T("未知源");
	CString strDst = _T("未知目的");
	CString strProtocol = _T("其他");
	CString strSummary = _T("未知信息");
	//读取秒数
	time_t rawTime = (time_t)header->ts.tv_sec;
	struct tm timeInfo;
	localtime_s(&timeInfo, &rawTime);
	CString strTime;
	//格式化：时:分:秒.毫秒
	strTime.Format(_T("%02d:%02d:%02d.%03d"),
		timeInfo.tm_hour, timeInfo.tm_min, timeInfo.tm_sec,
		header->ts.tv_usec / 1000);

	//判断是否为VLAN数据包
	if (eth_type == 0x8100 && header->caplen >= 18)
	{
		//偏移4个字节，读取真正的上层协议类型
		eth_type = ntohs(*(u_short*)(pkt_data + 16));
		eth_header_len = 18; //更新以太网头长度是18
	}

	// ================= 处理ARP协议 =================
	if (eth_type == 0x0806)
	{
		strProtocol = _T("ARP");
		if (header->caplen >= eth_header_len + 28) //ARP最小长度为eth_header_len+28字节
		{
			const u_char* arp_header = pkt_data + eth_header_len;
			u_short opcode = ntohs(*(u_short*)(arp_header + 6)); //操作码：1=请求，2=应答

			//获取源IP与目的IP
			struct in_addr src_ip, dst_ip;
			memcpy(&src_ip, arp_header + 14, 4);
			memcpy(&dst_ip, arp_header + 24, 4);
			char srcIpBuf[INET_ADDRSTRLEN] = { 0 };
			char dstIpBuf[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &src_ip, srcIpBuf, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &dst_ip, dstIpBuf, INET_ADDRSTRLEN);

			CString srcIpStr(srcIpBuf);
			CString dstIpStr(dstIpBuf);
			strSrc = srcIpStr;
			strDst = dstIpStr;

			if (opcode == 1) strSummary = _T("ARP 请求");
			else if (opcode == 2) strSummary = _T("ARP 应答");
		}
	}
	// ================= 处理IPv6协议 =================
	else if (eth_type == 0x86DD)
	{
		strProtocol = _T("IPv6");
		if (header->caplen >= eth_header_len + 40) //IPv6基本头长为40字节，加eth_header_len字节以太网头
		{
			const u_char* ip6_header = pkt_data + eth_header_len;
			u_char next_header = *(ip6_header + 6); //IPv6 的下一个头部相当于协议号

			//提取IPv6地址(16字节)
			struct in6_addr src_ip6, dst_ip6;
			memcpy(&src_ip6, ip6_header + 8, 16);
			memcpy(&dst_ip6, ip6_header + 24, 16);

			char srcBuf[INET6_ADDRSTRLEN] = { 0 };
			char dstBuf[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &src_ip6, srcBuf, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &dst_ip6, dstBuf, INET6_ADDRSTRLEN);
			strSrc = srcBuf;
			strDst = dstBuf;

			//解析IPv6里的TCP/UDP
			if (next_header == 6 || next_header == 17)
			{
				if (header->caplen >= eth_header_len + 40 + 4)
				{
					const u_char* trans_header = pkt_data + eth_header_len + 40;
					u_short sport = ntohs(*(u_short*)(trans_header));
					u_short dport = ntohs(*(u_short*)(trans_header + 2));
					if (next_header == 6) strSummary.Format(_T("TCP: %d -> %d"), sport, dport);
					else if (next_header == 17) strSummary.Format(_T("UDP: %d -> %d"), sport, dport);
				}
			}
			else if (next_header == 58 && header->caplen >= eth_header_len + 40 + 4) {
				strProtocol = _T("ICMPv6");
				if (header->caplen >= eth_header_len + 40 + 1)
				{
					const u_char* icmp6_header = pkt_data + eth_header_len + 40;
					u_char icmp6_type = icmp6_header[0];

					switch (icmp6_type)
					{
					case 128: strSummary = _T("ICMPv6 回显请求 (Ping)"); break;
					case 129: strSummary = _T("ICMPv6 回显应答 (Ping)"); break;
					case 133: strSummary = _T("ICMPv6 路由器请求 (RS)"); break;
					case 134: strSummary = _T("ICMPv6 路由器通告 (RA)"); break;
					case 135: strSummary = _T("ICMPv6 邻居请求 (NS)"); break;
					case 136: strSummary = _T("ICMPv6 邻居通告 (NA)"); break;
					default:  strSummary.Format(_T("ICMPv6 报文 (类型 %d)"), icmp6_type); break;
					}
				}
				else
				{
					strSummary = _T("ICMPv6 截断报文");
				}
			}
			else 
			{ 
				strSummary = strProtocol+ _T("数据");
			}
		}
	}
	// ================= 处理 IPv4 协议 =================
	else if (eth_type == 0x0800)
	{
		const u_char* ip_header = pkt_data + eth_header_len;
		if (header->caplen < 34) return;
		//提取IP头中的协议号(第9个字节)并调用函数识别
		u_char protocol = *(ip_header + 9);
		strProtocol = GetProtocolName(protocol);

		//提取源IP和目的IP
		struct in_addr src_ip, dst_ip;
		memcpy(&src_ip, ip_header + 12, 4);
		memcpy(&dst_ip, ip_header + 16, 4);

		char srcIpBuf[INET_ADDRSTRLEN] = { 0 };
		char dstIpBuf[INET_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET, &src_ip, srcIpBuf, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &dst_ip, dstIpBuf, INET_ADDRSTRLEN);

		CString srcIpStr(srcIpBuf);
		CString dstIpStr(dstIpBuf);
		strSrc = srcIpStr;
		strDst = dstIpStr;

		strSummary = _T("未知数据");
		//若是TCP或UDP协议，提取端口号
		if (protocol == 6 || protocol == 17)
		{
			//IP头长度=(首部长度字段)*4。通常IPv4是20字节，但也可能有可选项
			u_char ip_header_len = (*(ip_header) & 0x0f) * 4;

			// 确保抓到的包足够长，能读到端口
			if (header->caplen >= eth_header_len + ip_header_len + 4)
			{
				//获取端口号
				const u_char* transport_header = pkt_data + eth_header_len + ip_header_len;
				u_short sport = ntohs(*(u_short*)(transport_header));
				u_short dport = ntohs(*(u_short*)(transport_header + 2));

				if (protocol == 6) {//TCP
					if (sport == 80 || dport == 80 || sport == 8080 || dport == 8080) {//判断是不是HTTP
						strProtocol = _T("HTTP");
						strSummary.Format(_T("HTTP 报文, 端口: %d -> %d"), sport, dport);
					}
					else if (sport == 443 || dport == 443) {//判断是不是HTTPS
						strProtocol = _T("HTTPS");
						strSummary.Format(_T("HTTPS 报文, 端口: %d -> %d"), sport, dport);
					}
					else {
						strSummary.Format(_T("TCP 端口: %d -> %d"), sport, dport);
					}
				}
				else if (protocol == 17) {//UDP
					strSummary.Format(_T("UDP 端口: %d -> %d"), sport, dport);
				}
			}
		}
		else 
		{ 
			strSummary = strProtocol+ _T("数据");
		}
	}if (eth_type == 0x0049) //Cisco CDP
	{
		strProtocol = _T("CDP");
		strSummary = _T("思科发现协议报文");
	}
	else if (eth_type == 0x88CC)
	{
		strProtocol = _T("LLDP");
		strSummary = _T("链路层发现协议报文");
	}

	//获取主窗口指针
	CYSnifferDlg* pDlg = (CYSnifferDlg*)AfxGetMainWnd();
	if (!pDlg->ShouldPassFilter(strProtocol, eth_type, strSrc, strDst))
	{
		return; // 被过滤，直接丢弃，不发给界面
	}
	if (pDlg)
	{
		//创建新的结构体并拼接列表信息字符串
		PacketData* pData = new PacketData();
		pData->infoStr.Format(_T("%s|%s|%s|%s|%d|%s"),
			(LPCTSTR)strTime, (LPCTSTR)strSrc, (LPCTSTR)strDst,
			(LPCTSTR)strProtocol, header->len, (LPCTSTR)strSummary);

		//拷贝原始数据
		pData->rawLen = header->caplen;
		pData->rawData = new u_char[pData->rawLen];
		memcpy(pData->rawData, pkt_data, pData->rawLen);

		//传递数据
		pDlg->PostMessage(WM_PACKET_RECEIVED, 0, (LPARAM)pData);
	}
}

//抓包线程函数
UINT CYSnifferDlg::SnifferThread(LPVOID pParam)
{
	CYSnifferDlg* pDlg = (CYSnifferDlg*)pParam;

	int idx = pDlg->m_comboAdapter.GetCurSel();//获取选中的网卡下标
	if (idx == CB_ERR) return 0;
	CString* pDevName = (CString*)pDlg->m_comboAdapter.GetItemData(idx);//获取选中的网卡名称
	CStringA strDevNameA(*pDevName);
	char errbuf[PCAP_ERRBUF_SIZE];
	g_adhandle = pcap_open((const char*)strDevNameA.GetString(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//打开网卡

	if (g_adhandle == NULL)
	{
		pDlg->MessageBox(_T("打开网卡失败，请检查网卡是否正常！"), _T("错误"), MB_ICONERROR);
		return 0;
	}
	pDlg->UpdateBpfFilter();
	pDlg->GetDlgItem(IDC_BUTTON_START)->SetWindowText(_T("停止抓包"));
	//开始抓包循环（0表示无限抓）
	pcap_loop(g_adhandle, 0, packet_handler, NULL);
	pcap_close(g_adhandle);
	g_adhandle = NULL;
	pDlg->GetDlgItem(IDC_BUTTON_START)->SetWindowText(_T("开始抓包"));
	return 0;
}

bool m_bIsUpdatingList = false;//用于识别是点击还是数据更新引起的列表事件
//处理发过来的消息，更新列表
LRESULT CYSnifferDlg::OnPacketReceived(WPARAM wParam, LPARAM lParam)
{
	PacketData* pData = (PacketData*)lParam;
	if (pData)
	{
		CString strTime, strSrc, strDst, strProto, strLen, strSummary;
		// 解析字符串填充列表
		AfxExtractSubString(strTime, pData->infoStr, 0, '|');
		AfxExtractSubString(strSrc, pData->infoStr, 1, '|');
		AfxExtractSubString(strDst, pData->infoStr, 2, '|');
		AfxExtractSubString(strProto, pData->infoStr, 3, '|');
		AfxExtractSubString(strLen, pData->infoStr, 4, '|');
		AfxExtractSubString(strSummary, pData->infoStr, 5, '|');
		m_bIsUpdatingList = true;//加锁，列表更新时，非点击操作
		//插入列表
		int nIndex = m_listPackets.GetItemCount();//获取列表行数（最下行下一行的下标）
		CString strIndex;
		strIndex.Format(_T("%d"), nIndex + 1);
		m_listPackets.InsertItem(nIndex, strIndex);// 序号
		m_listPackets.SetItemText(nIndex, 1, strTime);
		m_listPackets.SetItemText(nIndex, 2, strSrc);
		m_listPackets.SetItemText(nIndex, 3, strDst);
		m_listPackets.SetItemText(nIndex, 4, strProto);
		m_listPackets.SetItemText(nIndex, 5, strLen);
		m_listPackets.SetItemText(nIndex, 6, strSummary);
 
		m_listPackets.SetItemData(nIndex, (DWORD_PTR)pData->rawData);//存储行对应数据，不会在列表中显示，但是点击时需要用到
		m_bIsUpdatingList = false;//解锁
		delete pData;// 释放内存
	}
	return 0;
}

void CYSnifferDlg::OnBnClickedButtonStart()
{
	// TODO: 在此添加控件通知处理程序代码
	static bool flag = false;
	if (!flag) {
		if (g_adhandle != NULL) return; //网卡正在抓包，则不执行抓包操作
		if (m_comboAdapter.GetCurSel() == CB_ERR)
		{
			MessageBox(_T("请先刷新并选择网卡！"), _T("提示"));
			return;
		}

		g_bStopSniffing = false;
		// 开启后台线程抓包
		AfxBeginThread(SnifferThread, this);//启动线程
		flag = true;
	}
	else {
		g_bStopSniffing = true;//设置停止抓包状态
		pcap_breakloop(g_adhandle);//停止循环抓包
		flag = false;
	}

}

void CYSnifferDlg::OnBnClickedButtonRefresh()
{
	// TODO: 在此添加控件通知处理程序代码
	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];

	m_comboAdapter.ResetContent(); //清空下拉框

	// 获取网卡列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		MessageBox(_T("获取网卡失败！"), _T("错误"), MB_ICONERROR);
		return;
	}

	//遍历网卡并将其添加到下拉框中
	for (d = alldevs; d != NULL; d = d->next)
	{
		CString devName(d->name);//网卡名称
		CString devDesc;//网卡描述
		if (d->description)
			devDesc = d->description;
		else
			devDesc = _T("未知网卡");

		// 把显示名称加到下拉框，并返回它的索引
		int idx = m_comboAdapter.AddString(devDesc);
		// 将设备底层名称存储到这个索引上，后面抓包要用
		m_comboAdapter.SetItemData(idx, (DWORD_PTR)new CString(devName));
	}

	if(m_comboAdapter.GetCount() > 0)
		m_comboAdapter.SetCurSel(0);//默认选中第1个
	pcap_freealldevs(alldevs);
}

void CYSnifferDlg::OnLvnItemchangedListPackets(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	if (m_bIsUpdatingList) {//非点击事件则不执行下面的操作
		return;
	}

	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	int nSelected = pNMItemActivate->iItem;
	if (nSelected != -1) //确保选中某一行
	{
		//取出存在里面的原始数据
		u_char* rawData = (u_char*)m_listPackets.GetItemData(nSelected);
		if (rawData == NULL) { *pResult = 0; return; }

		CString strLen = m_listPackets.GetItemText(nSelected, 5);
		int pktLen = _ttoi(strLen);
		if (pktLen <= 0) return; //长度检查

		CString strHex = _T("");
		CString strDetail = _T("");
		CString tempStr;

		//每行显示16个字节
		int bytesPerLine = 16;

		for (int i = 0; i < pktLen; i += bytesPerLine)
		{
			CString strLine;
			CString strAscii = _T("");

			//拼接行首的地址，比如 0000, 0010, 0020
			strLine.Format(_T("%04X   "), i);

			//循环拼接这一行的16个字节
			for (int j = 0; j < bytesPerLine; ++j)
			{
				if (i + j < pktLen)
				{
					u_char byte = rawData[i + j];

					//拼接十六进制
					CString hexByte;
					hexByte.Format(_T("%02X "), byte);
					strLine += hexByte;

					//拼接ASCII字符（如果是可打印字符，显示出来；否则显示点 '.'）
					if (byte >= 32 && byte <= 126) {
						strAscii += (TCHAR)byte;
					}
					else {
						strAscii += _T(".");
					}
				}
				else
				{
					//如果最后一行不足16个字节，补空格对齐
					strLine += _T("   ");
					strAscii += _T(" ");
				}

				//在第8个字节后，多加一个空格
				if (j == 7) {
					strLine += _T(" ");
				}
			}

			//拼成完整的一行（加个分隔符和ASCII部分）
			strLine += _T("  ") + strAscii + _T("\r\n");
			strHex += strLine;
		}
		// 显示到16进制编辑框
		m_editHex.SetWindowText(strHex);

		u_char eth_header_len = 14; //默认以太网头长度
		u_short eth_type = 0;
		// ---------- 解析详细信息 ----------
		if (pktLen >= 14)
		{
			tempStr.Format(_T("[第%d包]\t长度: %d字节\r\n"), nSelected + 1, pktLen, pktLen);
			strDetail += tempStr;

			//解析MAC地址
			CString strSrcMac, strDstMac;
			strSrcMac.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"),
				rawData[6], rawData[7], rawData[8], rawData[9], rawData[10], rawData[11]);
			strDstMac.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"),
				rawData[0], rawData[1], rawData[2], rawData[3], rawData[4], rawData[5]);

			eth_type = ntohs(*(u_short*)(rawData + 12));

			//检查VLAN 标签
			if (eth_type == 0x8100 && pktLen >= 18)
			{
				eth_type = ntohs(*(u_short*)(rawData + 16));
				eth_header_len = 18;
				tempStr.Format(_T("[链路层]\t以太网帧(含VLAN), 源MAC: %s, 目的MAC: %s\r\n"), (LPCTSTR)strSrcMac, (LPCTSTR)strDstMac);
				strDetail += tempStr;
			}
			else
			{
				CString strEthType;
				if (eth_type == 0x0800) strEthType = _T("IPv4(0x0800)");
				else if (eth_type == 0x86DD) strEthType = _T("IPv6(0x86DD)");
				else if (eth_type == 0x0806) strEthType = _T("ARP(0x0806)");
				else strEthType = _T("未知类型");

				tempStr.Format(_T("[链路层]\t以太网帧, 源MAC: %s, 目的MAC: %s, 上层协议: %s\r\n"), (LPCTSTR)strSrcMac, (LPCTSTR)strDstMac, (LPCTSTR)strEthType);
				strDetail += tempStr;
			}
		}
		// ---------- IPv4 ----------
		if (pktLen >= (eth_header_len + 20) && eth_type == 0x0800)
		{
			u_char ip_header_len = (*(rawData + eth_header_len) & 0x0f) * 4;
			u_char protocol = *(rawData + eth_header_len + 9);
			CString strSrcIp, strDstIp;

			struct in_addr src_ip, dst_ip;
			memcpy(&src_ip, rawData + eth_header_len + 12, 4);
			memcpy(&dst_ip, rawData + eth_header_len + 16, 4);

			char srcIpBuf[INET_ADDRSTRLEN] = {0};
			char dstIpBuf[INET_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET, &src_ip, srcIpBuf, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &dst_ip, dstIpBuf, INET_ADDRSTRLEN);
			CString srcIpStr(srcIpBuf);
			CString dstIpStr(dstIpBuf);
			strSrcIp = srcIpStr;
			strDstIp = dstIpStr;

			tempStr.Format(_T("[网络层]\tIPv4报文, 源IP: %s, 目的IP: %s\r\n"), (LPCTSTR)strSrcIp, (LPCTSTR)strDstIp);//Internet Protocol Version 4, Src: %s, Dst: %s\r\n
			
			// ---------- 传输层(TCP/UDP) ----------
			if ((protocol == 6 || protocol == 17) && pktLen >= eth_header_len + ip_header_len + 8)
			{
				strDetail += tempStr;
				const u_char* trans_header = (rawData + eth_header_len + ip_header_len);
				u_short sport = ntohs(*(u_short*)(trans_header));
				u_short dport = ntohs(*(u_short*)(trans_header + 2));

				if (protocol == 6) //TCP
				{
					u_int seq = ntohl(*(u_int*)(trans_header + 4));
					u_int ack = ntohl(*(u_int*)(trans_header + 8));
					u_short flags = ntohs(*(u_short*)(trans_header + 12)) & 0x01FF; //标志位

					CString strFlags;
					if (flags & 0x002) strFlags += _T("SYN(同步), ");
					if (flags & 0x010) strFlags += _T("ACK(确认), ");
					if (flags & 0x001) strFlags += _T("FIN(结束), ");
					if (flags & 0x004) strFlags += _T("RST(重置), ");
					if (flags & 0x008) strFlags += _T("PSH(推送), ");
					if (strFlags.IsEmpty()) strFlags = _T("无 ");
					else strFlags = strFlags.Left(strFlags.GetLength() - 2); //去掉最后的逗号

					//计算数据内容长度
					u_short tcp_header_len = (*(trans_header + 12) >> 4) * 4;
					int payload_len = pktLen - eth_header_len - ip_header_len - tcp_header_len;
					if (payload_len < 0) payload_len = 0;

					tempStr.Format(_T("[传输层]\tTCP协议, 源端口: %d, 目的端口: %d, "), sport, dport);
					strDetail += tempStr;
					tempStr.Format(_T("序列号: %u, 确认号: %u, 数据长度: %d, "), seq, ack, payload_len);
					strDetail += tempStr;
					tempStr.Format(_T("标志位: %s\r\n"), (LPCTSTR)strFlags);
					strDetail += tempStr;
					//判断是否是HTTP端口
					if (sport == 80 || dport == 80 || sport == 8080 || dport == 8080)
					{
						tempStr.Format(_T("[应用层]\tHTTP协议"));
						strDetail += tempStr;

						//提取HTTP内容
						const u_char* payload = trans_header + tcp_header_len;
						if (payload_len > 0)
						{
							CString strPayload = _T("");
							//只取前面最多100个字节看看
							int checkLen = payload_len < 100 ? payload_len : 100;
							for (int i = 0; i < checkLen; i++)
							{
								if (payload[i] >= 32 && payload[i] <= 126) {
									strPayload += (char)payload[i];
								}
								else {
									strPayload += ".";
								}
							}
							if (payload_len > 100) {
								strPayload += "......";
							}
							tempStr.Format(_T(", 应用数据: %s\r\n"), (LPCTSTR)strPayload);
							strDetail += tempStr;
						}
					}
					else if (sport == 443 || dport == 443)
					{
						//HTTPS只显示协议名，不显示内容
						tempStr.Format(_T("[应用层]\tHTTPS协议(加密数据不解析)\r\n"));
						strDetail += tempStr;
					}
				}
				else if (protocol == 17) //UDP
				{
					u_short udp_len = ntohs(*(u_short*)(trans_header + 4));
					tempStr.Format(_T("[传输层]\tUDP协议, 源端口: %d, 目的端口: %d, "), sport, dport);
					strDetail += tempStr;
					tempStr.Format(_T("UDP总长度: %d\r\n"), udp_len);
					strDetail += tempStr;
				}				
			}
			else if (protocol == 1 && pktLen >= eth_header_len + ip_header_len + 4)
			{//ICMP
				const u_char* icmp_header = rawData + eth_header_len + ip_header_len;
				u_char icmp_type = icmp_header[0];
				u_char icmp_code = icmp_header[1];

				CString strIcmpType;
				if (icmp_type == 8) strIcmpType = _T("请求回显 (Ping Request)");
				else if (icmp_type == 0) strIcmpType = _T("回显应答 (Ping Reply)");
				else if (icmp_type == 3) strIcmpType = _T("目标不可达");
				else strIcmpType = _T("其他 ICMP 报文");

				tempStr.Format(_T("[网络层]\tICMP协议, 类型: %d (%s), 代码: %d\r\n"), icmp_type, (LPCTSTR)strIcmpType, icmp_code);
				strDetail += tempStr;
			}
			else {
				strDetail += tempStr;
			}
		}
		// ---------- IPv6 ----------
		else if (pktLen >= eth_header_len + 40 && eth_type == 0x86DD)
		{
			tempStr.Format(_T("[网络层]\tIPv6报文, "));
			strDetail += tempStr;
			tempStr.Format(_T("下一个头部: %02X, "), rawData[eth_header_len + 6]);
			strDetail += tempStr;
			tempStr.Format(_T("跳数限制: %d\r\n"), rawData[eth_header_len + 7]);
			strDetail += tempStr;

			u_char next_header = rawData[eth_header_len + 6];
			if (next_header == 58)
			{//ICMPv6
				const u_char* icmp6_header = rawData + eth_header_len + 40;
				if (pktLen >= eth_header_len + 40 + 4)
				{
					u_char icmp6_type = icmp6_header[0];
					u_char icmp6_code = icmp6_header[1];
					CString strIcmp6Type;
					if (icmp6_type == 128) strIcmp6Type = _T("请求回显 (Ping Request)");
					else if (icmp6_type == 129) strIcmp6Type = _T("回显应答 (Ping Reply)");
					else if (icmp6_type == 133) strIcmp6Type = _T("路由器请求");
					else if (icmp6_type == 134) strIcmp6Type = _T("路由器通告");
					else if (icmp6_type == 135) strIcmp6Type = _T("邻居请求 (类似ARP)");
					else if (icmp6_type == 136) strIcmp6Type = _T("邻居通告");
					else strIcmp6Type = _T("其他 ICMPv6 报文");

					tempStr.Format(_T("[传输层]\tICMPv6协议, 类型: %d (%s), 代码: %d\r\n"), icmp6_type, (LPCTSTR)strIcmp6Type, icmp6_code);
					strDetail += tempStr;
				}
			}
		}
		// ---------- ARP ----------
		else if (pktLen >= eth_header_len + 28 && eth_type == 0x0806)
		{
			tempStr.Format(_T("[网络层]\tARP协议(地址解析)\r\n"));
			strDetail += tempStr;
		}

		m_editDetail.SetWindowText(strDetail);
	}

	*pResult = 0;
}

void CYSnifferDlg::OnBnClickedCheckIpv4()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateBpfFilter();
}

void CYSnifferDlg::OnBnClickedCheckIpv6()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateBpfFilter();
}

void CYSnifferDlg::OnBnClickedCheckTcp()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateBpfFilter();
}

void CYSnifferDlg::OnBnClickedCheckUdp()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateBpfFilter();
}

void CYSnifferDlg::OnBnClickedCheckHttp()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateBpfFilter();
}

void CYSnifferDlg::OnBnClickedCheckIcmp()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateBpfFilter();
}

void CYSnifferDlg::OnBnClickedButtonClear()
{
	// TODO: 在此添加控件通知处理程序代码
	//清空列表中保存的rawData数据
	int nCount = m_listPackets.GetItemCount();
	for (int i = 0; i < nCount; ++i)
	{
		u_char* raw = (u_char*)m_listPackets.GetItemData(i);
		if (raw) {
			delete[] raw;
		}
	}
	//清空列表控件里的所有项
	m_listPackets.DeleteAllItems();
	//清空下方的详情框和十六进制框
	if (GetDlgItem(IDC_EDIT_DETAIL)) GetDlgItem(IDC_EDIT_DETAIL)->SetWindowText(_T(""));
	if (GetDlgItem(IDC_EDIT_HEX)) GetDlgItem(IDC_EDIT_HEX)->SetWindowText(_T(""));
}

void CYSnifferDlg::OnBnClickedButtonFollow()
{
	// TODO: 在此添加控件通知处理程序代码
	//若当前已经处于追踪状态，点击则取消追踪
	if (m_bIsFollowing)
	{
		m_bIsFollowing = false;
		m_lockSrcIp.Empty();
		m_lockDstIp.Empty();
		GetDlgItem(IDC_BUTTON_FOLLOW)->SetWindowText(_T("追踪"));
		return;
	}

	//若没选中任何行，提示用户
	POSITION pos = m_listPackets.GetFirstSelectedItemPosition();
	if (pos == NULL)
	{
		MessageBox(_T("请先在列表中选中一个数据包！"), _T("提示"));
		return;
	}

	//获取选中的行，记录源IP和目的IP
	int nSelected = m_listPackets.GetNextSelectedItem(pos);
	m_lockSrcIp = m_listPackets.GetItemText(nSelected, 2);
	m_lockDstIp = m_listPackets.GetItemText(nSelected, 3);

	//设置追踪状态
	m_bIsFollowing = true;
	GetDlgItem(IDC_BUTTON_FOLLOW)->SetWindowText(_T("停止"));

	//清空当前列表
	OnBnClickedButtonClear();
}

//获取过滤规则
CStringA CYSnifferDlg::GetCurrentBpfString()
{
	CStringA bpfFilter;
	if (IsDlgButtonChecked(IDC_CHECK_HTTP) == BST_CHECKED) bpfFilter += "port 80 or port 8080 or ";
	if (IsDlgButtonChecked(IDC_CHECK_TCP) == BST_CHECKED)  bpfFilter += "tcp or ";
	if (IsDlgButtonChecked(IDC_CHECK_UDP) == BST_CHECKED)  bpfFilter += "udp or ";
	if (IsDlgButtonChecked(IDC_CHECK_IPV4) == BST_CHECKED) bpfFilter += "ip or ";
	if (IsDlgButtonChecked(IDC_CHECK_IPV6) == BST_CHECKED) bpfFilter += "ip6 or ";
	if (IsDlgButtonChecked(IDC_CHECK_ICMP) == BST_CHECKED) bpfFilter += "icmp or icmp6 or ";

	if (bpfFilter.GetLength() > 4)
		bpfFilter = bpfFilter.Left(bpfFilter.GetLength() - 4); //去掉末尾的or
	else
		bpfFilter = ""; //如果全没勾选，返回空字符串，不过滤

	return bpfFilter;
}

//更新过滤规则
void CYSnifferDlg::UpdateBpfFilter()
{
	if (g_adhandle == NULL) return; //没在抓包，不用管

	CStringA bpfStr = GetCurrentBpfString();
	struct bpf_program fcode;

	//若bpfStr为空，则规则设为""
	const char* filterChar = bpfStr.IsEmpty() ? "" : bpfStr.GetString();

	if (pcap_compile(g_adhandle, &fcode, filterChar, 1, PCAP_NETMASK_UNKNOWN) >= 0)
	{
		if (pcap_setfilter(g_adhandle, &fcode) >= 0)
		{
			OutputDebugString(_T("更新过滤规则成功: ") + CString(filterChar) + _T("\n"));
		}
		pcap_freecode(&fcode);
	}
}
