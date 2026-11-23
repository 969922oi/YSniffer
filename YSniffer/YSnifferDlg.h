
// YSnifferDlg.h: 头文件
//

#pragma once

// 网络数据包接收消息号
#define WM_PACKET_RECEIVED (WM_USER + 100)

// 用于传递网络数据包内容的结构体
struct PacketData {
	CString infoStr;      //列表显示信息
	u_char* rawData;      //原始二进制数据
	int rawLen;           //原始数据长度
};

// CYSnifferDlg 对话框
class CYSnifferDlg : public CDialogEx
{
// 构造
public:
	CYSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_YSNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();//初始化
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_listPackets;//数据包列表
	CComboBox m_comboAdapter;//网络适配器
	CEdit m_editDetail;//详细信息
	CEdit m_editHex;//16进制信息
	CFont m_fontHex; // 用于十六进制显示的等宽字体
	bool ShouldPassFilter(const CString& strProtocol, u_short eth_type, const CString& strSrc, const CString& strDst);//软过滤器
	CStringA GetCurrentBpfString();//获取过滤规则
	void UpdateBpfFilter();//更新过滤规则
	static UINT SnifferThread(LPVOID pParam);//抓包线程
	afx_msg LRESULT OnPacketReceived(WPARAM wParam, LPARAM lParam);//处理抓到的数据的回调函数
	afx_msg void OnBnClickedButtonStart();//开始抓包
	afx_msg void OnBnClickedButtonRefresh();//刷新玩咖
	afx_msg void OnLvnItemchangedListPackets(NMHDR* pNMHDR, LRESULT* pResult);//列表选中
	afx_msg void OnBnClickedCheckIpv4();//过滤IPV4
	afx_msg void OnBnClickedCheckIpv6();//过滤IPV6
	afx_msg void OnBnClickedCheckTcp();//过滤TCP
	afx_msg void OnBnClickedCheckUdp();//过滤UDP
	afx_msg void OnBnClickedCheckHttp();//过滤HTTP
	afx_msg void OnBnClickedCheckIcmp();//过滤ICMP
	afx_msg void OnBnClickedButtonClear();//清空列表
	afx_msg void OnBnClickedButtonFollow();//追踪数据
};
