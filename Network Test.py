import os
import socket
import requests
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(filename='network_test.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_device_info():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])
        return {
            'hostname': hostname,
            'ip_address': ip_address,
            'mac_address': mac_address
        }
    except Exception as e:
        logging.error(f"获取设备信息失败: {e}")
        return None

def check_network_connection(target='8.8.8.8'):
    try:
        response = os.system(f"ping -c 1 {target}")
        if response == 0:
            logging.info(f"网络连接正常到 {target}")
            return True
        else:
            logging.warning(f"网络连接异常到 {target}")
            return False
    except Exception as e:
        logging.error(f"检查网络连接失败: {e}")
        return False

def dns_resolution_test(domain='www.google.com'):
    try:
ip_address = socket.gethostbyname(domain)
info（f"DNS解析成功：{domain}->{ip_address}"）
返回真
除了socket. gaierror e：
error（f“DNS解析失败：{e}”）
返回假

def http_request_test(url='https://www.google.com'):
    try:
response = requests.get(url, timeout=5)
如果response.status_code===200：
info（f"HTTP请求成功：{url}->{response. status_code}"）
返回真
        else:
warning（f"HTTP请求返回非 200 mayodo：{url}->{response. status_code}"）
返回假
除外：
error（f“HTTP请求失败：{e}”）
返回假

def port_scan_test(ip='192.168.1.1', ports=[80, 443]):
open_ports = []
港口：
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
result = sock.connect_ex((ip, port))
如果result==0：
info（f"端口开放：{ip}：{port}"）
                open_ports.append(port)
            else:
info（f"端口关闭：{ip}：{port}"）
错误e除外：
error（f“端口扫描失败：{e}”）
        finally:
            sock.close()
返回open_ports

def vulnerability_scan_test(ip='192.168.1.1'):
    # 这里可以调用专业的漏洞扫描工具API，如Nessus或OpenVAS
info（f“开始漏洞扫描：{ip}”）
    # 示例返回值
漏洞=["CVE-2021-44228"，"CVE-2021-34527"]
info（f“发现漏洞：{villays}”）
返回漏洞

def main():
info（“开始网络测试”）
device_info = get_device_info()
如果不是device_info：
        logging.error("无法继续测试，设备信息获取失败")
返回

info（f“设备信息：{device_info}”）

如果不是，check_network_connection（）：
        logging.error("网络连接异常，无法继续测试")
返回

如果不是dns_resolution_test（）：
warning（“DNS解析失败，you you you you”）

如果不是http_request_test（）：
warning（“HTTP请求失败，you youth you you”）

open_ports = port_scan_test()
info（f“开放端口：{open_ports}”）

vulnerabilities = vulnerability_scan_test()
info（f“发现漏洞：{villays}”）

info（“网络测试完成”）

if __name__ == "__main__":
主要的()
