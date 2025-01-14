from playwright.sync_api import sync_playwright
import time
from datetime import datetime
import requests
from pathlib import Path
import base64
import json
from urllib.parse import unquote
import asyncio
import aiohttp
import subprocess
import tempfile
import os
import random

def is_base64(s):
    """检查字符串是否为base64编码"""
    try:
        # 尝试解码
        decoded = base64.b64decode(s).decode('utf-8')
        # 重新编码
        encoded = base64.b64encode(decoded.encode('utf-8')).decode('utf-8')
        # 如果重新编码后与原字符串相同（忽略填充），则可能是base64
        return s.replace('=', '') == encoded.replace('=', '')
    except Exception:
        return False

def decode_vmess(vmess_str):
    """解码vmess链接"""
    try:
        # 移除 'vmess://' 前缀
        base64_str = vmess_str.replace('vmess://', '')
        # 解码base64
        decoded = base64.b64decode(base64_str).decode('utf-8')
        # 解析JSON
        vmess_data = json.loads(decoded)
        return vmess_data
    except Exception:
        return None

def filter_content(content):
    """
    过滤内容：
    1. 只保留以代理协议开头的行
    2. 确保每行都是完整的节点信息
    3. 对特定协议的内容进行解码验证
    """
    if not content:
        return ""
    
    # 支持的代理协议
    PROXY_PROTOCOLS = ('vmess://', 'ss://', 'ssr://', 'trojan://', 'vless://')
    
    # 按行分割并去除空白字符
    lines = [line.strip() for line in content.split('\n') if line.strip()]
    
    # 过滤和验证每一行
    valid_lines = []
    for line in lines:
        # 检查是否以支持的协议开头
        if any(line.startswith(protocol) for protocol in PROXY_PROTOCOLS):
            # 对于vmess链接，验证并解码其内容
            if line.startswith('vmess://'):
                vmess_data = decode_vmess(line)
                if vmess_data and isinstance(vmess_data, dict):
                    valid_lines.append(line)
            # 对于其他协议，只要格式正确就保留
            elif '@' in line or '#' in line or '?' in line:
                valid_lines.append(line)
    
    # 如果有有效的节点信息，返回过滤后的内容
    if valid_lines:
        return '\n'.join(valid_lines)
    
    return ""

def get_node_info():
    try:
        print('开始启动浏览器...')
        with sync_playwright() as p:
            # 启动浏览器
            browser = p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage'
                ]
            )
            print('浏览器启动成功')

            # 创建新页面
            print('正在创建新页面...')
            context = browser.new_context()
            page = context.new_page()
            
            # 设置视窗大小
            page.set_viewport_size({"width": 1920, "height": 1080})
            print('页面创建完成，视窗已设置')

            # 设置请求头
            context.set_extra_http_headers({
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'zh-CN,zh;q=0.9',
                'cache-control': 'max-age=0',
                'dnt': '1',
                'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
            })

            # 访问目标网页
            print('正在访问目标网页...')
            start_time = time.time()
            page.goto(
                'https://banyunxiaoxi.icu/category/vpn%e8%8a%82%e7%82%b9/',
                wait_until='domcontentloaded',
                timeout=300000
            )
            print('目标网页加载完成')

            # 等待元素加载
            print('等待选择器加载...')
            page.wait_for_selector('#nav-new a:first-child', timeout=300000)
            end_time = time.time()
            print(f'选择器加载完成，耗时 {(end_time - start_time) * 1000}ms')

            # 获取链接
            print('正在获取链接...')
            href = page.locator('#nav-new a:first-child').get_attribute('href')
            print('获取到链接:', href)

            # 访问获取到的链接
            print('正在访问获取到的链接...')
            start_time2 = time.time()
            page.goto(href, wait_until='domcontentloaded', timeout=300000)

            # 等待内容加载
            print('等待内容加载...')
            page.wait_for_selector('#lightgallery > blockquote > p', timeout=300000)

            # 获取内容
            print('正在提取目标内容...')
            content = page.locator('#lightgallery > blockquote > p').text_content()
            end_time2 = time.time()
            print(f'内容提取成功，总耗时: {(end_time2 - start_time2) * 1000}ms')

            # 关闭浏览器
            browser.close()
            print('浏览器已关闭')

            # 检查内容是否为空并过滤内容
            if content and content.strip():
                # 过滤内容
                filtered_content = filter_content(content)
                
                if filtered_content:
                    # 直接写入过滤后的节点内容
                    with open('xiaoxi.txt', 'w', encoding='utf-8') as f:
                        f.write(filtered_content)
                    print('数据已保存到xiaoxi.txt文件')
                else:
                    print('过滤后的内容为空，未保存文件')
            else:
                print('获取的内容为空，未保存文件')

    except Exception as e:
        print('执行过程中发生错误:')
        print({'success': False, 'error': str(e)})

def get_nodefree_info():
    """获取 nodefree 的节点信息并保存到文件"""
    try:
        # 构建当前日期的URL
        date = datetime.now()
        url = f"https://nodefree.githubrowcontent.com/{date.year}/{date.strftime('%m')}/{date.strftime('%Y%m%d')}.txt"
        
        print(f'正在获取nodefree节点，URL: {url}')
        
        # 发送请求
        response = requests.get(
            url,
            verify=False,  # 忽略SSL证书验证
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
            },
            timeout=30
        )
        
        # 检查响应状态
        if response.status_code == 200:
            # 获取内容并过滤
            content = response.text
            if content and content.strip():
                filtered_content = filter_content(content)
                
                if filtered_content:
                    # 保存到文件
                    with open('nodefree.txt', 'w', encoding='utf-8') as f:
                        f.write(filtered_content)
                    print('nodefree节点数据已保存到nodefree.txt文件')
                    return True
                else:
                    print('nodefree过滤后的内容为空')
            else:
                print('nodefree获取的内容为空')
        else:
            print(f'nodefree请求失败，状态码: {response.status_code}')
            
    except Exception as e:
        print('获取nodefree节点时发生错误:')
        print(str(e))
    
    return False

class V2rayController:
    def __init__(self):
        self.process = None
        self.config_file = None
        self.port = None
        # 获取项目根目录
        self.base_dir = Path(__file__).parent
        # v2ray可执行文件路径
        self.v2ray_path = str(self.base_dir / 'v2ray' / 'v2ray.exe')
    
    async def start(self, node_url):
        """启动 V2ray"""
        try:
            # 生成随机端口
            self.port = random.randint(10000, 60000)
            
            # 创建临时配置文件
            config = self._generate_config(node_url, self.port)
            if not config:
                print(f"无法为节点生成配置: {node_url}")
                return False
            
            fd, self.config_file = tempfile.mkstemp(suffix='.json')
            os.write(fd, json.dumps(config).encode())
            os.close(fd)
            
            # 启动 v2ray 进程，添加 run 命令
            self.process = subprocess.Popen(
                [self.v2ray_path, 'run', '-c', self.config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.base_dir / 'v2ray')
            )
            
            # 等待启动
            await asyncio.sleep(2)
            
            # 检查进程是否还在运行
            if self.process.poll() is not None:
                error = self.process.stderr.read().decode()
                print(f"V2ray 启动失败: {error}")
                return False
            
            return True
        except Exception as e:
            print(f"启动 V2ray 失败: {str(e)}")
            return False
    
    async def stop(self):
        """停止 V2ray"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None
        
        if self.config_file and os.path.exists(self.config_file):
            os.remove(self.config_file)
            self.config_file = None
    
    def _generate_config(self, node_url, port):
        """生成 V2ray 配置"""
        try:
            # 基础配置
            config = {
                "log": {
                    "loglevel": "warning"
                },
                "inbounds": [{
                    "port": port,
                    "protocol": "http",
                    "settings": {},
                    "tag": "http_in"
                }],
                "outbounds": [{
                    "protocol": "",
                    "settings": {},
                    "streamSettings": {
                        "network": "tcp",
                        "security": "none",
                        "tcpSettings": {
                            "header": {
                                "type": "none"
                            }
                        }
                    },
                    "tag": "proxy"
                },
                {
                    "protocol": "freedom",
                    "settings": {},
                    "tag": "direct"
                }],
                "routing": {
                    "domainStrategy": "IPOnDemand",
                    "rules": [{
                        "type": "field",
                        "outboundTag": "proxy",
                        "network": "tcp,udp"
                    }]
                }
            }

            # 处理 vmess 协议
            if node_url.startswith('vmess://'):
                vmess_data = decode_vmess(node_url)
                if vmess_data:
                    stream_settings = {
                        "network": vmess_data.get("net", "tcp"),
                        "security": "tls" if vmess_data.get("tls") == "tls" else "none"
                    }
                    
                    # 根据传输协议配置具体设置
                    if vmess_data.get("net") == "ws":
                        stream_settings["wsSettings"] = {
                            "path": vmess_data.get("path", "/"),
                            "headers": {
                                "Host": vmess_data.get("host", "")
                            }
                        }
                        # 移除 tcpSettings
                        if "tcpSettings" in stream_settings:
                            del stream_settings["tcpSettings"]
                    elif vmess_data.get("net") == "tcp":
                        stream_settings["tcpSettings"] = {
                            "header": {
                                "type": "none"
                            }
                        }
                    
                    # TLS 设置
                    if vmess_data.get("tls") == "tls":
                        stream_settings["tlsSettings"] = {
                            "serverName": vmess_data.get("host", ""),
                            "allowInsecure": True
                        }
                    
                    config["outbounds"][0].update({
                        "protocol": "vmess",
                        "settings": {
                            "vnext": [{
                                "address": vmess_data["add"],
                                "port": int(vmess_data["port"]),
                                "users": [{
                                    "id": vmess_data["id"],
                                    "alterId": int(vmess_data.get("aid", 0)),
                                    "security": vmess_data.get("scy", "auto")
                                }]
                            }]
                        },
                        "streamSettings": stream_settings
                    })

            # 处理 vless 协议
            elif node_url.startswith('vless://'):
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(node_url)
                userpass = parsed.netloc.split('@')
                host, port = userpass[1].split(':')
                uuid = userpass[0]
                params = parse_qs(parsed.query)
                
                # 基本传输设置
                stream_settings = {
                    "network": params.get('type', ['tcp'])[0],
                    "security": params.get('security', ['none'])[0]
                }
                
                # 根据传输协议配置具体设置
                if params.get('type', [''])[0] == 'ws':
                    stream_settings["wsSettings"] = {
                        "path": params.get('path', ['/'])[0],
                        "headers": {
                            "Host": params.get('host', [''])[0]
                        }
                    }
                elif params.get('type', [''])[0] == 'tcp':
                    stream_settings["tcpSettings"] = {
                        "header": {
                            "type": "none"
                        }
                    }
                
                # TLS 设置
                if params.get('security', [''])[0] == 'tls':
                    stream_settings["tlsSettings"] = {
                        "serverName": params.get('sni', [params.get('host', [''])[0]])[0],
                        "allowInsecure": True
                    }
                
                config["outbounds"][0].update({
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": host,
                            "port": int(port),
                            "users": [{
                                "id": uuid,
                                "encryption": "none",
                                "flow": params.get('flow', [''])[0]
                            }]
                        }]
                    },
                    "streamSettings": stream_settings
                })

            # 处理 trojan 协议
            elif node_url.startswith('trojan://'):
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(node_url)
                userpass = parsed.netloc.split('@')
                host, port = userpass[1].split(':')
                password = userpass[0]
                params = parse_qs(parsed.query)
                
                config["outbounds"][0].update({
                    "protocol": "trojan",
                    "settings": {
                        "servers": [{
                            "address": host,
                            "port": int(port),
                            "password": password
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": params.get('sni', [host])[0],
                            "allowInsecure": True
                        }
                    }
                })

            # 处理 ss 协议
            elif node_url.startswith('ss://'):
                from urllib.parse import urlparse, unquote
                parsed = urlparse(node_url)
                
                try:
                    if '@' in parsed.netloc:
                        # 如果是 user:pass@host:port 格式
                        userpass, hostport = parsed.netloc.split('@')
                        method_password = base64.b64decode(userpass.encode()).decode().split(':')
                    else:
                        # 如果是 base64(method:password@host:port) 格式
                        decoded = base64.b64decode(parsed.netloc.encode()).decode()
                        if '@' in decoded:
                            method_password, hostport = decoded.rsplit('@', 1)
                            method_password = method_password.split(':')
                        else:
                            # 处理没有 @ 的情况
                            base64_str = parsed.netloc.split('#')[0]
                            decoded = base64.b64decode(base64_str.encode()).decode()
                            method_password, hostport = decoded.split('@')
                            method_password = method_password.split(':')
                    
                    host, port_str = hostport.split(':')
                    port_num = int(port_str.split('#')[0])  # 移除端口后的标签部分
                    
                    # 转换加密方法名称
                    method_mapping = {
                        'aes-256-cfb': 'aes-256-gcm',
                        'aes-128-cfb': 'aes-128-gcm',
                        'chacha20': 'chacha20-poly1305',
                        'chacha20-ietf': 'chacha20-poly1305',
                        'chacha20-poly1305': 'chacha20-poly1305',
                        'chacha20-ietf-poly1305': 'chacha20-poly1305',
                        'xchacha20-poly1305': 'xchacha20-poly1305',
                        'xchacha20-ietf-poly1305': 'xchacha20-poly1305',
                        'rc4-md5': 'chacha20-poly1305',
                        'aes-192-cfb': 'aes-256-gcm',
                        'aes-128-ctr': 'aes-128-gcm',
                        'aes-256-ctr': 'aes-256-gcm',
                        'aes-256-cfb1': 'aes-256-gcm',
                        'camellia-256-cfb': 'aes-256-gcm',
                        'camellia-192-cfb': 'aes-256-gcm',
                        'camellia-128-cfb': 'aes-128-gcm',
                    }
                    
                    # V2Ray 支持的加密方法
                    V2RAY_SUPPORTED_CIPHERS = {
                        'aes-128-gcm',
                        'aes-256-gcm',
                        'chacha20-poly1305',
                        'xchacha20-poly1305'
                    }
                    
                    method = method_mapping.get(method_password[0].lower(), 'chacha20-poly1305')
                    if method not in V2RAY_SUPPORTED_CIPHERS:
                        method = 'chacha20-poly1305'
                    
                    config["outbounds"][0].update({
                        "protocol": "shadowsocks",
                        "settings": {
                            "servers": [{
                                "address": host,
                                "port": port_num,
                                "method": method,
                                "password": method_password[1]
                            }]
                        }
                    })
                except Exception as e:
                    print(f"解析 SS 链接失败: {str(e)}")
                    return None

            # 确保 streamSettings 中不会同时存在多个协议的设置
            if "streamSettings" in config["outbounds"][0]:
                settings = config["outbounds"][0]["streamSettings"]
                if settings["network"] == "ws" and "tcpSettings" in settings:
                    del settings["tcpSettings"]
                elif settings["network"] == "tcp" and "wsSettings" in settings:
                    del settings["wsSettings"]

            # 打印生成的配置用于调试
            print(f"Generated config for {node_url}:")
            print(json.dumps(config, indent=2))

            return config
        except Exception as e:
            print(f"生成配置失败: {str(e)}")
            return None

async def test_node(node_url):
    """测试单个节点"""
    v2ray = V2rayController()
    try:
        # 启动 V2ray
        if not await v2ray.start(node_url):
            return {
                'url': node_url,
                'status': 'fail',
                'error': 'Failed to start V2ray',
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        
        # 使用节点访问测试网站
        async with aiohttp.ClientSession() as session:
            start_time = datetime.now()
            async with session.get(
                'http://www.gstatic.com/generate_204',
                proxy=f'http://127.0.0.1:{v2ray.port}',
                timeout=10
            ) as response:
                end_time = datetime.now()
                
                # 计算延迟
                delay = (end_time - start_time).total_seconds() * 1000
                
                return {
                    'url': node_url,
                    'status': 'ok',
                    'delay': round(delay, 2),
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
    except Exception as e:
        return {
            'url': node_url,
            'status': 'fail',
            'error': str(e),
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    finally:
        # 确保停止 V2ray
        await v2ray.stop()

async def test_nodes(filename):
    """测试文件中的所有节点"""
    try:
        # 读取节点文件
        with open(filename, 'r', encoding='utf-8') as f:
            nodes = [line.strip() for line in f if line.strip()]
        
        print(f'开始测试 {filename} 中的 {len(nodes)} 个节点...')
        
        # 并发测试节点
        tasks = [test_node(node) for node in nodes]
        results = await asyncio.gather(*tasks)
        
        # 分离可用和不可用的节点
        available = [r for r in results if r['status'] == 'ok']
        unavailable = [r for r in results if r['status'] == 'fail']
        
        # 按延迟排序可用节点
        available.sort(key=lambda x: x['delay'])
        
        # 保存测试结果
        result_file = f'test_results_{filename}'
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump({
                'test_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total': len(nodes),
                'available': len(available),
                'unavailable': len(unavailable),
                'available_nodes': available,
                'unavailable_nodes': unavailable
            }, f, ensure_ascii=False, indent=2)
            
        print(f'测试完成，结果已保存到 {result_file}')
        print(f'共测试 {len(nodes)} 个节点，可用 {len(available)} 个，不可用 {len(unavailable)} 个')
        
    except Exception as e:
        print(f'测试过程发生错误: {str(e)}')

async def main():
    """主函数"""
    # 测试两个文件中的节点
    await test_nodes('xiaoxi.txt')
    await test_nodes('nodefree.txt')

if __name__ == '__main__':
    # 先获取节点
    get_node_info()
    get_nodefree_info()
    
    # 然后测试节点
    print('开始测试节点...')
    asyncio.run(main()) 