from playwright.sync_api import sync_playwright
import time
from datetime import datetime
import requests
from pathlib import Path
import base64
import json
from urllib.parse import unquote
import urllib3

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def get_node_identifier(node_url):
    """获取节点的唯一标识"""
    try:
        if node_url.startswith('vmess://'):
            vmess_data = decode_vmess(node_url)
            if vmess_data:
                return f"vmess_{vmess_data['add']}_{vmess_data['port']}_{vmess_data['id']}"
        
        elif node_url.startswith('ss://'):
            from urllib.parse import urlparse
            parsed = urlparse(node_url)
            
            if '@' in parsed.netloc:
                userpass, hostport = parsed.netloc.split('@')
                method_password = base64.b64decode(userpass.encode()).decode().split(':')
            else:
                base64_str = parsed.netloc.split('#')[0]
                decoded = base64.b64decode(base64_str.encode()).decode()
                if '@' in decoded:
                    method_password, hostport = decoded.rsplit('@', 1)
                else:
                    method_password, hostport = decoded.split('@')
                method_password = method_password.split(':')
            
            host, port = hostport.split(':')[0], hostport.split(':')[1].split('#')[0]
            return f"ss_{host}_{port}_{method_password[0]}_{method_password[1]}"
        
        elif node_url.startswith('trojan://'):
            from urllib.parse import urlparse
            parsed = urlparse(node_url)
            userpass = parsed.netloc.split('@')
            host, port = userpass[1].split(':')
            password = userpass[0]
            return f"trojan_{host}_{port}_{password}"
        
        elif node_url.startswith('vless://'):
            from urllib.parse import urlparse
            parsed = urlparse(node_url)
            userpass = parsed.netloc.split('@')
            host, port = userpass[1].split(':')
            uuid = userpass[0]
            return f"vless_{host}_{port}_{uuid}"
            
    except Exception as e:
        print(f"生成节点标识符失败: {str(e)}")
    
    # 如果解析失败，返回完整的URL作为标识符
    return node_url

def filter_content(content):
    """
    过滤内容：
    1. 检查内容是否需要base64解密
    2. 只保留以代理协议开头的行
    3. 确保每行都是完整的节点信息
    4. 去除重复节点
    """
    if not content:
        return ""
    
    # 支持的代理协议
    PROXY_PROTOCOLS = ('vmess://', 'ss://', 'ssr://', 'trojan://', 'vless://')
    
    # 检查内容是否需要base64解密
    if '://' not in content and is_base64(content):
        try:
            content = base64.b64decode(content).decode('utf-8')
        except Exception as e:
            print(f"Base64解码失败: {str(e)}")
            return ""
    
    # 按行分割并去除空白字符
    lines = [line.strip() for line in content.split('\n') if line.strip()]
    
    # 用于去重的集合
    unique_nodes = {}
    
    # 过滤和验证每一行
    for line in lines:
        # 检查是否以支持的协议开头
        if any(line.startswith(protocol) for protocol in PROXY_PROTOCOLS):
            # 对于vmess链接，验证并解码其内容
            if line.startswith('vmess://'):
                vmess_data = decode_vmess(line)
                if vmess_data and isinstance(vmess_data, dict):
                    node_id = get_node_identifier(line)
                    unique_nodes[node_id] = line
            # 对于其他协议，只要格式正确就保留
            elif '@' in line or '#' in line or '?' in line:
                node_id = get_node_identifier(line)
                unique_nodes[node_id] = line
    
    # 如果有有效的节点信息，返回去重后的内容
    if unique_nodes:
        return '\n'.join(unique_nodes.values())
    
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

if __name__ == '__main__':
    # 先获取节点
    get_node_info()
    get_nodefree_info()