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
            fd, self.config_file = tempfile.mkstemp(suffix='.json')
            os.write(fd, json.dumps(config).encode())
            os.close(fd)
            
            # 启动 v2ray 进程，使用项目目录下的可执行文件
            self.process = subprocess.Popen(
                [self.v2ray_path, '-config', self.config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # 设置工作目录为v2ray目录，这样它能找到geoip.dat等文件
                cwd=str(self.base_dir / 'v2ray')
            )
            
            # 等待启动
            await asyncio.sleep(2)
            
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
        # 这里需要根据不同协议生成对应的配置
        # 示例配置
        return {
            "inbounds": [{
                "port": port,
                "protocol": "http",
                "settings": {}
            }],
            "outbounds": [{
                "protocol": "vmess",  # 或其他协议
                "settings": {
                    # 解析 node_url 并设置对应的配置
                }
            }]
        }

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