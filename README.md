# Free Node Collector

自动采集免费节点并进行去重，每天更新。

## 使用方法

1. 直接下载 `all.txt` 文件（base64编码）
2. 解码后导入到你的代理工具中

## 节点来源

- banyunxiaoxi.icu
- nodefree
- 多个订阅源

## 文件说明

- `all.txt`: 所有节点合并去重后的结果
- `node/xiaoxi.txt`: 小夕网站的节点
- `node/nodefree.txt`: nodefree的节点
- `node/subscribe.txt`: 订阅源的节点

## 自动更新

使用 GitHub Actions 每天自动更新节点信息。

## 注意事项

所有保存的节点文件都经过 base64 编码，使用前需要解码。 