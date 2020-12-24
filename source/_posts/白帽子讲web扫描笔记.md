---
title: 白帽子讲web扫描笔记
date: 2020-12-24 14:29:49
tags:
---

查看几款扫描器的能力  
http://www.sectoolmarket.com/price-and-feature-comparison-of-web-application-scanners-unified-list.html  


使用wavsep项目作为扫描器的靶场也是一个评估  

## 爬取
### 一些请求中的技巧
使用 HEAD方法 加快对检测链接或者目录的有效性 因为与GET是一样的  
除了不会返回响应体 响应体不返回就会节约很多时间  

对于页面url的爬取不能单纯采用深度和广度爬取  
我们需要对页面的url先进行评估 是一种启发式的爬取  
最多的还是广度优先遍历和 追加优先策略  

URL 有相似的这个概念即 ID=1 ID=2这种的 参数名参数个数  

还有URL包含 参数的多少包含关系 这种要注意  

页面相似算法 编辑距离和Simhash  

要注意断连重试  

他对每个url解析了解析成字典 
还封装了一个返回请求字符串的  

对requests进行了二次封装  比如请求头啊什么的响应呀的  

### 使用DNS缓存优化

这里还对dns的使用进行了优化  
如果 该域名已经被查询过 那么直接返回dns查询结果 否则  

网上看还是有用的我们试试  

```python
import socket

_dnscache={}
def _setDNSCache():
    """
    Makes a cached version of socket._getaddrinfo to avoid subsequent DNS requests.
    """

    def _getaddrinfo(*args, **kwargs):
        global _dnscache
        if args in _dnscache:
            print str(args)+" in cache"
            return _dnscache[args]

        else:
            print str(args)+" not in cache"  
            _dnscache[args] = socket._getaddrinfo(*args, **kwargs)
            return _dnscache[args]

    if not hasattr(socket, '_getaddrinfo'):
        socket._getaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = _getaddrinfo

def test():
	_setDNSCache()
	import urllib
	urllib.urlopen('http://www.baidu.com')
	urllib.urlopen('http://www.baidu.com')

test()
```  

代码
```python
import socket
# from gevent import socket
_dnscache = {}
def _setDNSCache():
  """ DNS缓存 """
  def _getaddrinfo(*args, **kwargs):
    if args in _dnscache:
      # print str(args) + " in cache"
      return _dnscache[args]
    else:
      # print str(args) + " not in cache"
      _dnscache[args] = socket._getaddrinfo(*args, **kwargs)
      return _dnscache[args]
  if not hasattr(socket, '_getaddrinfo'):
    socket._getaddrinfo = socket.getaddrinfo
    socket.getaddrinfo = _getaddrinfo
```

可以将上面的代码放在一个dns_cache.py文件里，爬虫框架里调用一下这个_setDNSCache()方法就行了。  

其实Windows本身是有DNS缓存机制的，访问一个域名后，系统会缓存下域名对应的IP。我们的爬虫通常是运行在Linux上的，Linux本身一般是没有DNS缓存的。  

### 第三方库管理dns缓存加快速度
https://github.com/s0md3v/velocity

```python
import requests
import velocity

for i in range(10):
     requests.get('https://s0md3v.github.io')

# 重要：如果使用线程，请考虑手动缓存主机名，以防止数据库受到竞争条件的影响
```
这个代码真滴low  



### 布隆过滤器 BloomFilter  
这里讲了下布隆过滤器 BloomFilter  
就是说这个方法就是说 我现在有三个元素 x,y,z 
有三个hash函数 a,b,c  
把x过a,b,c 然后看对应位置上  
如果a,b,c三个函数的值就是位置都是1 则可能存在否则一定不存在  
是存在一定的误判的 是可能存在 一定不存在  
python使用的话  

```python
from bloom_filter import BloomFilter
# 生成一个装1亿大小的
bloombloom = BloomFilter(max_elements=100000000, error_rate=0.1)
# 向bloom添加URL
bloom.add('https://www.tianyancha.com/company/23402373')
#判断URL是否在
bloombloom.__contains__('https://www.tianyancha.com/company/23402373')
```  

### 使用adsl拨号更换ip比ip代理池更便宜  

```python
windows下用os调用rasdial拨号：

import os
# 拨号断开
os.popen('rasdial 网络链接名称 /disconnect')
# 拨号
os.popen('rasdial 网络链接名称 adsl账号 adsl密码')

linux下拨号：

import os
# 拨号断开
code = os.system('ifdown 网络链接名称')
# 拨号
code = os.system('ifup 网络链接名称')
```

### 线程是怎么选择的具体多少呢
需要我们测试 从一个线程到多个线程  
线程个数、总抓取次数、抓取成功次数、耗时  

从这几个角度测试比较找到最优

### requests请求优化
要优化requests.get(timeout=1.5)的超时时间  
1.5s比10s好多了 实在不行了还可以重试  

### 为什么不使用异步  
异步是对程序逻辑的的性能 主要问题是网络性能  
而且爬取太快对网站也有影响  

### 如何控制速率

两种方式  
1. 通过构建一个队列 启动个线程每次去这个队列里去取出来 控制这个  
有次面试也说的叫令牌桶的概念  
2. 通过hook socket中的connect函数来在请求发送之前进行时间间隔的统一控制和处理  

hook socket的方式是 加载替换 connect方法  
然后在里面进行 while True的执行 计算时间后break这样  

### 页面解析
需要解析几个地方和字段  
```python
URL_HEADERS = ('location')
URL_TAGS = ('a', 'img', 'link', 'script', 'iframe', 'frame', 'form', 'object')
URL_ATTRS = ('href', 'src', 'data', 'action')
URL_RE = re.compile('(http|https)://([\w:@\-\./]*?)[^ \n\r\t"\'<>]\s)*)', re.U|re.I)
# 先判断 tags 里有没有 attrs的属性 有的话提取
```

三者合一 得到当前页面解析的url  

### 表单自动提交
是通过解析到的from后根据表单字段匹配 使用默认的表单内容字段  




### URL去重
1.使用布隆过滤器  
后面url的长度越来越长 最好是进行固定长度  
于是这里使用了hash对url进行固定长度
2. hash去重  
就是用list存储 然后判断 是否in 这个list 当时咱们看过一个对于大型list怎么判断 可以做成字典来去处理  

还有相似性的去重  
主要是对其url进行泛化  
比如 a=1&b=2&c=3 与 b=1&c=2&a=3  
其实是一个url 我们就可以对其进行排序+泛化变为 a=@&b=@&c=@ 这种形式  


### 404页面识别
1. 先构造一些不可能存在的页面 触发404 
将页面与404页面进行相似度比较  

### 重试
使用装饰器对请求进行超时重试  
在装饰器参数中支持重试次数和下次重试时间  


### 爬虫的限制
```python
# 控制爬行的深度
if depth > self.depth_limit:
    print "depth limit break"
    break
# 控制爬行的时间
if self.get_discovery_time() > self.time_limit:
    print "time limit break"
    break

# 控制爬行的链接数，避免内存泄露
if self.num_reqs > self.req_limit:
    print "reqs num limit break"
    break
```

### web2.0的url获取
```python
def CrawlAjax(url):
    # 存储最终爬取到的所有URL
    urls_out = []
    # 存储临时的URL 待过滤
    urls_temp = []
    # 初始化浏览器引擎 载入当前的URL页面
    browser.init()
    page = browser.open(url)
    # 获取当前页面中需要处理的事情
    events = page.get_events()
    # 获取当前页面中所有的URLS
    urls = page.get_urls()
    urls_temp.extends(urls)
    # 遍历状态深度为1的事件
    for i in events:
        # 对事件进行触发
        newpage_i = browser.do_event(i)
        # 获取页面中心的时间
        new_events = get_events(new_page, page)
        # 获取当前页面中所有的URL
        urls = newpage_i.get_urls()
        urls_temp.extends(urls)
        # 遍历状态深度为2的如上 再次for new_events 事件进行操作
```

比如说对a标签进行点击  
对按钮进行点击  
a标签获取会重复 使用 href onclick作为属性作为hash  
这个后续可以读下其他的源码  


## 指纹识别

1. 内容特征 在响应体中

2. 页面特征 有固定页面 可以直接hash判断

3. Headers特征 独有的报头信息  

## 安装漏洞审计
1. 需要分析现实现中这个漏洞的各种场景
2. 构造出可以覆盖所有漏洞场景的扫描载荷  
3. 将其转化为扫描器的检查脚本并生成最终的扫描签名  

安全漏洞可以分为两类 通用型漏洞 Nday/0day漏洞  

通用型就是 具有普遍性 sql注入、xss、 命令执行等  

Nday/0day就是针对某一个具体应用 poc 直接就能打的  

这些具体的检查可以从单独的扫描器中提取出核心检测当时来操作

几个需要检测的点  
1. sql注入
2. xss
3. 命令执行
4. 文件包含
5. 信息泄露  (压缩备份文件 git文件泄露等 敏感信息配置文件等 着重)

需要注意的是扫描器是进行检验的不是进行攻击的  

## 扫描器进阶

### 信息收集
1. ip信息
2. 子域信息
3. 敏感信息
4. 指纹信息
5. url信息

模块的职责功能需要单一 模块中关联的功能尽可能在同一个模块中实现  
每个模块只负责一个功能 保证每个功能都是独立 减少依赖  


### 功能模块
1. 端口模块
    端口爆破探测 syn 半连接探测 无状态探测
3. 域名模块
    域名接口、证书、爆破
3. 探测模块
    路径的爆破 字典、分析后智能构造字典 默认文件路径 根据github开源项目路由解析提取
4. 指纹模块
    开源项目 核心在字典和架构、速度
5. 爬虫模块
    参考一些开源的实现 基于浏览器做的比较好 可增加被动代理模块 做流量分析而不是 再次探测
6. 漏洞检测模块
    通用漏洞和poc
7. 扫描引擎 调度
    整体的流程:
        1.子域名爆破/监控->2.任务下发到端口-> 拿到大量服务-> 3.爬虫获取url 探测路径 漏洞检测等
8. 报告模块
    主要是好看 好理解 到底想要什么  

注重分层设计  

### 提升
拿靶场进行测试 扫描到了后误报进行规避 漏报进行处理  

## 云扫描
主要就是多work的形式还有队列加上webUI  
这么主要是架构方面的变化  

## 企业安全扫描实践

基于网络流量的扫描 最普遍以及使用的就是DPDK  

DPDK 对硬件有要求 需要Intel 并且需要至少两个CPU 三个网卡  
需要源码编译 并且有bug需要手动打补丁后编译  
安装完成后就可以用dpdk-pdump来捕获网络流量了  

后面可以解析pcap包来判断
还有一种是基于访问日志 比如splunk 来处理  

可以给nginx安装个 模块来获取到请求的post数据  
安装 lua语言  ngx_dev_kit 模块 lua_nginx_moudle模块  


 ## 防御
 1. 可以在页面标签中加个隐藏的url 访问了就是扫描器  
 2. 日志
 

## 参考
如何让爬虫一天抓取100万张网页  
https://mp.weixin.qq.com/s?__biz=MjM5NjE0NTY5OA==&mid=2448548659&idx=1&sn=d2a8dd3544bfd7980c8ab1fbb0c5dd4b&chksm=b2e8fc7e859f7568b41fcc55b384e9d78a4c4503707ac34c890a3be17ecfe2d40df4bc3602d5&scene=21#wechat_redirect  

