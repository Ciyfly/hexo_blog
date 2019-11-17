---
title: redis实战读书笔记(五)
date: 2019-11-17 15:49:51
tags:
  - 读书笔记
description: redis第五章的笔记 对redis的一些实例使用场景 主要是只用redis来解决一些问题
---
# Redis 第五章 

## Redis 使用Redis构建支付程序

主要是   
使用Redis记录日志  
使用Redis实现计数器并进行数据统计  
查询IP地址所属的城市与国家  
服务的发现与配置  

### 使用Redis来记录日志

#### 最新日志

程序使用LPUSH命令将日志消息推入一个列表里面 之后我们查看已有的日志消息的话  
那么可以使用 LRANGE命令来取出列表中的消息 还命名不同的日志消息队列 并根据问题的严重性对日志进行分级  
简单来说就是使用pipeline发送存储日志到redis列表并进行修剪限制最新

```python
# 设置一个字典 将大部分日志的安全级别映射为字符串
SERVERITY = {
    logging.DEBUG: 'debug',
    logging.INFO: 'info',
    logging.WARN: 'warn',
    logging.ERROR: 'error',
    logging.CRITICAL: 'critical'
}

SERVERITY.update((name, name) for name in SERVERITY.values())

def log_recent(conn, name, message, severity=logging.INFO, pipe=None):
    severity = str(SERVERITY.get(severity, severity)).lower()
    destination = 'recent:%s:%s' % (name, severity)
    message = time.asctime() + ''+ message
    pipe = pipe or conn.pipeline()
    pipe.lpush(destination, message)
    # 对日志列表进行修剪 让他只包含最新的100条消息
    pipe.ltrim(destination, 0, 99) 
    pipe.execute()

```

#### 常见日志

让程序记录特定消息出现的频率 并根据出现频率的高低来决定消息的排列顺序  
将消息作为成员存储到有序集合里面 并将消息出现的频率设置为成员的分值  
程序会以每小时一次的频率对消息进程轮换 并在轮换日志的时候保留上一个小时记录的常见消息  
也就是会备份  

```Python
def log_common(conn, name, message, severity=logging.INFO, timeout=5):
    severity = str(SERVERITY.get(severity, severity)).lower()
    destination = 'common:%s:%s' % (name, severity)
    start_key = destination + ':start'
    pipe = conn.pipline()
    end = time.time() + timeout
    while time.time() < end:
        try:
        # 对记录当前小时数的键进行监视
        pipe.watch(start_key)
        now = datetime.utcnow().timetuple()
        # 获取当前的小时数
        hour_start = datetime(*now[:4].isoformat)
        # 创建一个事务
        existing = pipe.get(start_key)
        pipe.multi()
        # 如果这个常见日志消息列表记录的上一个小时的日志
        if existing and existing < hour_start:
            # 那么将旧的常见日志消息归档
            pipe.rename(destination, destination+':last')
            pipe.rename(start_key, destination + ':pstart')
            # 更新当前所处的小时数
            pipe.set(start_key, hour_start)
        # 对记录日志出现次数的计数器执行自增操作
        pipe.zincrby(destination, message)
        log_recent(pipe, name, message, severity, pipe)
        return
    except redis.exceptions.WatchError:
        # 如果程序因为其他客户端正则执行归档操作而出现监视错误 那么进行重试
        continue

```

每次调用这个函数都会将传入的消息对应分值自增 如果时间过了当前小时那么就备份归档后重新搞一个  
如果有其他人操作这个key 那么就重试  

这里我们看到了 watch的查阅了一下还可以用作秒杀活动中的防止超卖的问题  

例子如下:

```python
from datetime import datetime
from threading import Thread
from threading import Lock
import redis
import time
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
lock = Lock()

class WatchDemo(object):  

    def  __init__(self):
        self.conn = self.get_connection()
        self.goods_key = 'goods'
        self.set_init_goods()

    def get_connection(self):
        connect = redis.Redis(host='127.0.0.1', port=6379 ,db=0)
        return connect
    
    def set_init_goods(self):
        self.conn.set(self.goods_key, 5)
    
    def consumer(self, name):
        flag = False
        while True:
            try:
                pipe = self.conn.pipeline()
                pipe.watch(self.goods_key)
                goods_count = int(pipe.get(self.goods_key))
                if goods_count>0:
                    pipe.multi() 
                    pipe.set(self.goods_key, goods_count-1)
                    pipe.execute()          # 执行事务
                    flag = True
                break
            except redis.exceptions.WatchError:
                lock.acquire()
                print('consumer {0} retry...'.format(name))
                lock.release()
                continue
            except Exception as e:
                print(e)
                break
        if flag:
            lock.acquire()
            print('consumer {0} success  : {1}'.format(name, goods_count))
            lock.release()
        else:
            lock.acquire()
            print('consumer {0} faild'.format(name))
            lock.release()
        
def main():
    wd = WatchDemo()
    threads = list()
    for i in range(0,10):
        t = Thread(target=wd.consumer, args=(i,))
        threads.append(t)
    for t in threads:
        t.start()

if __name__ == "__main__":
    main()
```

输出

```python
consumer 0 success  : 5
consumer 1 success  : 4
consumer 2 success  : 3
consumer 3 retry...
consumer 4 success  : 2
consumer 5 success  : 1
consumer 6 faild
consumer 3 faild
consumer 7 faild
consumer 8 faild
consumer 9 faild
```

### 计数器和统计数据

网站再最近5分钟内获得了10000次点击 或者数据库再最近5s内处理了200次写入和600次读取  

使用一个散列来存储网站在每个5s时间片 之内获得的点击量 其中 散列的每个键都是某个时间片的开始时间  
而键对应的值则存储了网站再该时间片之内获得的点击量   

不是整个时间的而是每5s为一个时间片存储 点击数量 也是方便统计  

使用有序集合 精度 和计数器的名字作为成员 成员的分值都为0  

针对不同的精度 不同的key 来存储  
程序只需要为每种时间片精度执行 ZADD命令和HINCRBY命令就可以了  

这里又单独搞了清理数据的程序 防止 存储过大 没有使用过期时间是一个 过期时间只能针对 一整个有序序列来不能针对单个键   


### 查找ip所属城市以及国家

通过将统计数据和日志存储到Redis里面 我们可以收集访客在系统中的行为信息  
将一个IP所属城市数据库载入Redis里面 然后通过搜索这个数据来发现玩家所在的位置  
Redis实现的IP所属地查找程序在运行速度上更有优势  
另一方面 对用户进行定位所需的信息量非常庞大 在应用程序启动时载入这些信息将影响 应用程序的启动速度  
所以也没有使用本地查找表实现  

需要先将数据载入Redis中  

数据来源: https://dev.maxmind.com/geoip/geoip2/geolite2/  

用到两个表 一个查找表需要根据输入的ip地址来查询ip所属城市的ID   
第二个表查找表则需要根据输入的城市ID来查找ID对应的城市的实际信息  

根据IP地址查来城市ID的查找表由有序集合实现 这个有序集合的成员为具体的城市ID 分值则是一个根据IP地址计算出来的整数值  
为了创建IP地址与城市ID之间的映射 程序需要将点分十进制转为一个整数分值  
IP地址中的每8个二进制位会被看做是无符号整数的1字节 其中IP地址最开头的8个二进制位为最高位

```python
def ip_to_score(ip_address):
    score = 0
    for v in ip_address.split('.'):
        score = score * 256 + int(v, 10)
    return score
```

因为多个IP地址范围可能会被映射到同一个城市ID 所以程序会在普通的城市ID后面加上一个 _字符以及有序集合已有城市ID的数量  
哦 因为用 城市ID 做的成员 分值是ip 所以肯定会有重复  


```python
def import_ips_to_redis(conn, filname):
    csv_file = csv.reader(open(filname, 'rb'))
    for count, row in enumerate(csv_file):
        start_ip = row[0] if row else ''
        if 'i' in start_ip.lower():
            continue
        elif '.' in start_ip:
            start_ip = ip_to_score(start_ip)
        else:
            continue
        city_id = row[2] + '_' +str(count)
        conn.zadd('ip2cityid:', city_id, start_ip)
```

构建出一个散列来  

还将 城市信息 json到redis中  

`conn.hset('cityid2city:', city_id, json.dumps([city, region, country]))`  

然后根据ip 转为分值直接去查询 获取城市ID 再去加载json获取城市信息  


#### 服务的发现与配置  

将大部分配置信息从文件转移到Redis里面 使得应用程序可以自己完成绝大部分配置工作  

我们可以把一个已知的Redis服务器用作配置信息字典 然后通过这个字典存储的配置信息来连接为不同应用或服务数据的其他Redis服务器  

这里定义个了一个装饰器 用于是被装饰的函数的调用可以自动连接至正确的Redis服务器  

```python
def redis_connection(component, wait=1): # 将应用组件的名字传递给装饰器
    key = 'config:redis:'+ component
    def wrapper(function):
        @functools.wraps(function)
        def call(*args, **kwargs):
            old_config = CONFIGS.get(key, object())
            _config = get_config(
                config_connection, 'redis', component, wait
            )
            config = {}
            for k, v in _config.iteritems():
                config[k.encode('utf8')] = v
            if config != old_config:
                REDIS_CONNECTIONS[key] = redis.Redis(**config)
                # 这里把函数的参数进行了更新 也就是conn 通过装饰器传入的 组件名称
            retutn function(REDIS_CONNECTIONS.get(key), *args, **kwargs)

        return call
    return wrapper

```


```python
@redis_connection('logs')
def log_recent(conn, app, message):
    # the old log_recent() code
```
这样自己不需要再切换连接 指定的log来给你更新这个新的连接 根据传入的logs  


这里就是很多的功能 通过redis去实现  