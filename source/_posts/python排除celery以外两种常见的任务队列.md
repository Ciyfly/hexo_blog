---
title: python排除celery以外两种常见的任务队列
date: 2020-12-24 18:19:43
tags: 任务队列
---


# pyton排除celery两种常见的任务队列


## rq

![目录结构](img/2020-12-24-15-34-59.png)

count_words_at_url work需要执行的函数  
![count_words_at_url](img/2020-12-24-15-35-31.png)


rq_test.py  

```python
#!/usr/bin/python
# coding=utf-8


from redis import Redis
from rq import Queue
from renwu import count_words_at_url

queue = Queue(connection=Redis())

# renwu.count_words_at_url 是因为环境变量设置的是 当前目录 count_words_at_url 在renwu里
job = queue.enqueue('renwu.count_words_at_url', 'http://nvie.com')
print(job)

```

设置环境变量 让work能找到 count_words_at_url函数  
`export PYTHONPATH=/当前路径/:$PYTHONPATH`  
启动work  
在 work函数目录下 ` rq worker --with-scheduler`  
![启动work](img/2020-12-24-15-37-47.png)  



成功执行  
![](img/2020-12-24-15-38-58.png) 


启动两个work试试  
rq info 可以看到work  
![rq info ](img/2020-12-24-15-28-15.png)  

执行  
![两个work执行](img/2020-12-24-15-41-50.png)  

可以看到两个work都执行了  


支持重试  

```python
from rq import Retry

# Retry up to 3 times, failed job will be requeued immediately
queue.enqueue(say_hello, retry=Retry(max=3))

# Retry up to 3 times, with configurable intervals between retries
queue.enqueue(say_hello, retry=Retry(max=3, interval=[10, 30, 60]))
```

定时任务  
```python
# Schedule job to run at 9:15, October 10th
job = queue.enqueue_at(datetime(2019, 10, 8, 9, 15), say_hello)

# Schedule job to be run in 10 seconds
job = queue.enqueue_in(timedelta(seconds=10), say_hello)
```

### 深入

#### 队列初始化
队列初始化的时候可以设置name等参数  

rq/queue.py:59  
```python
def __init__(self, name='default', default_timeout=None, connection=None,
                is_async=True, job_class=None, serializer=None, **kwargs):
```


#### 入队
函数，参数  
`queue.enqueue('renwu.count_words_at_url', 'http://nvie.com')`  

```python
def enqueue(self, f, *args, **kwargs):
    """Creates a job to represent the delayed function call and enqueues it."""

    (f, timeout, description, result_ttl, ttl, failure_ttl,
        depends_on, job_id, at_front, meta, retry, args, kwargs) = Queue.parse_args(f, *args, **kwargs)

    return self.enqueue_call(
        func=f, args=args, kwargs=kwargs, timeout=timeout,
        result_ttl=result_ttl, ttl=ttl, failure_ttl=failure_ttl,
        description=description, depends_on=depends_on, job_id=job_id,
        at_front=at_front, meta=meta, retry=retry
    )

def enqueue_call(self, func, args=None, kwargs=None, timeout=None,
                    result_ttl=None, ttl=None, failure_ttl=None,
                    description=None, depends_on=None, job_id=None,
                    at_front=False, meta=None, retry=None):
```

```
timeout	用于指定作业被中断并标记为失败之前的最大运行时间。默认单位是秒，可以是整数或表示整数的字符串 ( 例如，2，'2') 。此外，还可以是具有指定单位的字符串，包括小时，分钟，秒（例如'1h'，'3m'，'5s')  
result_ttl	用于指定作业任务执行结果保存的时间  
ttl	用于指定作业任务在队列中排队的最长时间，超过该时间后，该作业任务就会被取消。如果指定值 -1，则表示不限时间，也就是说会一直等待，知道该作业任务被执行  
depends_on	用于指定该作业任务运行之前必须完成的另一个作业任务( 或作业 ID )  
job_id	用于手动指定该作业任务的 id job_id  
at_front	用于将该作业任务放置在队列的头部，而不是尾部，也就是说可以优先被执行  
kwargs 或 args	使用字典或命名参数的方式指定上面提到的任何参数  
```

我们也可以直接使用 enqueue_call函数来创建更复杂的队列  

返回回来的队列实例q也有很多使用方法  

```python
['DEFAULT_TIMEOUT', '__bool__', '__class__', '__delattr__', '__dict__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__iter__', '__le__', '__len__', '__lt__', '__module__', '__new__', '__nonzero__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_default_timeout', '_is_async', '_key', 'acquire_cleaning_lock', 'all', 'compact', 'connection', 'count', 'create_job', 'deferred_job_registry', 'delete', 'dequeue_any', 'empty', 'enqueue', 'enqueue_at', 'enqueue_call', 'enqueue_dependents', 'enqueue_in', 'enqueue_job', 'failed_job_registry', 'fetch_job', 'finished_job_registry', 'from_queue_key', 'get_job_ids', 'get_jobs', 'is_async', 'is_empty', 'job_class', 'job_ids', 'jobs', 'key', 'lpop', 'name', 'parse_args', 'pop_job_id', 'push_job_id', 'redis_queue_namespace_prefix', 'redis_queues_keys', 'registry_cleaning_key', 'remove', 'run_job', 'scheduled_job_registry', 'started_job_registry']

```

获取队列长度 `len(queue)`  

获取所有id为 xxx的job `job = queue.fetch_job(xxx)`  

#### 回去返回结果 使用装饰器

`job.result` 没有执行完会返回空 否则会返回结果  

执行函数 在renwu目录下  

```python
from rq.decorators import job
from redis import Redis

@job('low', connection=Redis(), timeout=5)
def add(x, y):
    return x + y

```

测试调用函数  

```python
from renwu import add
import time
job = add.delay(3, 4)
time.sleep(1)
while True:
    if job.result:
        print(job.result)
        break

```

work执行 (在跟 执行函数一个目录下)  
`rq worker low`  

`python test.py`  

![装饰器执行](img/2020-12-24-16-41-00.png)  

这里 创建队列的时候指定了 name是 low 所以 work使用的时候也是要指定low队列  


work 可以-u指定redis连接  



## huey



### 使用  

目录

```python
├── task.py
├── task.pyc
├── test.py
└── test.pyc

```
task.py  

```python
from huey import RedisHuey, crontab

huey = RedisHuey('test', host='127.0.0.1')

@huey.task()
def add_numbers(a, b):
    return a + b

@huey.task(retries=2, retry_delay=60)
def flaky_task(url):
    # This task might fail, in which case it will be retried up to 2 times
    # with a delay of 60s between retries.
    return this_might_fail(url)

@huey.periodic_task(crontab(minute='0', hour='3'))
def nightly_backup():
    sync_all_data()

```

test.py  

```python
from task import add_numbers

res = add_numbers(1, 2)
print(res)

```

work  
先设置环境变量 `export PYTHONPATH=/当前路径/:$PYTHONPATH`
在当前目录下执行  `huey_consumer.py task.huey`  
后面的参数是 创建的队列的路径  
还可指定work数量 `-k process -w 4`  
并且可以指定 协程 进程等  

执行  
![add_numer](img/2020-12-24-17-23-09.png)  




### 文档

https://huey.readthedocs.io/en/latest/  

demo https://github.com/coleifer/huey/tree/master/example  



## 比较

相比较 celery 是比较笨重 但是应用广泛 经常出现不消费任务的情况  
今天了解的这两个消费队列 相对轻便 具体消费情况还没有测试  

huey 文档全面


rq的issues更活跃 (star 7.4k) 
![](img/2020-12-24-17-41-44.png)  

huey没有issues (3.3k)


个人倾向于 huey 后面在实际使用中看下效果吧  



参考  

https://www.twle.cn/t/39  
https://huey.readthedocs.io/en/latest/  
https://github.com/coleifer/huey/tree/master/examples  
https://github.com/rq/rq  

