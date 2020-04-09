---
title: Dsxs源码简单分析
date: 2020-04-09 18:18:41
tags:
  - 源码
---
100 行 xss 检查代码
主方法 `scan_page`  
传入 url 和 data
这里直接看代码

```python
def scan_page(url, data=None):
    retval, usable = False, False
    # 这里对于 id=1&name=&age=1 的name进行补1操作
    url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    # 先用_retrieve_content 请求url然后交与正则DOM_FILTER_REGEX
    # r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"
    # 用于清除多余字符串 注释等
    original = re.sub(DOM_FILTER_REGEX, "", _retrieve_content(url, data))
    # DOM_PATTERNS 从响应体中正则判断是否存在 dom xss 可能性
    # 因为dom型xss是js直接操作节点来生成的所以js源码有能正则匹配的document\.write\(|\.innerHTML location setTimeout等
    #
    dom = next(filter(None, (re.search(_, original) for _ in DOM_PATTERNS)), None)
    if dom: # 如果匹配到了可能存在dom xss 并输出匹配的地方
        print(" (i) page itself appears to be XSS vulnerable (DOM)")
        print("  (o) ...%s..." % dom.group(0))
        # 设置结果存在
        retval = True
    try:
      # 下面是根据参数来测试是否存在xss
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            # get的话 current就是url
            # 解析url的parameter 参数
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):
                found, usable = False, True
                print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                # 随机生成5位长度的字符串 两个 分别作为前后缀
                prefix, suffix = ("".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH)) for i in range(2))
                # SMALLER_CHAR_POOL    = ('<', '>')
                # LARGER_CHAR_POOL     = ('\'', '"', '>', '<', ';')
                for pool in (LARGER_CHAR_POOL, SMALLER_CHAR_POOL):
                    if not found: # 默认就是False
                        # 将参数改为 参数加 前缀+LARGER_CHAR_POOL+后缀 就是判断 <> 是否过滤
                        tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote("%s%s%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix, "".join(random.sample(pool, len(pool))), suffix))))
                        # 替换后的新的url
                        # 发起请求获取响应体 content
                        content = (_retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)).replace("%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix), prefix)
# 每个元组都代表输出点在dom结点中的一个确定的位置，比如：script标签内、单引号内、注释内
REGULAR_PATTERNS = (
#   匹配有可能存在xss的字符串的正则，攻击成功需要哪些字符未经过滤，说明(简易表达匹配格式)，获取响应包后首先筛掉的字符的regexp
    # <> 不被过滤 纯字符
    (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", None),
    # <> 不被过滤 是在注释内
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'), "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", None),
    # ' ; 不被过滤 在<script> 标签内被单引号包裹 使用方式: 先闭合单引号然后 ;终端语句再自定义js
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'), "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering", r"\\'"),
    # 这个被双引号包裹的 其他同上
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'), "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering", r'\\"'),
    # ; 不被过滤 在script标签内 没有单双引号包裹 直接分号中断
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',), "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering", None),
    # <> 不被过滤在标签外的 自己使用标签 每次匹配后要删除对于的一些东西比如这里 删除script标签和注释 防止xss匹配重合
    (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->"),
    # ' 单引号不被过滤 在标签内 被单引号包裹
    (r"<[^>]*=\s*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',), "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    # " 双引号 同上
    (r'<[^>]*=\s*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',), "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    #标签内，引号外 <img xss>等
    (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|=\s*'[^']*'|=\s*\"[^\"]*\""),
)
    # 查找之前传入的随机字符串匹配看是否被过滤 <> 找到后输出 并清除匹配的相关字符串
    # 只是根据位置来判断 输出利用方式
                        for regex, condition, info, content_removal_regex in REGULAR_PATTERNS:
                            filtered = re.sub(content_removal_regex or "", "", content)
                            for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), filtered, re.I):
                                context = re.search(regex % {"chars": re.escape(sample.group(0))}, filtered, re.I)
                                if context and not found and sample.group(1).strip():
                                    if _contains(sample.group(1), condition):
                                        print(" (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info % dict((("filtering", "no" if all(char in sample.group(1) for char in LARGER_CHAR_POOL) else "some"),))))
                                        found = retval = True
                                    break
        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")
    return retval
```

这里把匹配与利用的图贴上
![avatar]("Dsxs源码简单分析/table.png")

参考 https://www.cnblogs.com/litlife/p/10741864.html#4079918734
