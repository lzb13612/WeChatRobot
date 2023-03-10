import cptools
from corpwechatbot.app import AppMsgSender

app = AppMsgSender(corpid='',  # 你的企业id
                   corpsecret='',  # 你的应用凭证密钥
                   agentid='',  # 你的应用id
                   log_level=cptools.INFO,  # 设置日志发送等级，INFO, ERROR, WARNING, CRITICAL,可选
                   proxies={'http': 'http:example.com', 'https': 'https:example.com'}  # 设置代理，可选
                   )

# 如果你在本地配置添加了企业微信本地配置文件，也可以直接初始化AppMsgSender，而无需再显式传入密钥参数
# app = AppMsgSender()
# TODO:
