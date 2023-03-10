#!/usr/bin/env python
# -*- coding: utf-8 -*-
import uvicorn
import keyring
from secrets import receive_serve_secrets
from fastapi import FastAPI
from fastapi import Response, Request
from WXBizMsgCrypt3 import WXBizMsgCrypt
from xml.etree.ElementTree import fromstring

app = FastAPI()

receive_serve_secrets()
wx_cpt = WXBizMsgCrypt(keyring.get_password('Receive_Serve', 'Token'),
                       keyring.get_password('Receive_Serve', 'Aes_Key'),
                       keyring.get_password('Receive_Serve', 'Corp_Id'))


@app.get("/")
async def verify(msg_signature: str,
                 timestamp: str,
                 nonce: str,
                 echos_tr: str):
    """
    验证配置是否成功，处理get请求
    :param msg_signature:
    :param timestamp:
    :param nonce:
    :param echos_tr:
    :return:
    """

    ret, sEchoStr = wx_cpt.VerifyURL(msg_signature, timestamp, nonce, echos_tr)
    if ret == 0:
        return Response(content=sEchoStr.decode('utf-8'))
    else:
        print(sEchoStr)


@app.post("/")
async def recv(msg_signature: str,
               timestamp: str,
               nonce: str,
               request: Request):
    """
    接收用户消息，可进行被动响应
    :param msg_signature:
    :param timestamp:
    :param nonce:
    :param request:
    :return:
    """
    body = await request.body()
    ret, sMsg = wx_cpt.DecryptMsg(body.decode('utf-8'), msg_signature, timestamp, nonce)
    decrypt_data = {}
    sRespData = None
    for node in list(fromstring(sMsg.decode('utf-8'))):
        decrypt_data[node.tag] = node.text
    # 解析后得到的decrypt_data: {"ToUserName":"企业号", "FromUserName":"发送者用户名", "CreateTime":"发送时间", "Content":"用户发送的内容",
    # "MsgId":"唯一id，需要针对此id做出响应", "AgentID": "应用id"}
    # 用户应根据Content的内容自定义要做出的行为，包括响应返回数据，如下例子，如果发送的是123，就返回hello world

    # 处理任务卡片消息
    if decrypt_data.get('EventKey', '') == 'no':
        # 返回信息
        sRespData = """<xml>
           <ToUserName>{to_username}</ToUserName>
           <FromUserName>{from_username}</FromUserName>
           <CreateTime>{create_time}</CreateTime>
           <MsgType>update_taskbar</MsgType>
           <TaskCard>
               <ReplaceName>已处理</ReplaceName>
           </TaskCard>
        </xml>
        """.format(to_username=decrypt_data['ToUserName'],
                   from_username=decrypt_data['FromUserName'],
                   create_time=decrypt_data['CreateTime'],
                   event_key=decrypt_data['EventKey'],
                   agentid=decrypt_data['AgentId'])
    # 处理文本消息
    if decrypt_data.get('Content', '') == 'test':
        sRespData = """<xml>
           <ToUserName>{to_username}</ToUserName>
           <FromUserName>{from_username}</FromUserName> 
           <CreateTime>{create_time}</CreateTime>
           <MsgType>text</MsgType>
           <Content>{content}</Content>
        </xml>
        """.format(to_username=decrypt_data['ToUserName'],
                   from_username=decrypt_data['FromUserName'],
                   create_time=decrypt_data['CreateTime'],
                   content="test", )
    ret, send_msg = wx_cpt.EncryptMsg(sReplyMsg=sRespData, sNonce=nonce)
    if ret == 0:
        return Response(content=send_msg)
    else:
        print(send_msg)


if __name__ == "__main__":
    uvicorn.run("web:app", port=8000, host='0.0.0.0', reload=False)
