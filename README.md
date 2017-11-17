# CryptoFucker
Xposed框架，用于抓取javax.crypto.* 与 javax.security.* 算法参数（包括加密数据、密钥、IV、结果等数据）的工具。

## 使用方法
* 1.安装Xposed framework
* 2.安装并激活CryptoFucker
* 3.运行你想测试的APP
* 4./sdcard/ydsec/packgeName.txt 为数据文件

建议使用Notepad++查看数据文件。

## 优势

- 支持 javax.crypto.*  大部分函数
- 支持 javax.security.*大部分函数
- IV向量嗅探
- 密钥嗅探
- 加密原始数据嗅探
- 加密结果嗅探
- 调用栈显示
- HEX 显示

## 数据文件样例说明

样例数据在example目录。