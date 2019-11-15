# CryptoFucker

QQ 群：471525564

For English version of README, drag the page down

Xposed框架，用于抓取javax.crypto.* 与 javax.security.* 算法参数（包括加密数据、密钥、IV、结果等数据）的工具。

## 使用方法

- 1.安装Xposed framework
- 2.安装并激活CryptoFucker
- 3.运行你想测试的APP
- 4./sdcard/ydsec/packgeName.txt 为数据文件

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



# English Version starts here

This is a module runs on Xposed framework, a tool for intercepting the parameter of javax.crypto.* and javax.security. Including encrypted data, key, IV and results.

## How to use

- 1.Install Xposed framework
- 2.Install & Activate CryptoFucker
- 3.Run the application that you wish to debug on
- 4.Bam. The data file will show up at /sdcard/ydsec/packgeName.txt 

Tip: Use Notepad++ to view file. You don't have to, but maybe you should.

## Great unique feature that no one else have becuz they are fucking awesome

- Most functions of javax.crypto.*  are supported
- Most functions of javax.security.* are also supported
- IV vector sniffer
- key sniffer
- Encrypted raw data sniffer
- Encrypted result sniffer
- Call stack view
- View in HEX

## Samples

There are some samples in /example

Wonder why it's in /example instead of /sample?

Cuz me chinese don know english
