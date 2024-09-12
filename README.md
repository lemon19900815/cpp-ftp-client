# cpp-ftp-client

header-only FTP client for cpp。

Note：使用asio作为网络底层库，重写Poco的ftp模块；

https://github.com/mkulke/ftplibpp



FTP主动模式 vs 被动模式：

- 主动模式：FTP客户端发送`EPRT`命令，等待FTP服务器响应数据端口；（FTP客户端主机开启服务，等待FTP服务器建立数据通道；主动模式必须要支持RFC1738）
- 被动模式：FTP客户端开启服务，发送`EPSV`命令，告知FTP开启的数据端口；（FTP服务器主机开启服务，等待FTP客户端建立数据通道）



注意点：

- `ftp LIST`返回数据的解析；

  Windows和Linux不同，需要使用不同方式解析：[解析参考链接](https://blog.csdn.net/happyparrot/article/details/375628)

  - Windows数据（Server on Windows）
  
    ```ini
    12-29-22  03:40PM       <DIR>          CloudAdapter
    08-30-23  09:20AM                  195 CMakeLists.txt
    01-22-24  04:56PM       <DIR>          data
    12-27-22  03:00PM                   66 ftp站点开启.txt
    01-10-23  09:29AM                   56 info.txt
    09-12-23  04:00PM       <DIR>          photo
    09-12-23  03:49PM       <DIR>          photo2
    08-24-23  05:08PM               205324 pic.jpg
    01-10-23  09:29AM                   56 version.txt
  08-28-24  08:01PM                    0 新建文本文档.txt
    ```

  - Linux数据（Server on Linux）
  
    ```ini
    
    ```
  # 待补充Linux版本数据
    ```
  
    ```
  
- `ftp NLST`直接按照`\r\n`分割字符串之后再去掉尾部`\r\n`字符；