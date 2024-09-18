# cpp-ftp-client

header-only FTP client for cpp.



## 1. Note

1. Using [`asio`](https://github.com/chriskohlhoff/asio) as underlying network layer, rewrite the [`poco`](https://github.com/pocoproject/poco/tree/main) `FTPClientSession` class. 
   - remove `timeout` interface;
   - `beginDownload&endDownload->download`;
   - `beginUpload&endUpload->upload`;
2. That will make the class being header only dependency, it's easy to use.
3. Not support ftps.



## 2. Usage

1. Basic usage

   ```c++
   FTPClientSession session("127.0.0.1");
   session.login("user", "passwd");
   
   if (!session.isLoggedIn())
   {
       std::cout << "login ftp failed." << std::endl;
       return;
   }
   
   std::cout << "workingDirectory: " << session.getWorkingDirectory() << std::endl;
   
   auto file_list = session.listPath("path/to/ftp/dir", true);
   for(auto& info: file_list)
   {
       // display file name, type and size.
       std::cout << info.to_string() << std::endl;
   }
   
   auto file_info = session.getFileInfo("path/to/file/or/dir");
   std::cout << file_info.to_string() << std::endl;
   ```

   

2. Open active mode: the session is default on passive mode. 

   ```c++
   // active mode require ftp server supporst RFC1738.
   auto active_port = 10086;
   
   FTPClientSession session("127.0.0.1", 21, active_port);
   session.setPassive(false);
   ```



## 3. Interface

```c++
/// Creates an FTPClientSession.
///
/// Passive mode will be used for data transfers.
FTPClientSession(uint16_t activeDataPort = 0);

/// Creates an FTPClientSession using a socket connected
/// to the given host and port. If username is supplied,
/// login is attempted.
///
/// Passive mode will be used for data transfers.
FTPClientSession(const std::string &host, uint16_t port = FTP_PORT,
                 uint16_t activeDataPort = 0);

/// Destroys the FTPClientSession.
virtual ~FTPClientSession();

/// Enables (default) or disables FTP passive mode for this session.
///
/// If useRFC1738 is true (the default), the RFC 1738
/// EPSV command is used (with a fallback to PASV if EPSV fails)
/// for switching to passive mode. The same applies to
/// EPRT and PORT for active connections.
void setPassive(bool flag, bool useRFC1738 = true);

/// Returns true if passive mode is enabled for this connection.
bool getPassive() const;

/// Opens the FTP connection to the given host and port.
/// If username is supplied, login is attempted.
virtual void open(const std::string &host, uint16_t port,
                  const std::string &username = "",
                  const std::string &password = "");

/// Authenticates the user against the FTP server. Must be
/// called before any other commands (except QUIT) can be sent.
///
/// Sends a USER command followed by a PASS command with the
/// respective arguments to the server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
virtual void login(const std::string &username, const std::string &password);

/// Logs out from the server by sending a QUIT command. Any transfer
/// that's in progress is ended. The control connection is kept
/// open.
void logout();

/// Sends a QUIT command and closes the connection to the server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
void close();

/// Returns the system type of the FTP server.
///
/// Sends a SYST command to the server and returns the result.
std::string systemType();

/// Sets the transfer data type for transferring files.
///
/// Sends a TYPE command with a corresponding argument to the
/// server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
void setTransferType(TransferType type);

/// Returns the file type for transferring files.
TransferType getTransferType() const;

/// Returns the file info on path.
FileInfo getFileInfo(const std::string &path);

/// Changes the current working directory on the server.
///
/// Sends a CWD command with the given path as argument to the
/// server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
void setWorkingDirectory(const std::string &path);

/// Returns the current working directory on the server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
std::string getWorkingDirectory();

/// Moves one directory up from the current working directory
/// on the server.
///
/// Sends a CDUP command to the server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
void cdup();

/// Renames the file on the server given by oldName to newName.
///
/// Sends a RNFR command, followed by a RNTO command to the server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
void rename(const std::string &oldName, const std::string &newName);

/// Deletes the file specified by path on the server.
///
/// Sends a DELE command with path as argument to the server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
void remove(const std::string &path);

/// Creates a new directory with the given path on the server.
///
/// Sends a MKD command with path as argument to the server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
void createDirectory(const std::string &path);

/// Removes the directory specified by path from the server.
///
/// Sends a RMD command with path as argument to the server.
///
/// Throws a FTPException in case of a FTP-specific error, or a
/// NetException in case of a general network communication failure.
void removeDirectory(const std::string &path);

/// Starts downloading the file with the given name.
///
/// Creates a data connection between the client and the
/// server. If passive mode is on, then the server waits for
/// a connection request from the client. Otherwise, the
/// client waits for a connection request from the server.
/// After establishing the data connection, a SocketStream
/// for transferring the data is created.
///
/// If ASCII transfer mode is selected, the caller is
/// responsible for converting the received data to
/// the native text file format.
/// The InputLineEndingConverter class from the Foundation
/// library can be used for that purpose.
std::string download(const std::string &path);

/// Starts uploading the file with the given name.
///
/// Creates a data connection between the client and the
/// server. If passive mode is on, then the server waits for
/// a connection request from the client. Otherwise, the
/// client waits for a connection request from the server.
/// After establishing the data connection, a SocketStream
/// for transferring the data is created.
///
/// If ASCII transfer mode is selected, the caller is
/// responsible for converting the data to be sent
/// into network (CR-LF line endings) format.
/// The OutputLineEndingConverter class from the Foundation
/// library can be used for that purpose.
void upload(const std::string &path, const std::string &data);

/// Download a directory listing.
///
/// Optionally, a path to a directory or file can be specified.
/// According to the FTP protocol, if a path to a filename is
/// given, only information for the specific file is returned.
/// If a path to a directory is given, a listing of that directory
/// is returned. If no path is given, a listing of the current
/// working directory is returned.
///
/// If extended is false, only a filenames (one per line) are
/// returned. Otherwise, a full directory listing including
/// file attributes is returned. The format of this listing
/// depends on the FTP server. No attempt is made to interpret
/// this data.
///
/// Creates a data connection between the client and the
/// server. If passive mode is on, then the server waits for
/// a connection request from the client. Otherwise, the
/// client waits for a connection request from the server.
/// After establishing the data connection, a SocketStream
/// for transferring the data is created.
FileInfoList listPath(const std::string &path = "", bool extended = false);

/// Aborts the download or upload currently in progress.
///
/// Sends a TELNET IP/SYNCH sequence, followed by an ABOR
/// command to the server.
///
/// A separate call to endDownload() or endUpload() is
/// not necessary.
void abort();

/// Sends the given command verbatim to the server
/// and waits for a response.
int sendCommand(const std::string &command, std::string &response);

/// Sends the given command verbatim to the server
/// and waits for a response.
int sendCommand(const std::string &command, const std::string &arg,
                std::string &response);

/// Returns true if the connection with FTP server is opened.
bool isOpen() const;

/// Returns true if the session is logged in.
bool isLoggedIn() const;

/// Returns true if the session is FTPS.
bool isSecure() const;

/// Returns the welcome message.
const std::string &welcomeMessage();
```

