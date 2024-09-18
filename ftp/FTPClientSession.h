// Copyright (c) 2024 buerjia.
// Rewrite underlying network by asio.
//
// Reserved Previous BSL-1.0 License.
// 
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier: BSL-1.0

#pragma once

#include <cstdint>
#include <istream>
#include <memory>
#include <mutex>
#include <string>
#include <iostream>
#include <regex>

#include "asio.hpp"

using namespace asio;
using namespace asio::ip;

using StreamSocket = tcp::socket;
using SocketAddress = tcp::endpoint;
using DialogSocket = tcp::socket;
using SocketStream = tcp::socket;

namespace ftp
{

// ftp file type(not contains soft link file type.)
enum class FileType : uint8_t
{
    kInvalidFile = 0,
    kNormalFile = 1,
    kDirectoryFile = 2,
};

struct FileInfo
{
    std::string name;
    int64_t     size{0};
    FileType    type{FileType::kInvalidFile};

    std::string to_string()
    {
        std::string type_str;
        switch (type)
        {
        case FileType::kNormalFile:
            type_str = "file";
            break;
        case FileType::kDirectoryFile:
            type_str = "dir";
            break;
        case FileType::kInvalidFile:
            type_str = "unknown";
            break;
        }

        std::stringstream ss;
        ss << "name: " << name;
        ss << ", size: " << size;
        ss << ", type: " << type_str;
        return ss.str();
    }
};

using FileInfoList = std::vector<FileInfo>;

/// This class implements an File Transfer Protocol
/// (FTP, RFC 959) client.
///
/// Most of the features of the FTP protocol, as specified
/// in RFC 959, are supported. Not supported are EBCDIC and
/// LOCAL data types and format control and structured files.
///
/// Also supported are the EPRT and EPSV commands from
/// RFC 1738 (FTP Extensions for IPv6 and NAT).
/// The client will first attempt to use the EPRT and EPSV
/// commands. If the server does not supports these commands,
/// the client will fall back to PORT and PASV.
class FTPClientSession
{
public:
    enum { FTP_PORT = 21 };

    enum TransferType
    {
        TYPE_TEXT,   /// TYPE A (ASCII)
        TYPE_BINARY  /// TYPE I (Image/binary data)
    };

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

protected:
    virtual void receiveServerReadyReply();

    enum StatusClass
    {
        FTP_POSITIVE_PRELIMINARY = 1,
        FTP_POSITIVE_COMPLETION = 2,
        FTP_POSITIVE_INTERMEDIATE = 3,
        FTP_TRANSIENT_NEGATIVE = 4,
        FTP_PERMANENT_NEGATIVE = 5
    };

    enum
    {
        DEFAULT_TIMEOUT = 30000  // 30 seconds default timeout for socket operations
    };

    static bool isPositivePreliminary(int status);
    static bool isPositiveCompletion(int status);
    static bool isPositiveIntermediate(int status);
    static bool isTransientNegative(int status);
    static bool isPermanentNegative(int status);
    std::string extractPath(const std::string &response);
    virtual StreamSocket establishDataConnection(const std::string &command,
                                                 const std::string &arg);
    StreamSocket activeDataConnection(const std::string &command,
                                      const std::string &arg);
    StreamSocket passiveDataConnection(const std::string &command,
                                       const std::string &arg);
    void sendPortCommand(const SocketAddress &addr);
    SocketAddress sendPassiveCommand();
    bool sendEPRT(const SocketAddress &addr);
    void sendPORT(const SocketAddress &addr);
    bool sendEPSV(SocketAddress &addr);
    void sendPASV(SocketAddress &addr);
    void parseAddress(const std::string &str, SocketAddress &addr);
    void parseExtAddress(const std::string &str, SocketAddress &addr);
    void endTransfer();

    std::string sendAndReceive(const std::string &cmd, const std::string &arg);

    std::shared_ptr<DialogSocket> _pControlSocket = nullptr;
    std::shared_ptr<SocketStream> _pDataStream = nullptr;
    asio::io_context io_context_;

private:
    FTPClientSession(const FTPClientSession &) = delete;
    FTPClientSession &operator=(const FTPClientSession &) = delete;

    std::string _host;
    uint16_t _port = FTP_PORT;
    uint16_t _activeDataPort = 0;
    bool _passiveMode = true;
    TransferType _transferType = TYPE_BINARY;
    bool _supports1738 = true;
    bool _serverReady = false;
    bool _isLoggedIn = false;
    int32_t _timeout = DEFAULT_TIMEOUT;
    std::string _welcomeMessage;
    std::mutex _wmMutex;
};

//-------------------------------------------------------------------
//-----------------------------implement-----------------------------
//-------------------------------------------------------------------

inline bool FTPClientSession::isPositivePreliminary(int status)
{
    return status / 100 == FTP_POSITIVE_PRELIMINARY;
}

inline bool FTPClientSession::isPositiveCompletion(int status)
{
    return status / 100 == FTP_POSITIVE_COMPLETION;
}

inline bool FTPClientSession::isPositiveIntermediate(int status)
{
    return status / 100 == FTP_POSITIVE_INTERMEDIATE;
}

inline bool FTPClientSession::isTransientNegative(int status)
{
    return status / 100 == FTP_TRANSIENT_NEGATIVE;
}

inline bool FTPClientSession::isPermanentNegative(int status)
{
    return status / 100 == FTP_PERMANENT_NEGATIVE;
}

inline bool FTPClientSession::isOpen() const
{
    return _pControlSocket != nullptr;
}

inline bool FTPClientSession::isLoggedIn() const
{
    return _isLoggedIn;
}

inline bool FTPClientSession::isSecure() const
{
    return false;
}

inline const std::string &FTPClientSession::welcomeMessage()
{
    std::lock_guard<std::mutex> lock(_wmMutex);
    return _welcomeMessage;
}

namespace detail
{
static int32_t receiveLine(std::string &response)
{
    if (!response.empty())
    {
        if (response.back() == '\n')
        {
            response.pop_back();
        }
        if (response.back() == '\r')
        {
            response.pop_back();
        }
    }

    size_t n = 0u;
    int32_t status = 0;
    while (n < response.size() && n < 3)
    {
        auto ch = (int)(uint8_t)response[n];
        if (std::isdigit(ch))
        {
            status *= 10;
            status += ch - '0';
        }

        ++n;
    }

    if (n == 3 && n < response.size())
    {
        auto ch = (int)(uint8_t)response[n];
        if (ch == '-')
        {
            status = -status;
        }
    }

    return status;
}

static int32_t receiveStatusMessage(StreamSocket &s, std::string &response)
{
    asio::error_code ec;

    asio::streambuf buf;
    size_t len = asio::read_until(s, buf, "\r\n", ec);

    if (ec && ec != asio::error::eof)
    {
        std::cerr << __FUNCTION__ << "->error: " << ec.message() << std::endl;
        return -1;
    }

    // parse line data.
    auto buffer = buf.data();
    response = std::string((char *)buffer.data(), len);

    return receiveLine(response);
}

static std::string receiveAll(StreamSocket &s)
{
    std::string data;

    char buff[4096];
    asio::error_code ec;

    while (true)
    {
        auto len = asio::read(s, asio::buffer(buff, sizeof(buff)), ec);
        data.append(buff, len);

        if (ec)
        {
            if (ec != asio::error::eof)
            {
                std::cerr << __FUNCTION__ << "->error: "
                          << ec.message() << std::endl;
                data.clear();
            }
            break;
        }
    }

    return data;
}

static int32_t sendMessage(StreamSocket &s, const std::string &msg,
                           const std::string &arg = "")
{
    auto expand_len = arg.empty() ? 2 : arg.size() + 3;

    std::string command;
    command.append(msg);

    if (!arg.empty())
    {
        command.append(" ");
        command.append(arg);
    }

    command.append("\r\n");

    return (int32_t)s.send(asio::buffer(command.data(), command.size()));
}

static int32_t sendByte(StreamSocket &s, uint8_t ch)
{
    return (int32_t)s.send(asio::buffer(&ch, 1));
}

static int32_t sendUrgent(StreamSocket &s, uint8_t ch)
{
    return (int32_t)s.send(asio::buffer(&ch, 1),
                           socket_base::message_out_of_band);
}

static std::vector<std::string> split(const std::string &s,
                                      const std::string delimiter)
{
    std::vector<std::string> tokens;

    std::string::size_type last_pos = s.find_first_not_of(delimiter, 0);
    std::string::size_type pos = s.find_first_of(delimiter, last_pos);
    while ((std::string::npos != pos) || (std::string::npos != last_pos))
    {
        tokens.push_back(s.substr(last_pos, pos - last_pos));
        last_pos = s.find_first_not_of(delimiter, pos);
        pos = s.find_first_of(delimiter, last_pos);
    }

    return tokens;
}

static bool isNumberString(const std::string &s)
{
    if (s.empty())
    {
        return false;
    }

    for (auto &ch : s)
    {
        if (!std::isdigit(ch))
        {
            return false;
        }
    }

    return true;
}

} // namespace detail

class FTPException : public std::exception
{
public:
    FTPException(const std::string &msg)
        : error_(msg), std::exception(error_.c_str()) {}

    FTPException(const std::string &msg, const std::string &response)
        : error_(msg + ", response: " + response),
          std::exception(error_.c_str()) {}

    FTPException(const std::string &msg, const std::string &response,
                 int32_t status)
        : error_(msg + ", response: " + response +
                 ", status: " + std::to_string(status)),
          std::exception(error_.c_str()) {}

private:
    std::string error_;
};

class IFileInfoParser
{
public:
    using Ptr = std::shared_ptr<IFileInfoParser>;

    virtual ~IFileInfoParser() {}
    virtual FileInfoList parse(const std::string &data) = 0;
};

class NoExtendFileInfoParser : public IFileInfoParser
{
public:
    FileInfoList parse(const std::string &data) override
    {
        FileInfoList file_list;
        for (auto &line : detail::split(data, "\r\n"))
        {
            if (line.empty())
            {
                continue;
            }

            FileInfo info;
            info.name = line;
            file_list.emplace_back(std::move(info));
        }

        return file_list;
    }
};

// the ftp server on windows.
class WinFileInfoParser : public IFileInfoParser
{
public:
    FileInfoList parse(const std::string &data) override
    {
        FileInfoList file_list;
        for (auto &line : detail::split(data, "\r\n"))
        {
            if (line.empty())
            {
                continue;
            }

            /* e.g.
                name = line[39, -1], size = line[18, 38]
                12-29-22  03:40PM       <DIR>          CloudAdapter
                08-30-23  09:20AM                  195 CMakeLists.txt
                01-22-24  04:56PM       <DIR>          data
            */

            FileInfo info;

            auto len = line.size();
            auto pos = line.find_first_of("<DIR>");
            if (pos != std::string::npos)
            {
                info.type = FileType::kDirectoryFile;
            }
            else
            {
                info.type = FileType::kNormalFile;
                info.size = len >= 18 ? std::atoll(line.substr(18, 38).c_str()) : 0;
            }

            info.name = len >= 39 ? line.substr(39) : line;
            file_list.emplace_back(std::move(info));
        }

        return file_list;
    }
};

// the ftp server on unix like.
class PosixFileInfoParser : public IFileInfoParser
{
public:
    FileInfoList parse(const std::string &data) override
    {
        FileInfoList file_list;
        for (auto &line : detail::split(data, "\r\n"))
        {
            if (line.empty())
            {
                continue;
            }

            /*
            ----------------------------------------------
            -rw-rw-r--    1 1000     1000            4 Sep 10 18:36 1.txt
            lrwxrwxrwx    1 1000     1000            5 Sep 10 18:44 11.txt -> 1.txt
            -rw-rw-r--    1 1000     1000            4 Sep 10 18:42 2 a.txt
            -rwxrwxrwx    1 1001     1001     89484672 Sep 10 03:03 gcc.tar.xz
            drwxrwxr-x    2 1000     1000         4096 Sep 10 18:36 test
            ----------------------------------------------
            */

            FileInfo info;

            auto len = line.size();
            if (line.front() == 'd')
            {
                info.type = FileType::kDirectoryFile;
            }
            else
            {
                info.type = FileType::kNormalFile;

                if (len >= 30)
                {
                    info.size = std::atoll(line.substr(30, 42).c_str());
                }
            }

            if (len >= 56)
            {
                info.name = line.substr(56);

                auto pos = info.name.find(" -> ");
                if (pos != std::string::npos)
                {
                    info.name = info.name.substr(0, pos);
                }
            }

            file_list.emplace_back(std::move(info));
        }

        return file_list;
    }
};

class FileInfoParserFactory
{
public:
    static FileInfoList parse(const std::string &data, bool extend)
    {
        return create(data, extend)->parse(data);
    }

    static IFileInfoParser::Ptr create(const std::string &data, bool extend)
    {
        if (!extend)
        {
            return std::make_shared<NoExtendFileInfoParser>();
        }

        if (data.size() > 10)
        {
            std::regex regex("^[bcdlps-]([r-]{1}[w-]{1}[x-]{1}){3}$");
            if (std::regex_match(data.substr(0, 10), regex))
            {
                return std::make_shared<PosixFileInfoParser>();
            }
        }

        return std::make_shared<WinFileInfoParser>();
    }
};

inline FTPClientSession::FTPClientSession(uint16_t activeDataPort)
    : _pControlSocket(nullptr),
      _pDataStream(nullptr),
      _port(FTP_PORT),
      _activeDataPort(activeDataPort),
      _passiveMode(true),
      _transferType(TYPE_BINARY),
      _supports1738(true),
      _serverReady(false),
      _isLoggedIn(false),
      _timeout(DEFAULT_TIMEOUT) {}

// FTPClientSession::FTPClientSession(const StreamSocket &socket,
//                                    bool readWelcomeMessage,
//                                    uint16_t activeDataPort):
//     //_pControlSocket(std::make_shared<DialogSocket>(socket)),
//     _pDataStream(0),
//     _host(socket.local_endpoint().address().to_string()),
//     _port(socket.local_endpoint().port()),
//     _activeDataPort(activeDataPort),
//     _passiveMode(true),
//     _fileType(TYPE_BINARY),
//     _supports1738(true),
//     _serverReady(false),
//     _isLoggedIn(false),
//     _timeout(DEFAULT_TIMEOUT)
//{
//     if (readWelcomeMessage)
//     {
//         receiveServerReadyReply();
//     }
//     else
//     {
//         _serverReady = true;
//     }
// }

inline FTPClientSession::FTPClientSession(const std::string &host, uint16_t port,
                                          uint16_t activeDataPort)
    : _pControlSocket(nullptr),
      _pDataStream(nullptr),
      _host(host),
      _port(port),
      _activeDataPort(activeDataPort),
      _passiveMode(true),
      _transferType(TYPE_BINARY),
      _supports1738(true),
      _serverReady(false),
      _isLoggedIn(false),
      _timeout(DEFAULT_TIMEOUT)
{
}

inline FTPClientSession::~FTPClientSession()
{
    try
    {
        close();
    }
    catch (...)
    {
    }
}

//inline void FTPClientSession::setTimeout(const int32_t timeout)
//{
//    if (!isOpen())
//    {
//        throw FTPException("Connection is closed.");
//    }
//
//    _timeout = timeout;
//    //_pControlSocket->setReceiveTimeout(timeout);
//}
//
//inline int32_t FTPClientSession::getTimeout() const
//{
//    return _timeout;
//}

inline void FTPClientSession::setPassive(bool flag, bool useRFC1738)
{
    _passiveMode = flag;
    _supports1738 = useRFC1738;
}

inline bool FTPClientSession::getPassive() const
{
    return _passiveMode;
}

inline void FTPClientSession::open(const std::string &host, uint16_t port,
                                   const std::string &username,
                                   const std::string &password)
{
    _host = host;
    _port = port;
    if (!username.empty())
    {
        login(username, password);
    }
    else
    {
        if (!_pControlSocket)
        {
            _pControlSocket = std::make_shared<DialogSocket>(io_context_);
            tcp::resolver resolver(io_context_);
            asio::connect(*_pControlSocket,
                          resolver.resolve(_host, std::to_string(_port)));
        }
        receiveServerReadyReply();
    }
}

inline void FTPClientSession::receiveServerReadyReply()
{
    if (_serverReady)
    {
        return;
    }

    std::string response;
    auto status = detail::receiveStatusMessage(*_pControlSocket, response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException("Cannot receive status message", response, status);
    }

    {
        std::lock_guard<std::mutex> lock(_wmMutex);
        _welcomeMessage = response;
    }

    _serverReady = true;
}

inline void FTPClientSession::login(const std::string &username,
                                    const std::string &password)
{
    if (_isLoggedIn)
    {
        logout();
    }

    if (!_pControlSocket)
    {
        _pControlSocket = std::make_shared<DialogSocket>(io_context_);
        tcp::resolver resolver(io_context_);
        asio::connect(*_pControlSocket,
                      resolver.resolve(_host, std::to_string(_port)));
    }
    receiveServerReadyReply();

    int status = FTP_POSITIVE_COMPLETION * 100;
    std::string response;

    status = sendCommand("USER", username, response);
    if (isPositiveIntermediate(status))
    {
        status = sendCommand("PASS", password, response);
    }

    if (!isPositiveCompletion(status))
    {
        throw FTPException("Login denied", response, status);
    }

    setTransferType(_transferType);
    _isLoggedIn = true;
}

inline void FTPClientSession::logout()
{
    if (!isOpen())
    {
        throw FTPException("Connection is closed.");
    }

    if (_isLoggedIn)
    {
        try
        {
            endTransfer();
        }
        catch (...)
        {
        }
        _isLoggedIn = false;
        std::string response;
        sendCommand("QUIT", response);
    }
}

inline void FTPClientSession::close()
{
    try
    {
        logout();
    }
    catch (...)
    {
    }
    _serverReady = false;
    if (_pControlSocket)
    {
        _pControlSocket->close();
        _pControlSocket = nullptr;
    }
}

inline void FTPClientSession::setTransferType(FTPClientSession::TransferType type)
{
    std::string response;
    int status = sendCommand("TYPE", (type == TYPE_TEXT ? "A" : "I"), response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException("Cannot set file type", response, status);
    }
    _transferType = type;
}

inline FTPClientSession::TransferType FTPClientSession::getTransferType() const
{
    return _transferType;
}

inline FileInfo FTPClientSession::getFileInfo(const std::string &path)
{
    std::string response;

    auto status = sendCommand("STAT", path, response);
    if (status == -213)
    {
        status = detail::receiveStatusMessage(*_pControlSocket, response);
        if (status == 0)
        {
            auto pos = response.find_first_not_of(' ');
            if (pos != std::string::npos)
            {
                response = response.substr(pos);
            }

            //std::cout << response << std::endl;
            auto file_list = FileInfoParserFactory::parse(response, true);
            if (file_list.size() == 1u)
            {
                auto &info = file_list[0];
                if (info.name == ".")
                {
                    info.name = path;
                }
                return info;
            }
        }
    }

    return {};
}

inline std::string FTPClientSession::systemType()
{
    std::string response;
    int status = sendCommand("SYST", response);
    if (isPositiveCompletion(status))
    {
        return response.substr(4);
    }
    else
    {
        throw FTPException("Cannot get remote system type", response, status);
    }
}

inline void FTPClientSession::setWorkingDirectory(const std::string &path)
{
    std::string response;
    int status = sendCommand("CWD", path, response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException("Cannot change directory", response, status);
    }
}

inline std::string FTPClientSession::getWorkingDirectory()
{
    std::string response;
    int status = sendCommand("PWD", response);
    if (isPositiveCompletion(status))
    {
        return extractPath(response);
    }
    else
    {
        throw FTPException("Cannot get current working directory",
                           response, status);
    }
}

inline void FTPClientSession::cdup()
{
    std::string response;
    int status = sendCommand("CDUP", response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException("Cannot change directory", response, status);
    }
}

inline void FTPClientSession::rename(const std::string &oldName,
                                     const std::string &newName)
{
    std::string response;
    int status = sendCommand("RNFR", oldName, response);
    if (!isPositiveIntermediate(status))
    {
        throw FTPException(std::string("Cannot rename ") + oldName,
                           response, status);
    }
    status = sendCommand("RNTO", newName, response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException(std::string("Cannot rename to ") + newName,
                           response, status);
    }
}

inline void FTPClientSession::remove(const std::string &path)
{
    std::string response;
    int status = sendCommand("DELE", path, response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException(std::string("Cannot remove " + path),
                           response, status);
    }
}

inline void FTPClientSession::createDirectory(const std::string &path)
{
    std::string response;
    int status = sendCommand("MKD", path, response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException(std::string("Cannot create directory ") + path,
                           response, status);
    }
}

inline void FTPClientSession::removeDirectory(const std::string &path)
{
    std::string response;
    int status = sendCommand("RMD", path, response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException(std::string("Cannot remove directory ") + path,
                           response, status);
    }
}

// std::istream& FTPClientSession::beginDownload(const std::string& path)
//{
//     if (!isOpen())
//     {
//         throw FTPException("Connection is closed.");
//     }
//
//     delete _pDataStream;
//     _pDataStream = 0;
//     _pDataStream = new SocketStream(establishDataConnection("RETR", path));
//     return *_pDataStream;
// }

// void FTPClientSession::endDownload()
//{
//     endTransfer();
// }

inline std::string FTPClientSession::download(const std::string &path)
{
    return sendAndReceive("RETR", path);
    //auto s = establishDataConnection("RETR", path);
    //_pDataStream = std::make_shared<SocketStream>(std::move(s));

    //auto data = detail::receiveAll(*_pDataStream);
    //endTransfer();

    //return data;
}

inline void FTPClientSession::upload(const std::string &path,
                                     const std::string &data)
{
    if (!isOpen())
    {
        throw FTPException("Connection is closed.");
    }

    auto s = establishDataConnection("STOR", path);
    _pDataStream = std::make_shared<SocketStream>(std::move(s));

    detail::sendMessage(*_pDataStream, data);
    endTransfer();
}

// std::ostream &FTPClientSession::beginUpload(const std::string &path)
//{
//     if (!isOpen())
//     {
//         throw FTPException("Connection is closed.");
//     }
//
//     delete _pDataStream;
//     _pDataStream = 0;
//     _pDataStream = new SocketStream(establishDataConnection("STOR", path));
//     return *_pDataStream;
// }

// void FTPClientSession::endUpload()
//{
//     endTransfer();
// }

// std::istream &FTPClientSession::beginList(const std::string &path, bool
// extended)
//{
//     if (!isOpen())
//     {
//         throw FTPException("Connection is closed.");
//     }
//
//     _pDataStream = new SocketStream(establishDataConnection(extended ? "LIST"
//     : "NLST", path)); return *_pDataStream;
// }

// void FTPClientSession::endList()
//{
//     endTransfer();
// }

inline FileInfoList FTPClientSession::listPath(const std::string &path,
                                               bool extended)
{
    if (!isOpen())
    {
        throw FTPException("Connection is closed.");
    }

    //std::string data;

    //auto s = establishDataConnection(extended ? "LIST" : "NLST", path);
    //_pDataStream = std::make_shared<SocketStream>(std::move(s));

    //data = detail::receiveAll(*_pDataStream);
    //endTransfer();

    auto data = sendAndReceive(extended ? "LIST" : "NLST", path);

    //std::cout << "----------------------------------------------" << std::endl;
    //std::cout << data << std::endl;
    //std::cout << "----------------------------------------------" << std::endl;

    return FileInfoParserFactory::parse(data, extended);
}

inline std::string FTPClientSession::sendAndReceive(const std::string &cmd,
                                                    const std::string &arg)
{
    std::string data;

    auto s = establishDataConnection(cmd, arg);
    _pDataStream = std::make_shared<SocketStream>(std::move(s));

    data = detail::receiveAll(*_pDataStream);
    endTransfer();

    return data;
}

enum TelnetCodes
{
    TELNET_SE = 240,
    TELNET_NOP = 241,
    TELNET_DM = 242,
    TELNET_BRK = 243,
    TELNET_IP = 244,
    TELNET_AO = 245,
    TELNET_AYT = 246,
    TELNET_EC = 247,
    TELNET_EL = 248,
    TELNET_GA = 249,
    TELNET_SB = 250,
    TELNET_WILL = 251,
    TELNET_WONT = 252,
    TELNET_DO = 253,
    TELNET_DONT = 254,
    TELNET_IAC = 255
};

inline void FTPClientSession::abort()
{
    if (!isOpen())
    {
        throw FTPException("Connection is closed.");
    }

    detail::sendByte(*_pControlSocket, TELNET_IP);  // 244
    detail::sendUrgent(*_pControlSocket, TELNET_DM);

    std::string response;
    int status = sendCommand("ABOR", response);
    if (status == 426)
    {
        status = detail::receiveStatusMessage(*_pControlSocket, response);
    }
    if (status != 226)
    {
        throw FTPException("Cannot abort transfer", response, status);
    }
}

inline int FTPClientSession::sendCommand(const std::string &command,
                                         std::string &response)
{
    if (!isOpen())
    {
        throw FTPException("Connection is closed.");
    }

    detail::sendMessage(*_pControlSocket, command);
    return detail::receiveStatusMessage(*_pControlSocket, response);
}

inline int FTPClientSession::sendCommand(const std::string &command,
                                         const std::string &arg,
                                         std::string &response)
{
    if (!isOpen())
    {
        throw FTPException("Connection is closed.");
    }

    detail::sendMessage(*_pControlSocket, command, arg);
    return detail::receiveStatusMessage(*_pControlSocket, response);
}

inline std::string FTPClientSession::extractPath(const std::string &response)
{
    std::string path;
    std::string::const_iterator it = response.begin();
    std::string::const_iterator end = response.end();
    while (it != end && *it != '"')
    {
        ++it;
    }
    if (it != end)
    {
        ++it;
        while (it != end)
        {
            if (*it == '"')
            {
                ++it;
                if (it == end || *it != '"')
                {
                    break;
                }
            }
            path += *it++;
        }
    }
    return path;
}

inline StreamSocket FTPClientSession::establishDataConnection(
    const std::string &command, const std::string &arg)
{
    if (_passiveMode)
    {
        return passiveDataConnection(command, arg);
    }
    else
    {
        return activeDataConnection(command, arg);
    }
}

inline StreamSocket FTPClientSession::activeDataConnection(const std::string &command,
                                                           const std::string &arg)
{
    if (!isOpen())
    {
        throw FTPException("Connection is closed.");
    }

    auto local_addr = _pControlSocket->local_endpoint().address();
    tcp::endpoint svr_endpoint(local_addr, _activeDataPort);

    tcp::acceptor server(io_context_, svr_endpoint);

    sendPortCommand(svr_endpoint);

    std::string response;
    int status = sendCommand(command, arg, response);
    if (!isPositivePreliminary(status))
    {
        throw FTPException(command + " command failed", response, status);
    }

    return server.accept();
}

inline StreamSocket FTPClientSession::passiveDataConnection(const std::string &command,
                                                            const std::string &arg)
{
    SocketAddress sa(sendPassiveCommand());
    StreamSocket sock(io_context_);

    asio::error_code ec;
    sock.connect(sa, ec);

    if (ec)
    {
        std::cout << "error: " << ec.message() << std::endl;
        throw FTPException("fail to connect.");
    }

    std::string response;
    int status = sendCommand(command, arg, response);
    if (!isPositivePreliminary(status))
    {
        throw FTPException(command + " command failed", response, status);
    }
    return sock;
}

inline void FTPClientSession::sendPortCommand(const SocketAddress &addr)
{
    if (_supports1738)
    {
        if (sendEPRT(addr))
        {
            return;
        }
        else
        {
            _supports1738 = false;
        }
    }
    sendPORT(addr);
}

inline SocketAddress FTPClientSession::sendPassiveCommand()
{
    SocketAddress addr;
    if (_supports1738)
    {
        if (sendEPSV(addr))
        {
            return addr;
        }
        else
        {
            _supports1738 = false;
        }
    }
    sendPASV(addr);
    return addr;
}

inline bool FTPClientSession::sendEPRT(const SocketAddress &addr)
{
    std::string arg("|");
    arg += addr.address().is_v4() ? '1' : '2';
    arg += '|';
    arg += addr.address().to_string();
    arg += '|';
    arg += std::to_string(addr.port());
    arg += '|';
    std::string response;
    int status = sendCommand("EPRT", arg, response);
    if (isPositiveCompletion(status))
    {
        return true;
    }
    else if (isPermanentNegative(status))
    {
        return false;
    }
    else
    {
        throw FTPException("EPRT command failed", response, status);
    }
}

inline void FTPClientSession::sendPORT(const SocketAddress &addr)
{
    std::string arg(addr.address().to_string());
    for (auto &ch : arg)
    {
        if (ch == '.')
        {
            ch = ',';
        }
    }
    arg += ',';
    uint16_t port = addr.port();
    arg += std::to_string(port / 256);
    arg += ',';
    arg += std::to_string(port % 256);
    std::string response;
    int status = sendCommand("PORT", arg, response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException("PORT command failed", response, status);
    }
}

inline bool FTPClientSession::sendEPSV(SocketAddress &addr)
{
    std::string response;
    int status = sendCommand("EPSV", response);
    if (isPositiveCompletion(status))
    {
        parseExtAddress(response, addr);
        return true;
    }
    else if (isPermanentNegative(status))
    {
        return false;
    }
    else
    {
        throw FTPException("EPSV command failed", response, status);
    }
}

inline void FTPClientSession::sendPASV(SocketAddress &addr)
{
    std::string response;
    int status = sendCommand("PASV", response);
    if (!isPositiveCompletion(status))
    {
        throw FTPException("PASV command failed", response, status);
    }
    parseAddress(response, addr);
}

inline void FTPClientSession::parseAddress(const std::string &str,
                                           SocketAddress &addr)
{
    std::string::const_iterator it = str.begin();
    std::string::const_iterator end = str.end();
    while (it != end && *it != '(')
    {
        ++it;
    }
    if (it != end)
    {
        ++it;
    }
    std::string host;
    while (it != end && std::isdigit(*it))
    {
        host += *it++;
    }
    if (it != end && *it == ',')
    {
        host += '.';
        ++it;
    }
    while (it != end && std::isdigit(*it))
    {
        host += *it++;
    }
    if (it != end && *it == ',')
    {
        host += '.';
        ++it;
    }
    while (it != end && std::isdigit(*it))
    {
        host += *it++;
    }
    if (it != end && *it == ',')
    {
        host += '.';
        ++it;
    }
    while (it != end && std::isdigit(*it))
    {
        host += *it++;
    }
    if (it != end && *it == ',')
    {
        ++it;
    }
    uint16_t portHi = 0;
    while (it != end && std::isdigit(*it))
    {
        portHi *= 10;
        portHi += *it++ - '0';
    }
    if (it != end && *it == ',')
    {
        ++it;
    }
    uint16_t portLo = 0;
    while (it != end && std::isdigit(*it))
    {
        portLo *= 10;
        portLo += *it++ - '0';
    }

    addr = SocketAddress(make_address(host), portHi * 256 + portLo);
}

inline void FTPClientSession::parseExtAddress(const std::string &str,
                                              SocketAddress &addr)
{
    std::string::const_iterator it = str.begin();
    std::string::const_iterator end = str.end();
    while (it != end && *it != '(')
    {
        ++it;
    }
    if (it != end)
    {
        ++it;
    }
    char delim = '|';
    if (it != end)
    {
        delim = *it++;
    }
    if (it != end && *it == delim)
    {
        ++it;
    }
    if (it != end && *it == delim)
    {
        ++it;
    }
    uint16_t port = 0;
    while (it != end && std::isdigit(*it))
    {
        port *= 10;
        port += *it++ - '0';
    }

    addr = SocketAddress(_pControlSocket->remote_endpoint().address(), port);
}

inline void FTPClientSession::endTransfer()
{
    if (_pDataStream)
    {
        _pDataStream = nullptr;

        std::string response;
        int status = detail::receiveStatusMessage(*_pControlSocket, response);
        if (!isPositiveCompletion(status))
        {
            throw FTPException("Data transfer failed", response, status);
        }
    }
}

}  // namespace ftp
