#include <chrono>
#include <iostream>
#include <thread>
#include <iomanip>

#include "FTPClientSession.h"
using namespace ftp;

#include "stopwatch.h"

std::string get_time_fmt(const std::string &fmt = "%Y-%m-%d %H:%M:%S")
{
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::system_clock::to_time_t(now);

    auto stm = std::localtime(&timestamp);

    std::ostringstream ostr;
    ostr << std::put_time(stm, fmt.c_str());

    return ostr.str();
}

#define LOG_INFO(var) std::cout << get_time_fmt() << " " << var << std::endl;
#define LOG_ERROR(var)                                          \
    do {                                                        \
        std::cout << get_time_fmt() << " " << var << std::endl; \
        system("pause");                                        \
    } while (0)

void test_receiveLine()
{
    std::string txt = "220 Microsoft FTP Service\r";
    auto status = ftp::detail::receiveLine(txt);

    assert(status == 220);
    assert(txt == "220 Microsoft FTP Service");
}

int main(int argc, char **argv)
{
    //FTPClientSession session("10.2.34.178", 21, 10086); // windows
    FTPClientSession session("192.168.223.128", 21, 10086); // linux
    //session.setPassive(false);

    session.login("lemon", "123456");

    if (!session.isLoggedIn())
    {
        LOG_ERROR("login ftp failed.");
        return 1;
    }

    LOG_INFO("login ftp success.");
    LOG_INFO("welcome message: " << session.welcomeMessage());
    LOG_INFO("workingDirectory: " << session.getWorkingDirectory());
    LOG_INFO("systemType: " << session.systemType());

    session.upload("3.txt", "this is a upload test.");
    LOG_INFO("upload 3.txt success.");

    auto txt3 = session.listPath("3.txt", true);
    LOG_INFO("listPath 3.txt success.");

    LOG_INFO(session.getFileInfo("1.txt").to_string());
    LOG_INFO("getFileInfo 1.txt success.");
    //LOG_INFO(session.getFileInfo("5.txt").to_string());

    //session.rename("1.txt", "2.txt");
    //auto txt_info = session.listPath("2.txt", true);
    //session.rename("2.txt", "1.txt");

    //session.setWorkingDirectory("test/Medusa");
    //LOG_INFO("workingDirectory: " << session.getWorkingDirectory());

    //session.cdup();
    //LOG_INFO("workingDirectory: " << session.getWorkingDirectory());

    // auto data = session.download("info.txt");
    // LOG_INFO("data = " << data);

    //auto file_list = session.listPath("", true);
    //for (auto& file : file_list)
    //{
    //    std::cout << file.to_string() << std::endl;
    //}

#ifdef _WIN32
    system("pause");
#endif
    return 0;
}
