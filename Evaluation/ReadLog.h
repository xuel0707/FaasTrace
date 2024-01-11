#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class ReadLog
{
private:
    std::string filename;
    std::ifstream logFile;
    std::vector<std::string> split(const std::string &str, char delim) const;
public:
    // 构造函数
    ReadLog(const std::string &filename);

    ~ReadLog();

    bool open();

    void parseLog();
    
};

