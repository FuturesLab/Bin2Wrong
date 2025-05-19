#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <cstring>
#include <unistd.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <algorithm>

using namespace std;

struct Config
{
    string flags_list_path;
    string used_flags_path;
    string src_code_file;
    string output_path;
};


string getEnvVar( string const & key )
{
    char * val = getenv( key.c_str() );
    return val == NULL ? string("") : string(val);
}

vector<string> splitStringByComma(const string& str) {
    vector<string> result;
    stringstream iss(str);
    string token;

    while (getline(iss, token, ',')) {
        result.push_back(token);
    }

    return result;
}

// Mutate bytes representing each compilation optimization flag
void bytes_mutation(uint8_t *bytes_buf, size_t bytes_size) {
    for (size_t i=1; i<bytes_size; i++) {
        random_device rd_bytes;
        mt19937 gen(rd_bytes());
        uniform_int_distribution<> dis(0, 6);
        int randNum = dis(gen);

        switch (randNum) {
            case 0:{ // flip bit
                random_device rd_bitflip;
                mt19937 gen_bitflip(rd_bitflip());
                uniform_int_distribution<> dis(0, 1);
                uint8_t bit = dis(gen_bitflip);

                bytes_buf[i] ^= 1 << bit;
                break;
            }
            case 1:{ // flip byte
                random_device rd_byteflip;
                mt19937 gen_byteflip(rd_byteflip());
                uniform_int_distribution<> distr(0, 255);
                uint8_t byte = distr(gen_byteflip);

                bytes_buf[i] ^= byte;
                break;
            }
            case 2:{ // add 1
                bytes_buf[i] += 1;
                break;
            }
            case 3:{ // sub 1
                if (bytes_buf[i] != 0){
                    bytes_buf[i] -= 1;
                }
                break;
            }
            case 4:{ // set to 0
                bytes_buf[i] += 0;
                break;
            }
            case 5:{ // set to 1
                bytes_buf[i] = 1;
                break;
            }
            default:{
                break;
            }
        }
    }
}

bool endsWith(const string& str, char c) {
    if (!str.empty()) {
        return str[str.length() - 1] == c;
    }
    return false;
}

string getLeftPart(const string& str) {
    size_t pos = str.find_last_of('=');
    if (pos != string::npos) {
        return str.substr(0, pos);
    }
    return str;
}

string flags_mutation(uint8_t *buf, size_t buf_size, string path, string compiler){
    vector<string> optimFlags;
    string comp_flags("");

    fstream file;
    file.open(path, ios::in);
    
    // read all the flags from FLAGS_LIST_PATH
    if(file.is_open()){
        string line;
        while(getline(file, line)){
            optimFlags.push_back(line);
        }
    }
    else{
        cout << "Error opening flags list text file" << endl;
        exit(1);
    }

    bytes_mutation(buf, optimFlags.size());

    for (unsigned int i = 2; i < buf_size; i++) {
        unsigned int intVal = buf[i];

        if (i < optimFlags.size()) {
            string flag(optimFlags[i]);

            // only select a flag when the corresponding byte is odd
            if (comp_flags.find(flag) == string::npos && (intVal % 2 == 1)) {

                if (compiler.find("MSVC") != std::string::npos || compiler.find("msvc") != std::string::npos) {
                    
                    if (flag.find("=") != std::string::npos){
                        string left_part = getLeftPart(flag);
                        
                        if (comp_flags.find(left_part) == string::npos){
                            if (endsWith(flag, '=-')) {
                                flag.erase(remove(flag.begin(), flag.end(), '='), flag.end());
                            } else if (endsWith(flag, '=+')) {
                                flag.erase(remove(flag.begin(), flag.end(), '='), flag.end());
                                flag.erase(remove(flag.begin(), flag.end(), '+'), flag.end());
                            } else if (endsWith(flag, '=')) {
                                flag.erase(remove(flag.begin(), flag.end(), '='), flag.end());
                                flag += to_string( ((intVal - 1) / 2) );
                            } else {
                                flag.erase(remove(flag.begin(), flag.end(), '='), flag.end());
                            }
                            comp_flags += flag;
                            comp_flags += " ";
                        }
                    } else{
                        comp_flags += flag;
                        comp_flags += " ";
                    }

                }
                else {
                    if (flag.find("=") != std::string::npos){
                        
                        string left_part = getLeftPart(flag);
                        if (comp_flags.find(left_part) == string::npos){
                            if (endsWith(flag, '=')) {
                                flag += to_string( ((intVal - 1) / 2) );
                            }
                            if ((compiler == "clang" or compiler == "o64-clang" or compiler == "icx") && flag != "") {
                                flag = "-mllvm=" + flag;
                                }
                            comp_flags += flag;
                            comp_flags += " ";
                        }
                        
                    } else{
                        if ((compiler == "clang" or compiler == "o64-clang" or compiler == "icx") && flag != "") {
                            flag = "-mllvm=" + flag;
                            }
                        comp_flags += flag;
                        comp_flags += " ";
                    }
                    
                }
                    
            }
        }
    }

    return comp_flags;
}

extern "C"{
    void compilation_mutation(uint8_t *buf, size_t buf_size, uint8_t *pointer){
        Config* config = new Config;
        config->used_flags_path = getEnvVar("USED_FLAGS_PATH");
        config->src_code_file = getEnvVar("ORIGINAL_CODE_PATH");
        config->output_path = getEnvVar("ORIGINAL_EXEC_PATH");

        string faulty_flags_path = getEnvVar("FAULTY_FLAGS_PATH");

        if (filesystem::exists(config->output_path)) {
            filesystem::remove(config->output_path);
        }
        if (filesystem::exists(config->used_flags_path)) {
            filesystem::remove(config->used_flags_path);
        }

        string command("");

        string comp_env = getEnvVar("COMPILER");
        string compiler_chosen;

        vector<string> compilers = splitStringByComma(comp_env);

        random_device rd_mutate;
        mt19937 gen_mutate(rd_mutate());
        uniform_int_distribution<> dis(0, compilers.size()-1);
        int c_byte = dis(gen_mutate);
        compiler_chosen = compilers[c_byte];
        buf[0] = c_byte;
        
        string flags_chosen = "";

        string msvc_inc = getEnvVar("MSVCINC");
        string msvc_lib = getEnvVar("MSVCLIB");
        string win2lin = getEnvVar("WIN2LIN");

        string tmp_folder = getEnvVar("TMP_FOLDER");
        string orig_filename = ((filesystem::path)config->src_code_file).filename().string();
        int compile_status = 0;
        string exec_postfix = "_exec";
        string defaultOutputName = config->output_path;
        
        if(compiler_chosen == "msvc"){
            compiler_chosen = getEnvVar("MSVC");
            config->flags_list_path = getEnvVar("MSVC_FLAGS");

            // get optimization flags based on mapped bytes and compiler chosen
            flags_chosen = flags_mutation(buf, buf_size, config->flags_list_path, compiler_chosen);
                
            char cwd[1024];
            getcwd(cwd, sizeof(cwd));
            chdir(tmp_folder.c_str());
            command = "(timeout 30s " + win2lin + " " + compiler_chosen + " " + flags_chosen + " " + orig_filename + " " + msvc_inc + " " + msvc_lib + ") > /dev/null 2>&1";

            compile_status = system(command.c_str());
            chdir(cwd);

            config->output_path = config->output_path.replace(config->output_path.find(exec_postfix), exec_postfix.length(), ".exe");
        }
        else{

            if(compiler_chosen == "clang"){
                config->flags_list_path = getEnvVar("CLANG_FLAGS");
            }
            else if(compiler_chosen == "gcc"){
                config->flags_list_path = getEnvVar("GCC_FLAGS");
            }
            else if(compiler_chosen == "tcc"){
                config->flags_list_path = getEnvVar("TCC_FLAGS");
            }
            else if(compiler_chosen == "icx"){
                config->flags_list_path = getEnvVar("ICX_FLAGS");
            }
            else if(compiler_chosen == "o64-clang"){
                config->flags_list_path = getEnvVar("CLANG_FLAGS");
            }

            // get optimization flags based on mapped bytes and compiler chosen
            flags_chosen = flags_mutation(buf, buf_size, config->flags_list_path, compiler_chosen);
            command = "(timeout 15s " + compiler_chosen + " " + flags_chosen + config->src_code_file + " -o " + config->output_path + " ) > /dev/null 2>&1";
            compile_status = system(command.c_str());
        }

        // if the executable does not exist after compilation command, mark compilation failed
        if (!filesystem::exists(config->output_path)) {
            compile_status = 256;

            string faulty_flags = compiler_chosen + " " + flags_chosen;
            // save used flags into a file 
            ofstream ffFile(faulty_flags_path);
            if (ffFile.is_open()) {
                ffFile << faulty_flags;
                ffFile.close();
                } else {
                }
        }

        if (compile_status != 0) {
            // if compilation failed, compile with default command
            string defaultCommand = "";
            if(compiler_chosen == getEnvVar("MSVC")){        

                random_device rd;
                mt19937 eng(rd());
                uniform_int_distribution<> distr(1, 2);
                int randomNumber = distr(eng);    

                char cwd[1024];
                getcwd(cwd, sizeof(cwd));
                chdir(tmp_folder.c_str());

                flags_chosen = "/O" + to_string(randomNumber);
                string newCommand = "(timeout 30s " + win2lin + " " + compiler_chosen + " " + flags_chosen + " " + orig_filename + " " + msvc_inc + " " + msvc_lib + ") > /dev/null 2>&1";

                system(newCommand.c_str());
                chdir(cwd);
                buf[1] = randomNumber;
                
                if (!filesystem::exists(config->output_path)) {
                    char cwd[1024];
                    getcwd(cwd, sizeof(cwd));
                    chdir(tmp_folder.c_str());

                    defaultCommand = "(timeout 30s " + win2lin + " " + compiler_chosen + " /Od " + orig_filename + " " + msvc_inc + " " + msvc_lib + ") > /dev/null 2>&1";
                    flags_chosen = "/Od";

                    system(defaultCommand.c_str());
                    chdir(cwd);
                    buf[1] = 0;
                }
            }
            else{
                random_device rd;
                mt19937 eng(rd());
                uniform_int_distribution<> distr(1, 3);
                int randomNumber = distr(eng);

                flags_chosen = "-O" + to_string(randomNumber);
                string new_command = "(timeout 15s " + compiler_chosen + " " + flags_chosen + " " + config->src_code_file+" -o "+config->output_path + ") > /dev/null 2>&1";
                system(new_command.c_str());
                buf[1] = randomNumber;

                if (!filesystem::exists(config->output_path)) {
                    defaultCommand = "(timeout 15s " + compiler_chosen + " -O0 " + config->src_code_file+" -o "+config->output_path + ") > /dev/null 2>&1";
                    flags_chosen = "-O0";
                    system(defaultCommand.c_str());

                    buf[1] = 0;
                }
                
            }
            for (size_t i=2; i< buf_size; i++){
                buf[i] = 0;
            }
        }

        if(compiler_chosen == getEnvVar("MSVC")){
            rename(config->output_path.c_str(), defaultOutputName.c_str());
        }

        string used_flags = compiler_chosen + " " + flags_chosen;
        // save used flags into a file 
        ofstream outputFile(config->used_flags_path);
        if (outputFile.is_open()) {
            outputFile << used_flags;
            outputFile.close();
            } else {
            }

        memcpy(pointer, buf, buf_size);
    }
}