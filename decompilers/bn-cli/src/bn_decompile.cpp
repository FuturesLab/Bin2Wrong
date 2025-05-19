#include <memory>
#include <iostream>
#include <fstream>
#include "binaryninjacore.h"
#include "binaryninjaapi.h"

using namespace std;
using namespace BinaryNinja;

string dec(string input){

    string dec = "";
    
    SetBundledPluginDirectory(GetBundledPluginDirectory());
	InitPlugins();

	Ref<BinaryData> bd = BinaryData::CreateFromFilename(new FileMetadata(), input);
	if (!bd)
	{
		fprintf(stderr, "Could not open input file.\n");
		return dec;
	}
	Ref<BinaryView> bv;
	for (auto type : BinaryViewType::GetViewTypes())
	{
		if (type->IsTypeValidForData(bd) && type->GetName() != "Raw")
		{
			bv = type->Create(bd);
			break;
		}
	}

	if (!bv || bv->GetTypeName() == "Raw")
	{
		fprintf(stderr, "Input file does not appear to be an exectuable\n");
		return dec;
	}

    bv->UpdateAnalysisAndWait();

    DisassemblySettings settings;

    settings.SetOption(ShowVariableTypesWhenAssigned);
    settings.SetOption(GroupLinearDisassemblyFunctions);
    settings.SetOption(WaitForIL);

    vector<Ref<Function>> functionList = bv->GetAnalysisFunctionList();

    for(Ref<Function> func: functionList ){
        Ref<LinearViewObject> obj = LinearViewObject::CreateSingleFunctionLanguageRepresentation(func, settings.Duplicate());
        LinearViewCursor cursor = LinearViewCursor(obj);
        while(true){
            for(LinearDisassemblyLine line: cursor.GetLines()){
                if (line.type == FunctionHeaderStartLineType || line.type == FunctionHeaderEndLineType || line.type == AnalysisWarningLineType) {
                    continue;
                }

                for(InstructionTextToken token: line.contents.tokens){
                    if(token.type == TagToken){
                        continue;
                    }
                    dec += token.text;
                }
                dec += "\n";
            }
            if(!cursor.Next()){
                break;
            }
        }
    }
    
    BNShutdown();
    return dec;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <binary file path> <(optional)decompile code path>" << endl;
        return 1;
    }

    string decompiled_code = dec(argv[1]);

    if(decompiled_code != ""){
        if(argc == 2){
            cout << decompiled_code;
        }
        else{
            ofstream outputFile(argv[2]);
            if (outputFile.is_open()) {
                outputFile << decompiled_code;
                outputFile.close();
            } else {
            }
        }
    }
    
    return 0;
}