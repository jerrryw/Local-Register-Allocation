#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <climits>
#include <sstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include <stack>
#include <unordered_map>
#include <queue>

#define MAXBUFFERSIZE 256

using namespace std;

struct Instruction
{
    string         opcode;
    vector<string> inputs;
    vector<string> outputs;
    string         debugStr;
};


bool isRegister(string token)
{
    return token[0] == 'r';
}


int findNextUsed(const vector<Instruction>& ins_in, const string& target, const int start_index)
{
    for (int i = start_index; i < ins_in.size(); i++)
    {
        for (const auto& token : ins_in[i].inputs)
        {
            if (token == target) return i - start_index;
        }

        // for (const auto& token : ins_in[i].outputs)
        // {
        //     if (token == target) return i - start_index;
        // }
    }

    return INT_MAX;
}


// operand + string("#") + to_string(slotIdx)
string RenamedRegister(string operand, int slotIdx)
{
    // return operand + string("#") + to_string(slotIdx);
    // return string("r") + ((char)('a' + slotIdx));
    return string("r") + to_string(slotIdx);
}


void GetAvailableSlots(const unordered_map<string, int>& operandToMemory,
                       const vector<string>&             slots,
                       vector<int>&                      availableSlotIndices)
{
    availableSlotIndices.clear();

    for (int i = 0; i < slots.size(); i++)
    {
        // If the slot is empty or the resident also exists in the memory, it means the slot can be used.
        if ((slots[i] == "") || (operandToMemory.find(slots[i]) != operandToMemory.end()))
        {
            availableSlotIndices.push_back(i);
        }
    }
}


void PrintOneInstruction(const Instruction& instruction, FILE* oFile=stderr)
{
    fprintf(oFile, "%s", instruction.opcode.c_str());

    for (int i = 0; i < instruction.inputs.size(); i++)
    {
        if (i != 0) fprintf(oFile, ",");
        fprintf(oFile, " %s", instruction.inputs[i].c_str());
    }

    if (instruction.outputs.size() > 0)
    {
        fprintf(oFile, " =>");
        for (int i = 0; i < instruction.outputs.size(); i++)
        {
            if (i != 0) fprintf(oFile, ",");
            fprintf(oFile, " %s", instruction.outputs[i].c_str());

        }
    }

    // cout << "\t" << instruction.debugStr;
    #ifdef DEBUG
    fprintf(oFile, "\t%s", instruction.debugStr.c_str());
    #endif // #ifdef DEBUG

    // cout << endl;
    fprintf(oFile, "\n");
}

void DumpInstructions(const vector<Instruction>& instructions, FILE* oFile=stderr)
{
    for (const auto& instruction : instructions)
    {
        PrintOneInstruction(instruction, oFile);
    }
}


void findRegistersToAllocate(const vector<string>& operands,
                             const vector<string>& slots,
                             vector<string>&       result)
{
    for (const auto& op : operands)
    {
        assert(isRegister(op));

        // operand does not exist in the slots
        if (find(slots.begin(), slots.end(), op) == slots.end())
        {
            result.push_back(op);
        }
    }
}

// Spill "slots[victimSlotIdx]" to memory address "memoryAddr".
void insertSpillOutCode(const int               feasibleRegSlotIdx,
                        const vector<string>&   slots,
                        const int               victimSlotIdx,
                        const int               memoryAddr,
                        vector<Instruction>&    ins_out)
{
    auto feasible_register = RenamedRegister("f0", feasibleRegSlotIdx);

    Instruction pre_load_instruction = {};
    pre_load_instruction.opcode = "loadI";
    pre_load_instruction.inputs.push_back(to_string(memoryAddr));
    pre_load_instruction.outputs.push_back(feasible_register);
    ins_out.push_back(pre_load_instruction);

    // Construct spill instruction.
    Instruction spill_instruction = {};
    spill_instruction.opcode = "store";
    spill_instruction.inputs.push_back(RenamedRegister(slots[victimSlotIdx], victimSlotIdx));
    spill_instruction.outputs.push_back(feasible_register);
    ins_out.push_back(spill_instruction);
}

void insertLoadCode(const int               feasibleRegSlotIdx,
                    const string&           operand,
                    const int               memoryAddr,
                    vector<Instruction>&    ins_out)
{
    Instruction pre_load_instruction = {};
    pre_load_instruction.opcode = "loadI";
    pre_load_instruction.inputs.push_back(to_string(memoryAddr));
    pre_load_instruction.outputs.push_back(RenamedRegister(operand, feasibleRegSlotIdx));
    ins_out.push_back(pre_load_instruction);

    Instruction load_instruction = {};
    load_instruction.opcode = "load";
    load_instruction.inputs.push_back(RenamedRegister(operand, feasibleRegSlotIdx));
    load_instruction.outputs.push_back(RenamedRegister(operand, feasibleRegSlotIdx));
    ins_out.push_back(load_instruction);
}

void AllocRegister(const vector<Instruction>& ins_in, vector<Instruction>& ins_out, int numSlots)
{
    unordered_map<string, int> operandToMemory;

    stack<int> memoryPool;
    for (int i = 1024 / sizeof(int) - 1; i >= 0; i--)
    {
        memoryPool.push(i);
    }

    vector<string> slots(numSlots, "");

    for (int i = 0; i < ins_in.size(); i++)
    {
        #ifdef DEBUG
        PrintOneInstruction(ins_in[i]);
        #endif // #ifdef DEBUG

        string debugStr = "";
        vector<string> operands;
        for (const auto& operand : ins_in[i].inputs)  if (isRegister(operand)) operands.push_back(operand);
        for (const auto& operand : ins_in[i].outputs) if (isRegister(operand)) operands.push_back(operand);


        for (const auto& operand : operands)
        {
            // Ignore constant operand.
            if (!isRegister(operand)) continue;

            // Skip if the register is already allocated.
            if (find(slots.begin(), slots.end(), operand) != slots.end()) continue;

            vector<int> availableSlotIndices;
            GetAvailableSlots(operandToMemory, slots, availableSlotIndices);
            assert(availableSlotIndices.size() >= 1);

            #ifdef DEBUG
            cout << " availables: ";
            for (const auto& idx : availableSlotIndices)
            {
                cout << "([" + to_string(idx) + "]:" + slots[idx] + ")";
            }
            #endif // #ifdef DEBUG

            // Operand should move in to slots[victomSlot].
            int availableSlotIdx = -1;
            for (const auto& idx : availableSlotIndices)
            {
                if (find(operands.begin(), operands.end(), slots[idx]) == operands.end())
                {
                    availableSlotIdx = idx;
                    break;
                }
            }

            string loadBackReg     = "";
            int    loadBackSlotIdx = -1;

            // We must find an available slot that is not used in the current instruction and spill it out, so we can allocate this operand.
            if ((availableSlotIndices.size() == 1) || (availableSlotIdx == -1))
            {
                #ifdef DEBUG
                printf("availableSlotIndices.size() == %d, availableSlotIdx = %d\n", availableSlotIndices.size(), availableSlotIdx);
                #endif
                // Find register that has maximum late usage line
                int maxNextUsed    = 0;
                int victimSlotIdx  = -1;

                debugStr += " nextUsed: ";

                #ifdef DEBUG
                cout << " nextUsed: ";
                #endif // #ifdef DEBUG
                for (int slotIdx = 0; slotIdx < slots.size(); slotIdx++)
                {
                    // Ignore empty slot or when it already exists in memory.
                    if ((slots[slotIdx] == "") || (operandToMemory.find(slots[slotIdx]) != operandToMemory.end())) continue;

                    // Don't pick the operand that's used in the current instruction.
                    if (find(operands.begin(), operands.end(), slots[slotIdx]) != operands.end()) continue;

                    // if nextUsed is INT_MAX (never used again), no need to spill out, overwrite.
                    auto nextUsed = findNextUsed(ins_in, slots[slotIdx], i);

                    debugStr += slots[slotIdx] + "(" + to_string(nextUsed) + ")";
                    #ifdef DEBUG
                    cout << slots[slotIdx] + "(" + to_string(nextUsed) + ")";
                    #endif // #ifdef DEBUG

                    if (nextUsed > maxNextUsed)
                    {
                        maxNextUsed   = nextUsed;
                        victimSlotIdx = slotIdx;
                    }
                }

                #ifdef DEBUG
                cout << "\n";
                #endif // #ifdef DEBUG
                if (victimSlotIdx == -1)
                {
                    assert(availableSlotIndices.size() == 1); // not sure

                    // Find any slot that does not exist in the memory. Copy out to memory.
                    for (int slotIdx = 0; slotIdx < slots.size(); slotIdx++)
                    {
                        // If not exists in the memory
                        if (operandToMemory.find(slots[slotIdx]) == operandToMemory.end())
                        {
                            victimSlotIdx = slotIdx;
                            break;
                        }
                    }
                }

                assert((victimSlotIdx >= 0) && (victimSlotIdx < slots.size()));

                // Spill out that register.
                {
                    // The resident in slots[victimSlotIdx] needs to be spilled out.
                    // There must be an available memory in the pool for spilling out.
                    assert(memoryPool.size() > 0);
                    int memoryAddr = memoryPool.top() * sizeof(int);
                    memoryPool.pop();

                    // Record which memory address this operand is stored at.
                    operandToMemory[slots[victimSlotIdx]] = memoryAddr;

                    debugStr += " spill out \"" + slots[victimSlotIdx] + "\"";

                    int feasibleRegisterSlotIdx = availableSlotIndices[0];
                    #ifdef DEBUG
                    printf(" spill out \"%s\" with f1==%d\n", slots[victimSlotIdx].c_str(), feasibleRegisterSlotIdx);
                    #endif // #ifdef DEBUG
                    // No need to spill out if it's never going to be used.
                    // if (maxNextUsed != INT_MAX)
                    insertSpillOutCode(feasibleRegisterSlotIdx, slots, victimSlotIdx, memoryAddr, ins_out);

                    if (availableSlotIdx == -1)
                    {
                        loadBackSlotIdx = feasibleRegisterSlotIdx;
                        loadBackReg     = slots[loadBackSlotIdx];

                        #ifdef DEBUG
                        printf(" need to load back %s into slot#%d\n", loadBackReg.c_str(), loadBackSlotIdx);
                        #endif // #ifdef DEBUG
                    }

                    // It was used as feasible register, mark slot as empty.
                    slots[feasibleRegisterSlotIdx] = "";

                    // We don't need to mark the slot as empty. It can stay.
                    // slots[victimSlotIdx] = "";
                }
            }

            // load back
            if (loadBackSlotIdx != -1)
            {
                #ifdef DEBUG
                printf(" Loading back %s into slot#%d\n", loadBackReg.c_str(), loadBackSlotIdx);
                #endif // #ifdef DEBUG
                debugStr += " Loading back " + loadBackReg + " into slot#" + to_string(loadBackSlotIdx);

                assert(loadBackReg != "");
                assert(operandToMemory.find(loadBackReg) != operandToMemory.end());
                int memoryAddr = operandToMemory[loadBackReg];
                insertLoadCode(loadBackSlotIdx, loadBackReg, memoryAddr, ins_out);
                slots[loadBackSlotIdx] = loadBackReg;
            }

            GetAvailableSlots(operandToMemory, slots, availableSlotIndices);
            assert(availableSlotIndices.size() > 1);

            // Operand should move in to slots[victomSlot].
            availableSlotIdx = -1;
            for (const auto& idx : availableSlotIndices)
            {
                if (find(operands.begin(), operands.end(), slots[idx]) == operands.end())
                {
                    availableSlotIdx = idx;
                    break;
                }
            }

            #ifdef DEBUG
            if (!(availableSlotIdx >= 0 && availableSlotIdx < slots.size()))
            {
                cout << ">>>>>>>>>>>>>>>>>>>>> operand: " << operand << endl;
            }
            #endif // #ifdef DEBUG

            assert(availableSlotIdx >= 0 && availableSlotIdx < slots.size());

            // Allocate
            slots[availableSlotIdx] = operand;

            #ifdef DEBUG
            cout << " move " << operand << " into slot#" << to_string(availableSlotIdx) << endl;
            #endif // #ifdef DEBUG

            debugStr += " move " + operand + " into slot#" + to_string(availableSlotIdx);

            // Read from memory if it was spilled out.
            if (operandToMemory.find(operand) != operandToMemory.end())
            {
                // spilled instruction is in operandToMemory[memoryAddr]
                // locate instruction and load back to slots
                // place instruction in next line and place to slot
                int memoryAddr = operandToMemory[operand];

                // Leave it in the memory. Do not erase it.
                //operandToMemory.erase(operand);
                //assert(memoryAddr % sizeof(int) == 0);
                //memoryPool.push(memoryAddr / sizeof(int));
                insertLoadCode(availableSlotIdx, operand, memoryAddr, ins_out);
            }

            #ifdef DEBUG
            cout << " slots: ";
            for (const auto& resident : slots)
            {
                cout << "(" + resident + ")";
            }

            cout << " memory: ";
            for (const auto& card : operandToMemory)
            {
                cout << "(" + card.first + "," + to_string(card.second) + ")";
            }
            cout << "\n";
            #endif // #ifdef DEBUG
        }

        // Since the output operands are updated, if they exist in the memory, the value in the memory must be out-dated,
        // invalidate the output operands in the memory, and release the memory.
        if (strncmp(ins_in[i].opcode.c_str(), "store", 5) != 0)
        {
            for (const auto& output_operand : ins_in[i].outputs)
            {
                auto it = operandToMemory.find(output_operand);
                if (it != operandToMemory.end())
                {
                    #ifdef DEBUG
                    cout << " invalidate " << it->first << " in memory address " << to_string(it->second) << endl;
                    #endif // #ifdef DEBUG
                    debugStr += " invalidate " + it->first + " in memory address " + to_string(it->second);
                    memoryPool.push(it->second);
                    operandToMemory.erase(it);

                    #ifdef DEBUG
                    cout << " memory-after-invalidate: ";
                    for (const auto& card : operandToMemory)
                    {
                        cout << "(" + card.first + "," + to_string(card.second) + ")";
                    }
                    cout << "\n";
                    #endif // #ifdef DEBUG
                }
            }
        }

        debugStr += " slots: ";
        for (const auto& resident : slots)
        {
            debugStr += "(" + resident + ")";
        }

        debugStr += " memory: ";
        for (const auto& card : operandToMemory)
        {
            debugStr += "(" + card.first + "," + to_string(card.second) + ")";
        }

        // All operands in the current instruction has been allocated physical registers.
        // add r11, r14 => r16
        // slots [r11, r16, r14]
        // add slot#0, slot#2 => slot#1
        Instruction renamed_instruction = {};

        renamed_instruction.debugStr = debugStr;

        renamed_instruction.opcode = ins_in[i].opcode;

        for (const auto& operand : ins_in[i].inputs)
        {
            // cout << "operand = " << operand << endl;
            if (isRegister(operand))
            {
                bool found = false;
                for (int slotIdx=0; slotIdx<slots.size(); slotIdx++)
                {
                    // cout << "slots[" << slotIdx << "] = " << slots[slotIdx] << endl;
                    if (slots[slotIdx] == operand)
                    {
                        renamed_instruction.inputs.push_back(RenamedRegister(operand, slotIdx));
                        found = true;
                    }
                }
                assert(found == true);
            }
            else
            {
                renamed_instruction.inputs.push_back(operand);
            }
        }


        for (const auto& operand : ins_in[i].outputs)
        {
            if (isRegister(operand))
            {
                bool found = false;
                for (int slotIdx=0; slotIdx<slots.size(); slotIdx++)
                {
                    if (slots[slotIdx] == operand)
                    {
                        renamed_instruction.outputs.push_back(RenamedRegister(operand, slotIdx));
                        found = true;
                    }
                }
                assert(found == true);
            }
            else
            {
                renamed_instruction.outputs.push_back(operand);
            }
        }

        ins_out.push_back(renamed_instruction);
    }
}


int main(int argc, char *argv[])
{
    if (argc != 4) {
        perror("Error: invalid input\n");
        fprintf(stderr, "Usage:\n\t%s <pattern>\n", argv[0]);
        return -1;
    }

    const int numRegisters = atoi(argv[1]);
    FILE* iFile = fopen(argv[2], "r");
    FILE* oFile = fopen(argv[3], "w");

    assert(iFile != NULL);
    assert(oFile != NULL);

    vector<Instruction> instructions;

    char buffer[MAXBUFFERSIZE];
    while (true)
    {
        if (fgets(buffer, MAXBUFFERSIZE, iFile) == NULL) break;

        const char* delimiters = ", \t\n";
        char* ctoken = strtok(buffer, delimiters);

        string token;

        Instruction instruction;
        bool isInstruction = false;

        string         opcode;
        vector<string> inputs;
        vector<string> outputs;
        bool           first = true;
        bool           isLHS = true;

        while (ctoken)
        {
            token = string(ctoken);

            // Skip empty lines
            if (ctoken[0] == '\0') break;

            // Skip comment lines
            if (strncmp(token.c_str(), "//", 2) == 0) break;

            // printf("[%s]\n", ctoken);
            // printf("{%s}\n", token.c_str());
            // cout << "(" << token << ") ";
            isInstruction = true;

            // Trim comma
            {
                auto comma = std::find(token.begin(), token.end(), ',');
                if (comma != token.end()) token.erase(comma);
            }

            if (first)
            {
                instruction.opcode = token;
                first = false;
            }
            else if (token == "=>")
            {
                isLHS = false;
            }
            else if (isLHS)
            {
                instruction.inputs.push_back(token);
            }
            else
            {
                instruction.outputs.push_back(token);
            }

            ctoken = strtok(nullptr, delimiters);
        }

        if (isInstruction)
        {
            instructions.push_back(instruction);
        }

        // fprintf(oFile, "%s", buffer);
    }

    fclose(iFile);

    // DumpInstructions(instructions);

    vector<Instruction> alloc_instructions;
    AllocRegister(instructions, alloc_instructions, numRegisters);

    // printf("============ Processed ===========\n");

    #ifdef DEBUG
    DumpInstructions(alloc_instructions, stdout);
    #else
    DumpInstructions(alloc_instructions, oFile);
    #endif // #ifdef DEBUG

    fclose(oFile);
    return 0;
}
