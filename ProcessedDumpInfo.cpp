#include "ProcessedDumpInfo.h"
#include <cstdio>
#include <cstdarg>

void ProcessedDumpInfoHandler::AddString(char const* pFormat, ...)
{
    va_list args;
    va_start(args, pFormat);

    // 计算所需缓冲区大小（包含结尾 '\0'）
    int len = _vscprintf(pFormat, args);
    if (len < 0) {
        va_end(args);
        return; // 格式化出错，直接返回
    }

    std::string buf;
    buf.resize(len);                       // 不包含 '\0'
    _vsnprintf_s(&buf[0], len + 1, _TRUNCATE, pFormat, args);
    va_end(args);

    Entries.emplace_back(ProcessedDumpInfoEntry_String{ std::move(buf) });
}

void ProcessedDumpInfoHandler::Flush()
{
    for (const auto& entry : Entries) {
        std::visit([](const auto& e) {
            if constexpr (std::is_same_v<std::decay_t<decltype(e)>, ProcessedDumpInfoEntry_String>) {
                Log::WriteLine("%s", e.Info.c_str());
            }
            else { // ProcessedDumpInfoEntry_Addr
                if (!e.Processed.empty())
                {
                    Log::WriteLine("%s", e.Processed.c_str());
                }
            }
            }, entry);
    }
}

void ProcessedDumpInfoHandler::Fillin(const std::vector<std::string> DescStr)
{
    std::size_t idx = 0;
    for (auto& entry : Entries) {
        if (auto* pAddr = std::get_if<ProcessedDumpInfoEntry_Addr>(&entry)) {
            if (idx < DescStr.size()) {
                pAddr->Processed = DescStr[idx++];
            }
            // 若 DescStr 数量不足，剩余条目保持 Processed 为空
        }
    }
}