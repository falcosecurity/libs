#pragma once

#include "visitor.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <exception>

struct cpp_readwrite_defs_visitor: public defs_visitor
{
    virtual ~cpp_readwrite_defs_visitor() = default;

    void start_events()
    {
        std::cout << "// this file is generated automatically\n\n";
        std::cout << "#pragma once\n";
        std::cout << "\n";
        std::cout << "#include <falcosecurity/event_writer.h>\n";
        std::cout << "#include <falcosecurity/internal/hacks.h>\n";
        std::cout << "#include <falcosecurity/types.h>\n";
        std::cout << "#include <stdexcept>\n";
        std::cout << "#include <string>\n";
        std::cout << "\n";
        std::cout << "namespace falcosecurity {\n";
        std::cout << "namespace events {\n";
        std::cout << "\n";
    }

    void end_events()
    {
        std::cout << "}; // namespace events\n";
        std::cout << "}; // namespace falcosecurity\n";
        std::cout << "\n";
    }

    void on_event(ppm_event_code code, const char* defname, const struct ppm_event_info& info)
    {
        std::string classname = defname + 5; // skip ppme_ prefix
        std::transform(classname.begin(), classname.end(), classname.begin(),
            [](auto c){ return std::tolower(c); });
        classname += "_encoder";

        std::string paramlentype = "uint16_t";
        if (info.flags & EF_LARGE_PAYLOAD)
        {
            paramlentype = "uint32_t";
        }

        // todo: make this stringstram (one for private vars, one for length encoding, one for data encoding)
        std::stringstream sencode_grow;
        std::stringstream sencode_len;
        std::stringstream sencode_data;
        std::stringstream smethods;
        std::stringstream sprivate_vars;

        sprivate_vars << "private:\n";
        sprivate_vars << "    uint64_t m_evt_ts = (uint64_t)-1;\n";
        sprivate_vars << "    uint64_t m_evt_tid = (uint64_t)-1;\n";

        sencode_grow << std::to_string(sizeof(ppm_evt_hdr));
        sencode_grow << "+(sizeof(" << paramlentype << ") * " << info.nparams << ")";

        smethods << "    FALCOSECURITY_INLINE\n";
        smethods << "    void set_evt_tid(uint64_t v)\n";
        smethods << "    {\n";
        smethods << "        m_evt_tid = v;\n";
        smethods << "    }\n\n";
        smethods << "    FALCOSECURITY_INLINE\n";
        smethods << "    void set_evt_ts(uint64_t v)\n";
        smethods << "    {\n";
        smethods << "        m_evt_ts = v;\n";
        smethods << "    }\n\n";

        for (size_t i = 0; i < info.nparams; i++)
        {
            bool skip = false;
            auto &p = info.params[i];
            std::string pname = p.name;
            std::transform(pname.begin(), pname.end(), pname.begin(),
                [](auto c){ return std::tolower(c); });
            std::stringstream body;
            std::stringstream signature;
            signature << "    FALCOSECURITY_INLINE\n";
            signature << "    void set_" + pname + "(";
            body << "    {\n";
            body << "        m_" + pname + " = v;\n";
            switch(p.type)
            {
                case PT_INT8:
                    signature << "int8_t v";
                    sprivate_vars << "    int8_t m_" + pname + " = 0;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = sizeof(int8_t);\n";
                    sencode_data << "        *((int8_t*) parambuf) = m_" + pname + ";\n";
                    sencode_data << "        parambuf += sizeof(int8_t);\n";
                    sencode_grow << "+sizeof(int8_t)";
                    break;
                case PT_INT16:
                    signature << "uint16_t v";
                    sprivate_vars << "    uint16_t m_" + pname + " = 0;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = sizeof(int16_t);\n";
                    sencode_data << "        *((int16_t*) parambuf) = m_" + pname + ";\n";
                    sencode_data << "        parambuf += sizeof(int16_t);\n";
                    sencode_grow << "+sizeof(int16_t)";
                    break;
                case PT_INT32:
                    signature << "int32_t v";
                    sprivate_vars << "    int32_t m_" + pname + " = 0;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = sizeof(int32_t);\n";
                    sencode_data << "        *((int32_t*) parambuf) = m_" + pname + ";\n";
                    sencode_data << "        parambuf += sizeof(int32_t);\n";
                    sencode_grow << "+sizeof(int32_t)";
                    break;
                case PT_ERRNO:
                case PT_INT64:
                    signature << "int64_t v";
                    sprivate_vars << "    int64_t m_" + pname + " = 0;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = sizeof(int64_t);\n";
                    sencode_data << "        *((int64_t*) parambuf) = m_" + pname + ";\n";
                    sencode_data << "        parambuf += sizeof(int64_t);\n";
                    sencode_grow << "+sizeof(int64_t)";
                    break;
                case PT_SIGTYPE:
                case PT_L4PROTO:
                case PT_SOCKFAMILY:
                case PT_FLAGS8:
                case PT_ENUMFLAGS8:
                case PT_UINT8:
                    signature << "uint8_t v";
                    sprivate_vars << "    uint8_t m_" + pname + " = 0;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = sizeof(uint8_t);\n";
                    sencode_data << "        *((uint8_t*) parambuf) = m_" + pname + ";\n";
                    sencode_data << "        parambuf += sizeof(uint8_t);\n";
                    sencode_grow << "+sizeof(uint8_t)";
                    break;
                case PT_SYSCALLID:
                case PT_PORT:
                case PT_FLAGS16:
                case PT_ENUMFLAGS16:
                case PT_UINT16:
                    signature << "uint16_t v";
                    sprivate_vars << "    uint16_t m_" + pname + " = 0;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = sizeof(uint16_t);\n";
                    sencode_data << "        *((uint16_t*) parambuf) = m_" + pname + ";\n";
                    sencode_data << "        parambuf += sizeof(uint16_t);\n";
                    sencode_grow << "+sizeof(uint16_t)";
                    break;
                case PT_FLAGS32:
                case PT_UID:
                case PT_GID:
                case PT_SIGSET:
                case PT_MODE:
                case PT_ENUMFLAGS32:
                case PT_UINT32:
                    signature << "uint32_t v";
                    sprivate_vars << "    uint32_t m_" + pname + " = 0;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = sizeof(uint32_t);\n";
                    sencode_data << "        *((uint32_t*) parambuf) = m_" + pname + ";\n";
                    sencode_data << "        parambuf += sizeof(uint32_t);\n";
                    sencode_grow << "+sizeof(uint32_t)";
                    break;
                case PT_BOOL:
                    signature << "bool v";
                    sprivate_vars << "    bool m_" + pname + " = false;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = sizeof(uint32_t);\n";
                    sencode_data << "        *((uint32_t*) parambuf) = m_" + pname + ";\n";
                    sencode_data << "        parambuf += sizeof(uint32_t);\n";
                    sencode_grow << "+sizeof(uint32_t)";
                    break;
                case PT_FD:
                case PT_PID:
                case PT_RELTIME:
                case PT_ABSTIME:
                case PT_CHARBUFARRAY:
                case PT_CHARBUF_PAIR_ARRAY:
                case PT_UINT64:
                    signature << "uint64_t v";
                    sprivate_vars << "    uint64_t m_" + pname + " = 0;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = sizeof(uint64_t);\n";
                    sencode_data << "        *((uint64_t*) parambuf) = m_" + pname + ";\n";
                    sencode_data << "        parambuf += sizeof(uint64_t);\n";
                    sencode_grow << "+sizeof(uint64_t)";
                    break;
                case PT_FSRELPATH:
                case PT_FSPATH:
                case PT_CHARBUF:
                    signature << "const std::string& v";
                    sprivate_vars << "    std::string m_" + pname + ";\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = m_" + pname + ".length() + 1;\n";
                    sencode_data << "        memcpy(parambuf, m_" + pname + ".c_str(), m_" + pname + ".length() + 1);\n";
                    sencode_data << "        parambuf += m_" + pname + ".length() + 1;\n";
                    sencode_grow << "+(m_" + pname + ".length() + 1)";
                    break;
                case PT_DYN:
                case PT_SOCKADDR:
                case PT_SOCKTUPLE:
                case PT_FDLIST:
                case PT_BYTEBUF:
                    signature << "void* v, uint32_t vlen";
                    body << "        m_" + pname + "len = vlen;\n";
                    sprivate_vars << "    void* m_" + pname + " = nullptr;\n";
                    sprivate_vars << "    uint32_t m_" + pname + "len = 0;\n";
                    sencode_len << "        *((" +    paramlentype + "*) parambuf) = m_" + pname + "len;\n";
                    sencode_data << "        memcpy(parambuf, m_" + pname + ", m_" + pname + "len);\n";
                    sencode_data << "        parambuf += m_" + pname + "len;\n";
                    sencode_grow << "+m_" + pname + "len";
                    break;
                case PT_DOUBLE:
                case PT_IPADDR:
                case PT_IPV4ADDR:
                case PT_IPV6ADDR:
                case PT_IPNET:
                case PT_IPV4NET:
                case PT_IPV6NET:
                default:
                    skip = true;
                    fprintf(stderr, "skipping unsupported param type: %s\n", std::to_string(p.type).c_str());
                    break;
            }
            if (!skip)
            {
                sencode_len << "        parambuf += sizeof(" + paramlentype + ");\n";
                signature << ")\n";
                body << "    }\n";
                body << "\n";
                smethods << signature.str() << body.str();
            }
        }

        std::cout << "class " + classname + "\n";
        std::cout << "{\n";
        std::cout << "public:\n";
        std::cout << "    FALCOSECURITY_INLINE\n";
        std::cout << "    " + classname + "() = default;\n";
        std::cout << "    FALCOSECURITY_INLINE\n";
        std::cout << "    ~" + classname + "() = default;\n";
        std::cout << "    FALCOSECURITY_INLINE\n";
        std::cout << "    " + classname + "(" + classname + "&&) = default;\n";
        std::cout << "    FALCOSECURITY_INLINE\n";
        std::cout << "    " + classname + "& operator = (" + classname + "&&) = default;\n";
        std::cout << "    FALCOSECURITY_INLINE\n";
        std::cout << "    " + classname + "(const " + classname + "& s) = default;\n";
        std::cout << "    FALCOSECURITY_INLINE\n";
        std::cout << "    " + classname + "& operator = (const " + classname + "& s) = default;\n";
        std::cout << "\n";
        std::cout << "    FALCOSECURITY_INLINE\n";
        std::cout << "    void encode(falcosecurity::event_writer& w) const\n";
        std::cout << "    {\n";
        std::cout << "        w.grow(" << sencode_grow.str() << ");\n";
        std::cout << "        uint8_t* evt = (uint8_t*)w.get_buf();\n";
        std::cout << "        uint8_t* parambuf = evt + " + std::to_string(sizeof(ppm_evt_hdr)) + ";\n";
        std::cout << "        *((uint64_t*)(evt + " + std::to_string(offsetof(ppm_evt_hdr, ts))+ ")) = m_evt_ts;\n";
        std::cout << "        *((uint64_t*)(evt + " + std::to_string(offsetof(ppm_evt_hdr, tid))+ ")) = m_evt_tid;\n";
        std::cout << "        *((uint16_t*)(evt + " + std::to_string(offsetof(ppm_evt_hdr, type))+ ")) = " + std::to_string(code) + ";\n";
        std::cout << "        *((uint32_t*)(evt + " + std::to_string(offsetof(ppm_evt_hdr, nparams))+ ")) = " + std::to_string(info.nparams) + ";\n";
        std::cout << sencode_len.str();
        std::cout << sencode_data.str();
        std::cout << "        *((uint32_t*)(evt + " + std::to_string(offsetof(ppm_evt_hdr, len))+ ")) = (uint32_t)(parambuf - evt);\n";
        std::cout << "    }\n";
        std::cout << "\n";
        std::cout << smethods.str();
        std::cout << sprivate_vars.str();
        std::cout << "};\n";
        std::cout << "\n";
    }

};
