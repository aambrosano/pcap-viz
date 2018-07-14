#ifndef PCAPOPTIONCODES_H
#define PCAPOPTIONCODES_H

class OptionCode {
public:
    static const int EndOfOpt = 0;
    static const int Comment = 1;
    static const int Custom1 = 2988;
    static const int Custom2 = 2989;
    static const int Custom3 = 19372;
    static const int Custom4 = 19373;
};

class OptionCodeInterfaceDescriptionBlock : public OptionCode {
public:
    static const int IfName = 2;
    static const int IfDescription = 3;
    static const int IfIPv4Addr = 4;
    static const int IfIPv6Addr = 5;
    static const int IfMACAddr = 6;
    static const int IfEUIAddr = 7;
    static const int IfSpeed = 8;
    static const int IfTsResol = 9;
    static const int IfTzone = 10;
    static const int IfFilter = 11;
    static const int IfOs = 12;
    static const int IfFcsLen = 13;
    static const int IfTsOffset = 14;
};

class OptionCodeEnhancedPacketBlock : public OptionCode {
public:
    static const int EPBFlags = 2;
    static const int EPBHash = 3;
    static const int EPDropCount = 4;
}

#endif // PCAPOPTIONCODES_H
