#include <iostream>
#include <fstream>
#include <cstring>
#include <stdio.h>
#include <Windows.h>
#include <vector>
#include <string>
#include <windows.h>
#include <locale.h>
#include <TCHAR.h>
#include <strsafe.h>
#include <ImageHlp.h>
#include <memory.h>
#define BufferLength 512

uint64_t uint8to64(uint8_t eightuint8[8]) {
    return *(uint64_t*)eightuint8;
}
uint16_t uint8to16(uint8_t twouint8[2]) {
    return *(uint16_t*)twouint8;
}
uint32_t uint8to32(uint8_t fouruint8[4]) {
    return *(uint32_t*)fouruint8;
}

struct MasterDBR {
    uint8_t osboot[446];//引导代码和55AA 
    uint8_t depart1[16];
    uint8_t depart2[16];
    uint8_t depart3[16];
    uint8_t depart4[16];
    uint8_t end5;
    uint8_t endA;
};
//DBR结构，EBR应该也是类似管理 
struct FATDBR {
    uint8_t jumpcode[3];//EB 58 90
    uint8_t OEM[8];//OEM代号
    // BPB

    uint8_t bytes_per_sector[2];//扇区字节数
    uint8_t secotrs_per_cluster;//每簇扇区数
    uint8_t reserve_sectors[2];//保留扇区数
    uint8_t FATnum;//FAT个数，一般为2 

    uint8_t unimportant1[9];// 无用
    uint8_t diskHeads[2]; // 磁头数

    uint8_t DBR_LBA[4];// 隐藏扇区数
    uint8_t totalsectors[4];//本分区的总扇区数
    uint8_t sectors_per_FAT[4];//每个FAT的扇区数
    uint8_t unimportant2[4];// 标记 + 版本
    uint8_t root_cluster_number[4];//根目录簇号
    uint8_t file_info[2];// 文件系统信息扇区号
    uint8_t backup_DBR[2];//备份引导扇区的相对于DBR的扇区号，一般为6，内容和DBR一模一样
    uint8_t zero1[12];// 保留
    uint8_t extBPB[26];//扩展BPB
    uint8_t osboot[422];//引导代码和55AA 
};
struct FDT {
    uint8_t content[32];
};

//短文件目录项32字节
struct shortFDT {
    uint8_t filename[8];//第一部分文件名
    uint8_t extname[3];//文件扩展名
    uint8_t attr;//属性 0F则说明是长文件需要索引到非0F，然后倒着读回来
    uint8_t reserve;
    uint8_t time1;
    uint8_t creattime[2];
    uint8_t createdate[2];
    uint8_t visittime[2];
    uint8_t high_cluster[2];//文件起始簇号高16位
    uint8_t changetim2[2];
    uint8_t changedate[2];
    uint8_t low_cluster[2];//文件起始簇号低16位
    uint8_t filelen[4];//文件长度
};

struct longFDT {
    char flag;//如果是0x4*,第6位置位了，说明是最后一个长文件目录，各位是下面还有几个
    char name1[10];
    char attr;//如果是长文件名，除了最下面一个，都是0F
    char reserve;
    char checksum;
    char name2[12];
    char rel_cluster[2];//相对起始簇号
    char name3[4];
};

struct FATDBR fatDBR;
ULONGLONG FAT32_reladdr;
char* GetDriveGeometry(DISK_GEOMETRY* pdg, int addr)
{
    HANDLE hDevice;               // 设备句柄
    BOOL bResult;                 // results flag
    DWORD junk;                   // discard resultscc
    uint8_t lpBuffer[BufferLength] = { 0 };


    //通过CreateFile来获得设备的句柄
    hDevice = CreateFile(TEXT("\\\\.\\PhysicalDrive2"), // 设备名称,这里指第一块硬盘
        GENERIC_READ,                // no access to the drive
        FILE_SHARE_READ | FILE_SHARE_WRITE,  // share mode
        NULL,             // default security attributes
        OPEN_EXISTING,    // disposition
        0,                // file attributes
        NULL);            // do not copy file attributes
    if (hDevice == INVALID_HANDLE_VALUE) // cannot open the drive
    {
        printf("Creatfile error!May be no permission!ERROR_ACCESS_DENIED\n");
        return (FALSE);
    }
    //通过DeviceIoControl函数与设备进行IO
    bResult = DeviceIoControl(hDevice, // 设备的句柄
        IOCTL_DISK_GET_DRIVE_GEOMETRY, // 控制码，指明设备的类型
        NULL,
        0, // no input buffer
        pdg,
        sizeof(*pdg),
        &junk,                 // # bytes returned
        (LPOVERLAPPED)NULL); // synchronous I/O

    LARGE_INTEGER offset;//long long signed
    offset.QuadPart = (ULONGLONG)addr * (ULONGLONG)512;//0

    SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//从0开始读MBR
    if (GetLastError())
        printf("错误类型代号：%ld\n\n", GetLastError());//如果出错了

    DWORD dwCB;
    struct MasterDBR the_MasterDBR;
    //从这个位置开始读 
    BOOL bRet = ReadFile(hDevice, &the_MasterDBR, 512, &dwCB, NULL);
    printf("第一个分区的偏移扇区是 :\n");
    for (int i = 0; i < 16; ++i) {
        printf("%02x ", the_MasterDBR.depart1[i]);
    }
    printf("第一个扇区数据转为十进制 \n");

    uint8_t tmp1[2] = { the_MasterDBR.depart1[8], the_MasterDBR.depart1[9] };
    uint8_t tmp2[2] = { the_MasterDBR.depart2[8], the_MasterDBR.depart2[9] };
    uint8_t tmp3[2] = { the_MasterDBR.depart3[8], the_MasterDBR.depart3[9] };
    uint8_t tmp4[2] = { the_MasterDBR.depart4[8], the_MasterDBR.depart4[9] };

    DWORD depart1_cluster_num = uint8to16(tmp1);
    DWORD depart2_cluster_num = uint8to16(tmp2);
    DWORD depart3_cluster_num = uint8to16(tmp3);
    DWORD depart4_cluster_num = uint8to16(tmp4);


    FAT32_reladdr = depart1_cluster_num *
        (ULONGLONG)512;//得到FAT32的具体地址，但是偏移需要用相对偏移 
    printf("FAT32文件系统的偏移地址 %llu \n ", FAT32_reladdr);

    // 重新设置偏移量
    offset.HighPart = 0;
    offset.LowPart = FAT32_reladdr;
    SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);


    BOOL bRet1 = ReadFile(hDevice, &fatDBR, 512, &dwCB, NULL);
    // 都是相对于FAT32系统的起始位置
    ULONGLONG FAT1_reladdr = (ULONGLONG)uint8to16(fatDBR.reserve_sectors) *
        (ULONGLONG)512;//得到FAT1的具体地址，但是偏移需要用相对偏移
    ULONGLONG root_reladdr = FAT1_reladdr + (ULONGLONG)(fatDBR.FATnum) *
        (ULONGLONG)uint8to32(fatDBR.sectors_per_FAT) * (ULONGLONG)512;//根目录的起始相对位置,根目录是在第[01]2簇

    // 读取FAT 暂时先读512个字节
    offset.HighPart = 0;
    offset.LowPart = FAT32_reladdr + FAT1_reladdr;
    uint8_t FAT[512] = { 0 };
    SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//从0开始读MBR
    BOOL bRet2 = ReadFile(hDevice, &FAT, 512, &dwCB, NULL);
    printf("FAT表的内容 \n");
    for (int i = 0; i < 512; i++) {
        printf("%02x ", FAT[i]);
    }


    printf("保留扇区数: %02x %02x \n", fatDBR.reserve_sectors[0], fatDBR.reserve_sectors[1]);
    printf("每个FAT的扇区数: %02x %02x %02x %02x\n", fatDBR.sectors_per_FAT[0], fatDBR.sectors_per_FAT[1], fatDBR.sectors_per_FAT[2], fatDBR.sectors_per_FAT[3]);
    printf("每个FAT的扇区数: %llu \n", (ULONGLONG)uint8to32(fatDBR.sectors_per_FAT));
    printf("FAT1的偏移字节数: %llu \n", FAT1_reladdr);
    printf("ROOT的偏移字节数: %llu \n", root_reladdr);


    // 开始读取目录项

    // 重新设置偏移量
    offset.HighPart = 0;
    offset.LowPart = FAT32_reladdr + root_reladdr;
    SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//从0开始读MBR
    BOOL bRet3 = ReadFile(hDevice, &lpBuffer, 512, &dwCB, NULL);
    FDT tmpFDT16[16] = { 0 };
    memset(tmpFDT16, 0, sizeof(tmpFDT16));
    memcpy(tmpFDT16, lpBuffer, 512);
    // ***************************************************************仅限于低16位的簇 ***********************************************************

    // 文件名，与簇号链一一对应
    std::vector<char*> fi_name;
    char* res_file;
    // 遍历前16个目录项
    for (int i = 0; i < 16; i++) {
        FDT tmpFDT1 = tmpFDT16[i];
        if (tmpFDT1.content[11] == 0x00) {
            break;
        }
        // 短文件
        if (tmpFDT1.content[11] != 0x0F) {
            char prename[9] = { 0 };
            char rearname[4] = { 0 };
            strncpy_s(prename, reinterpret_cast<const char*>(&tmpFDT1.content[0]), 8);
            strncpy_s(rearname, reinterpret_cast<const char*>(&tmpFDT1.content[8]), 3);
            printf("文件名为: %s \n", prename);
            printf("扩展名名为: %s \n", rearname);
            // 去掉 prename 后面的空格
            int len = strlen(prename);
            while (len > 0 && prename[len - 1] == ' ') {
                len--;
            }
            prename[len] = '\0'; // 设置 null 终止符
            if (rearname[0] == 'E' && rearname[1] == 'X' && rearname[2] == 'E') {
                printf("找到EXE文件: %s.%s \n", prename, rearname);
                char* restmp = prename;
                CloseHandle(hDevice);
                return restmp;
            }

            // 找簇号链
            uint8_t cu_num[2] = { tmpFDT1.content[26], tmpFDT1.content[27] };
            uint16_t t_num = uint8to16(cu_num);
            if (t_num == 0) {
                continue;
            }
            printf("起始簇号为: %hu \n", t_num);
            // 创建一个新的 char 数组来存储 prename 数组的副本
            char* copy = new char[9];
            std::memcpy(copy, prename, 9);
            fi_name.push_back(copy);
            std::vector<uint16_t> tmpcu;
            tmpcu.push_back(t_num);

            uint16_t cur_num = FAT[t_num * 4];
        }

        printf("\n第 %d 块目录项的值 \n", i);
        for (int i = 0; i < 32; i++) {
            printf("%02x ", tmpFDT1.content[i]);
        }
        printf("\n");
    }
    CloseHandle(hDevice);
    return nullptr;
}
int main() {
    DISK_GEOMETRY pdg;            // 保存磁盘参数的结构体
    BOOL bResult;                 // generic results flag
    ULONGLONG DiskSize;           // size of the drive, in bytes
    printf("<-----------------欢迎使用解析FAT32根目录的EXE文件程序----------------->\n\n");
    char* file_name = GetDriveGeometry(&pdg, 0);
    printf("main函数的得到返回exe文件名字: %s \n", file_name);
    HANDLE hFile;
    HANDLE hMapping;
    LPVOID pMapping;
    // 文件路径
    LPCWSTR filePath1 = L"D:\\gx.exe";
    // loadPE(hFile, hMapping, pMapping, filePath);
    hFile = CreateFileW(filePath1, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        printf("无效INVALID_HANDLE_VALUE");
        return 0;
    }
    // 将PE文件映射到内存
    // 注意权限
    hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
    if (!hMapping) {
        printf("无效hMapping");
        return 0;
    }
    pMapping = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);//返回的是map的开始地址
    if (!pMapping) {
        printf("无效pMapping");
        return 0;
    }
    PIMAGE_DOS_HEADER dosheader;
    dosheader = (PIMAGE_DOS_HEADER)pMapping;
    if (dosheader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("无效");
        return 0;
    }
    printf("测试读入的pe头: %d \n", dosheader->e_magic);
    PIMAGE_NT_HEADERS nt_header;
    nt_header = (PIMAGE_NT_HEADERS)((BYTE*)pMapping + dosheader->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "无效的PE文件" << std::endl;
        return 0;
    }

    printf("AddressOfEntryPoint: %#x\n", nt_header->OptionalHeader.AddressOfEntryPoint);
    printf("ImageBase: %#x\n", nt_header->OptionalHeader.ImageBase);
    printf("SectionAlignment: %#x\n", nt_header->OptionalHeader.SectionAlignment);
    printf("FileAlignment: %#x\n", nt_header->OptionalHeader.FileAlignment);
    printf("NumberOfSections: %#x\n", nt_header->FileHeader.NumberOfSections);


    // 解析节表
    PIMAGE_SECTION_HEADER section_header;
    section_header = IMAGE_FIRST_SECTION(nt_header);
    printf("%-10s\t%-10s\t\t%-10s\t\t%-10s\t\t%-10s\t\t\t%-10s\n",
        "Name", "VirtualSize", "VirtualAddress", "SizeOfRawData", "PointerToRawData", "Characteristics");
    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_header++) {
        printf("%-10s\t%-10x\t\t%-10x\t\t%-10x\t\t%-10x\t\t\t%-10x\n",
            section_header->Name,
            section_header->Misc.VirtualSize,
            section_header->VirtualAddress,
            section_header->SizeOfRawData,
            section_header->PointerToRawData,
            section_header->Characteristics);
    }

    // 写入隐藏扇区
    // 准备隐藏扇区数据
    DWORD PointerToRawData = IMAGE_FIRST_SECTION(nt_header)->PointerToRawData;
    DWORD SizeOfRawData = IMAGE_FIRST_SECTION(nt_header)->SizeOfRawData;
    UINT8* textContent = new UINT8[SizeOfRawData];
    memcpy(textContent, (UINT8*)pMapping + PointerToRawData, SizeOfRawData);
    // 检查要写入的数据
    printf("要写入隐藏扇区的数据\n");
    for (int i = 0; i < SizeOfRawData; ++i) {
        printf("%02X ", textContent[i]);
    }
    printf("\n");

    CloseHandle(hFile);
    // 找到隐藏扇区
    HANDLE hDevice1;
    hDevice1 = CreateFile(TEXT("\\\\.\\PhysicalDrive2"), // 设备名称,这里指第一块硬盘
        GENERIC_WRITE | GENERIC_READ,        // Access mode  
        FILE_SHARE_READ | FILE_SHARE_WRITE,  // share mode
        NULL,             // default security attributes
        OPEN_EXISTING,    // disposition
        0,                // file attributes
        NULL);            // do not copy file attributes
    if (hDevice1 == INVALID_HANDLE_VALUE) // cannot open the drive
    {
        printf("Creatfile error!May be no permission!ERROR_ACCESS_DENIED\n");
        return 0;
    }
    DWORD junk;
    BOOL TMP = DeviceIoControl(
        hDevice1, // 设备的句柄
        FSCTL_LOCK_VOLUME, // 控制码，指明设备的类型
        NULL,
        0,
        NULL,
        0,
        &junk,
        (LPOVERLAPPED)NULL
    ); // synchronous I/O


    uint16_t bytes_per_sector = uint8to16(fatDBR.bytes_per_sector);
    printf("FAT个数: %u \n", fatDBR.FATnum);
    printf("FAT的扇区字节数: %hu \n", bytes_per_sector);
    printf("FAT的每簇扇区数: %u \n", fatDBR.secotrs_per_cluster);
    int dir_sectors = 2;
    LARGE_INTEGER offset;//long long signed
    offset.HighPart = 0;
    printf("main函数FAT32: %llu\n", FAT32_reladdr);
    offset.LowPart = FAT32_reladdr + bytes_per_sector * 2;
    offset.LowPart = 3072;
    printf("要写入的隐藏扇区的地址: %llu \n", offset.LowPart);
    SetFilePointer(hDevice1, offset.LowPart, &offset.HighPart, FILE_BEGIN);//从0开始读MBR
    DWORD NumberOfBytesWritten;
    BOOL res = WriteFile(hDevice1, textContent, SizeOfRawData, &NumberOfBytesWritten, NULL);
    if (!res) {
        DWORD dwError = GetLastError();
        printf("写入失败，错误代码: %lu\n", dwError);
        return 0;
    }
    printf("写入成功\n");

    // 开始节表免疫

    DWORD optionHeaderSize = nt_header->FileHeader.SizeOfOptionalHeader;//扩展头大小
    DWORD offsetOfFirst = optionHeaderSize + 216;//节表项开头的位置
    int numOfSections = nt_header->FileHeader.NumberOfSections;
    DWORD PointerCopy = IMAGE_FIRST_SECTION(nt_header)->PointerToRawData - 40 * numOfSections;//拷贝的位置
    printf("节表拷贝的位置: %lld \n", PointerCopy);
    memcpy((UINT8*)pMapping + PointerCopy, (UINT8*)pMapping + offsetOfFirst, 40 * numOfSections);
    nt_header->FileHeader.SizeOfOptionalHeader += (PointerCopy - offsetOfFirst);
    
    nt_header->OptionalHeader.CheckSum = 0;
    
    
    DWORD HeaderCheckSum = nt_header->OptionalHeader.CheckSum;   //PE头里的校验值
    DWORD CheckSum = 0;
    
    // 节间免疫
    // 遍历节表
    PIMAGE_SECTION_HEADER section_header1;
    section_header1 = IMAGE_FIRST_SECTION(nt_header);
    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_header1++) {
        // 修改vir的大小
        // memcpy(&(section_header1->SizeOfRawData), &(section_header1->Misc.VirtualSize), 4);
        section_header1->Misc.VirtualSize = section_header1->SizeOfRawData;
    }
    printf("节间免疫完成,修改了 %d 个节表 \n", nt_header->FileHeader.NumberOfSections);
    //计算校验值

    MapFileAndCheckSumW(filePath1, &HeaderCheckSum, &CheckSum);
    printf("修改校验和完成,新的校验和 %lld \n", CheckSum);
    nt_header->OptionalHeader.CheckSum = CheckSum;//修改checkSum
    FlushViewOfFile(pMapping, 0);
    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    printf("修改校验和完成,新的校验和 %lld \n", CheckSum);

    return 0;
}