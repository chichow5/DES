#include <iostream>
#include <bitset>
namespace DES{

    enum{
        ENCRYPT,
        DECRYPT
    };
    int mode;

    /* 初始置换IP */
    const static char initial_substitution_IP[]={
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };
    /* 逆初始置换IP-1 */
    const static char inverse_substitution_IP[]={
            40,  8, 48, 16, 56, 24, 64, 32,
            39,  7, 47, 15, 55, 23, 63, 31,
            38,  6, 46, 14, 54, 22, 62, 30,
            37,  5, 45, 13, 53, 21, 61, 29,
            36,  4, 44, 12, 52, 20, 60, 28,
            35,  3, 43, 11, 51, 19, 59, 27,
            34,  2, 42, 10, 50, 18, 58, 26,
            33,  1, 41,  9, 49, 17, 57, 25
    };
    /* 位选择函数E */
    const static char bit_extend_E[]={
            32,  1,  2,  3,  4,  5,
            4,  5,  6,  7,  8,  9,
            8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
    };
    /* 置换函数P */
    const static char bit_narrow_P[]={
            16,  7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2,  8, 24, 14,
            32, 27,  3,  9,
            19, 13, 30,  6,
            22, 11,  4, 25
    };
    /* S盒 */
    const static char S[][64] = {
            //{},

            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
             0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
             4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
             15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},

            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
             3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
             0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
             13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},

            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
             13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
             13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
             1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},

            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
             13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
             10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
             3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},

            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
             14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
             4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
             11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},

            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
             10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
             9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
             4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},

            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
             13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
             1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
             6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},

            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
             1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
             7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
             2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    };
    /* 置换选择PC-1 */
    const static char key_substitution_p1[]={
            57, 49, 41,	33,	25,	17,	9,
            1,	58,	50,	42,	34,	26,	18,
            10,	2,	59,	51,	43,	35,	27,
            19,	11,	3,	60,	52,	44,	36,
            63,	55,	47,	39,	31,	23,	15,
            7,	62,	54,	46,	38,	30,	22,
            14,	6,	61,	53,	45,	37,	29,
            21,	13,	5,	28,	20,	12,	4
    };
    /* 置换选择PC-2 */
    const static char key_substitution_p2[]={
            14,	17,	11,	24,	1,	5,  3,	28,	15,	6,	21,	10,
            23,	19,	12,	4,	26,	8,  16,	7,	27,	20,	13,	2,
            41,	52,	31,	37,	47,	55, 30,	40,	51,	45,	33,	48,
            44,	49,	39,	56,	34,	53, 46,	42,	50,	36,	29,	32
    };
    /* 密钥生成左移量 */
    const static char key_shift_size[]={
            1, 1, 2, 2,
            2, 2, 2, 2,
            1, 2, 2, 2,
            2, 2, 2, 1
    };

    char f[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    template<typename T> void hexDump(const std::string& info, T x){
        int sx = (sizeof x)*8-4;
        std::cout<<info<<' ';
        for (int i=sx; i>=0; i-=4){
            putchar(f[(x>>i)&0xf]);
        }
        putchar('\n');
    }
    template<typename T> void hexDump(const std::string& info, T *x, size_t length){
        std::cout<<info<<' ';
        if (length < 1) return;
        int sx = (sizeof x[0])*8-4;
        for  (int i=0; i<length; i++){
            for (int j=sx; j>=0; j-=4){
                putchar(f[(x[i]>>j)&0xf]);
            }
            putchar(' ');
        }
        putchar('\n');
    }

    template<typename T> void binaryDump(const std::string& info,T x){
        int bits = (sizeof x) * 8;
        std::cout<<info<<' ';
        for (int i= bits - 1; i >= 0; i--){
            putchar(((x>>i)&1)?'1':'0');
            if ((i & 7) == 0) putchar(' ');
        }
        putchar('\n');
    }
    template<typename T> void binaryDump(const std::string& info, T *x, size_t length){
        std::cout<<info<<' ';
        if (length < 1) return;
        int bits = (sizeof x[0]) * 8;
        for (size_t i = 0; i<length; i++){
            for (int j=bits-1; j>=0; j--){
                putchar(((x[i]>>j)&1)?'1':'0');
                if ((j & 7) == 0) putchar(' ');
            }
            putchar(' ');
        }
        putchar('\n');
    }

#define BITAT(xx,yy) ((xx>>yy)&1)
#define BITUP(xx,yy) (xx<<yy)
    /**
     * 根据排列 permutation 位变换
     * @param source 输入要转换的源
     * @param permutation 变换矩阵
     * @param length 生成的结果长度
     * @return 返回生成的结果
     */
    uint64_t bitReform(uint64_t source, int sou_length, const char *permutation, int res_length ){
        uint64_t result = 0;
        for (int i=0, j= res_length - 1; i < res_length; i++,j--){
            result |= BITUP( BITAT( source, (sou_length - permutation[i]) ),  j);
        }
        return result;
    }
    uint64_t keys[16];
    /**
     * 生成16个子密钥
     * @param key 主密钥
     */
    void generateKeys(uint64_t key){
        //初始密钥变换
        uint64_t t_u64 = bitReform(key, 64, key_substitution_p1, 56);
        uint32_t c, d, tc, td;
        c = (uint32_t) (t_u64 >> 28);//c0
        d = (uint32_t) (t_u64 & ((1<<28)-1));//d0
        int sz;
        uint32_t mask[3]={0,1<<27,3<<26};
        for (int i=0; i<16; i++){
            sz = key_shift_size[i];
            tc = c; td = d;
            /* 循环移位 */
            c <<= sz;
            c &= (1<<28)-1;
            c |= ((tc & mask[sz]) >> (28-sz));
            d <<= sz;
            d &= (1<<28)-1;
            d |= ((td & mask[sz]) >> (28-sz));

            keys[i] = c;
            keys[i] <<= 28;
            keys[i] |= d;
            keys[i] = bitReform(keys[i], 56, key_substitution_p2, 48);
        }
    }
    /**
     * 64字节的主循环
     * @param in 输入的64字节
     * @return 返回加密的64字节
     */
    uint64_t mainLoop(uint64_t in){
        const static unsigned char mask = 0x3F; // 64-1
        // /* 初始置换IP */
        in = bitReform(in, 64, initial_substitution_IP, 64);
        uint64_t L,R, t_u64;
        L = (uint32_t) (in>>32);
        R = (uint32_t) in;
        unsigned char row_s, col_s, t_u8;
        for (int i=0; i<16; i++){
            uint64_t tR = R;
            R = bitReform(R, 32, bit_extend_E, 48); /* E变换 32 到 48 位拓展 */
            if (mode == ENCRYPT) R ^= keys[i];//加密
            else if(mode == DECRYPT) R ^=keys[15-i];//解密
            t_u64 = 0;
            for (int j=0; j<8; j++){
                t_u8 = (u_char) ((R >> ((7-j) * 6)) & mask);
                col_s = ((t_u8 & 0x1E) >> 1);               /* 2~5 位 */
                row_s = ((t_u8 & 0x20) >> 4) + (t_u8 & 1);  /* 1 & 6 位  */
                t_u64 |= ((S[j][row_s*16 + col_s])<<((7-j)*4));    /* 放到S盒变换 */
            }
            t_u64 = bitReform(t_u64, 32, bit_narrow_P, 32);
            R = (L ^ t_u64);
            L = tR;
        }
        t_u64 = R;
        t_u64 <<= 32;
        t_u64 |= L;
        t_u64 = bitReform(t_u64, 64, inverse_substitution_IP, 64);/* 逆初始置换IP-1 */
        return t_u64;
    }
    /**
     * DES 加密入口
     * @param message_stream 明文消息
     * @param key 密钥
     * @param length_64 需要加密的长度
     * @param ciphertext 保存到加密结果
     */
    void main(void *message_stream, uint64_t key, size_t length_64, void *ciphertext, int _mode){
        mode = _mode;
        //以64字节为单位加密
        uint64_t *stream = (uint64_t *) message_stream;
        uint64_t *result = (uint64_t *) ciphertext;
        generateKeys(key);
        for (int i=0; i < length_64; i++){
            result[i] = mainLoop(stream[i]);
        }
    }
}

int main(){
    //uint64_t msg[] = {7165065861944075634};
    //uint64_t msg[] = {0x636f6d7075746400};
    uint64_t msg[] = {0x0123456789ABCDEF};
    uint64_t key = 0x133457799BBCDFF1;
    uint64_t result[1];
    std::cout<<"书上样例"<<std::endl;
    DES::binaryDump("msg",msg,1);
    DES::hexDump("msg", msg, 1);
    DES::binaryDump("key",key);
    DES::hexDump("key",key);

    std::cout<<"加密"<<std::endl;
    DES::main(msg, key, 1, result, DES::ENCRYPT);
    DES::hexDump("res", result, 1);
    DES::binaryDump("res", result, 1);

    std::cout<<"解密"<<std::endl;
    DES::main(result, key, 1, msg, DES::DECRYPT);
    DES::hexDump("res", msg, 1);
    DES::binaryDump("res", msg, 1);
}
