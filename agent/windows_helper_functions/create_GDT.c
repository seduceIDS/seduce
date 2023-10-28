#include <unicorn/unicorn.h>
#include "../utils-windows-x68.h"
//#include <capstone/capstone.h>

static uc_err _uc_err_check(uc_err err, const char* expr)
{
    if (err) {
        fprintf(stderr, "Failed on %s with error: %s\n", expr, uc_strerror(err)); exit(1);
    }
    else {
        // fprintf(stderr, "Succeeded on %s\n", expr);
    }
    return err;
}
#define UC_ERR_CHECK(x) _uc_err_check(x, #x)







void create_GDT(uc_engine *uc){
    uc_x86_mmr gdtr;
    uc_err err;

    err = uc_mem_map(uc, GDT_BASE, GDT_SIZE, UC_PROT_ALL);
    //GDTR gdtr;
    gdtr.base = 2147483648;
    gdtr.flags = 0;
    gdtr.limit = 4096;
    gdtr.selector = 0;
    err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
    uc_assert_success(err);
    const uint8_t a []= "\xff\xff\x00\x00\x00\xfb\xcf\x00";
    
    err = uc_mem_write(uc, gdtr.base + 4 * 8, &a, sizeof(a));
    int b = 35;
    err = uc_reg_write(uc, UC_X86_REG_CS, &b);

    const uint8_t a1 []= "\xff\xff\x00\x00\x00\xf3\xcf\x00";
    
    err = uc_mem_write(uc, gdtr.base + 5 * 8, a1, sizeof(a1));
    int b1 = 43;
    err = uc_reg_write(uc, UC_X86_REG_DS, &b1);
    err = uc_reg_write(uc, UC_X86_REG_ES, &b1);
    err = uc_reg_write(uc, UC_X86_REG_GS, &b1);

    const uint8_t a2 []= "\xff\xff\x00\x00\x00\x97\xcf\x00";
    
    int b2 = 48;
    err = uc_mem_write(uc, gdtr.base + 6 * 8, &a2, sizeof(a2));
    err = uc_reg_write(uc, UC_X86_REG_SS, &b2);

    const uint8_t a3 []= "\xff\x0f\x00\xd0\xb7\xf3\x40\x00";
    
    err = uc_mem_write(uc, gdtr.base + 10 * 8, &a3, sizeof(a3));
    int b3 = 83;
    err = uc_reg_write(uc, UC_X86_REG_FS, &b3);

    
    
}