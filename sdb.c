#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/user.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <capstone/capstone.h>
#include <fcntl.h>

#define CODE_SIZE  0x10000
#define CMD_LEN    50
#define MAP_LEN    50
#define BP_LEN     50
#define ull unsigned long long 
#define ul unsigned long
pid_t child;
int status;
void* prog_ptr;
Elf64_Addr entry_point;

off_t text_offset = 0;      
size_t text_size = 0;
ull base_addr = 0;
csh cshandle = 0;
int init = 0;
int syscall_enter = 1;
unsigned char code_buffer[CODE_SIZE];
char cmd[CMD_LEN];
ul  break_points[BP_LEN];
int break_cnt = 0;
int finished = 0;


ul bp_reset = 0;

ull GetCurRip();
void Disasm();
void Disasm_addr(ull addr);
void Load(char *path[]);
void Nextstep();
void GetRegs();
void GetBreaks();
void SetBreak(char* addr);
void Replace_Bp();
void Cont();
void DelBreak(char* bp_num);
void Patch(char* addr, char* content, char* len);
void Syscall();

int main(int argc, char* argv[]){

    if(argc > 1){
        Load(argv+1);
    }

    while(!finished){
        fprintf(stdout, "(sdb) ");
        fflush(stdout);
        memset(cmd, 0, CMD_LEN);

        if(read(0, cmd, CMD_LEN) < 0){
            perror("read cmd from user");
        }

        cmd[strlen(cmd)-1] = 0;
        

        if(strncmp(cmd, "load ", 5) == 0){
            char *path[5];
            char *tmp_cmd = strdup(cmd);
            path[0] = strtok(tmp_cmd, " ");
            path[0] = strtok(NULL, " ");
            // fprintf(stderr, "[DEBUG] path: %s \n", path[0]);
            path[1] = NULL;
            
            Load(path);
        }
        else if(!init){
            fprintf(stdout, "** please load a program first.\n");
        }
        else if(strcmp(cmd, "si") == 0){
            Nextstep();
        }
        else if(strcmp(cmd, "cont") == 0){
            Cont();
        }
        else if(strcmp(cmd, "info reg") == 0){
            GetRegs();
        }
        else if(strcmp(cmd, "info break") == 0){
            GetBreaks();
        }
        else if(strncmp(cmd, "break ", 6) == 0){
            char *tmp_cmd = strdup(cmd);
            char *bp = strtok(tmp_cmd, " ");
            bp = strtok(NULL, " ");

            SetBreak(bp);

        }
        else if(strncmp(cmd, "delete ", 7) == 0){
            char *tmp_cmd = strdup(cmd);
            char *bp = strtok(tmp_cmd, " ");
            bp = strtok(NULL, " ");

            DelBreak(bp);
            
        }
        else if(strncmp(cmd, "patch ", 6) == 0){

            char *tmp_cmd = strdup(cmd);
            char *token = strtok(tmp_cmd, " ");

            token = strtok(NULL, " ");
            char *addr = strdup(token);

            token = strtok(NULL, " ");
            char *content = strdup(token);

            token = strtok(NULL, " ");
            char *len = strdup(token);





            Patch(addr, content, len);

        }
        else if(strcmp(cmd, "syscall") == 0){
            Syscall();
        }
        else{
            Nextstep();
            continue;
        }
            

    }
    
}



void Load(char *path[]){

    
    if( (child = fork()) < 0){
        perror("fork()");
    }

    if(child == 0){
        // printf("child\n");
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            perror("ptrace");
        
        execvp(path[0], path);
        perror("execvp");
    }
    else if(child > 0){
        if(waitpid(child, &status, 0) < 0){
            perror("wait");
        }
        if(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) < 0){
            perror("ptrace setopt");    
        }
            
        int fd;
        if( (fd = open(path[0], O_RDONLY)) < 0){
            perror("open elf");
        }
            
        prog_ptr = mmap(NULL, CODE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
        if(prog_ptr == NULL){
            // fprintf(stderr, "[DEBUG] Error during mmap\n");
        }

        Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*)prog_ptr;
        entry_point = elf_hdr->e_entry;
        
        Elf64_Shdr* shdr = (Elf64_Shdr*)((uintptr_t)prog_ptr + elf_hdr->e_shoff);
        char *sh_str_table = (char*)((uintptr_t)prog_ptr + shdr[elf_hdr->e_shstrndx].sh_offset);

        for(int i = 0; i < elf_hdr->e_shnum; i++) {
            if(shdr[i].sh_type == SHT_PROGBITS && strcmp(".text", sh_str_table + shdr[i].sh_name) == 0) {
                text_offset = shdr[i].sh_offset;
                text_size = shdr[i].sh_size;
                base_addr = shdr[i].sh_addr;
                break;
            }
        }

        // if(text_offset == 0 || text_size == 0 || base_addr == 0) {
        //     fprintf(stderr, "[DEBUG] text offset and size not found\n");
        // }
            
    
             
        /* Print entry point info */ 
        fprintf(stdout, "** program \'%s\' loaded. entry point 0x%lx.\n", path[0], entry_point);
        


        memcpy(code_buffer, prog_ptr+text_offset, text_size);

    

        if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
            perror("cs_open");
        
        cs_insn* insn;
        int instr_count = cs_disasm(cshandle, &code_buffer[entry_point-base_addr], text_size, entry_point, 0, &insn);

        cs_free(insn, instr_count);
        Disasm();

        init = 1;
        for(int i=0; i<BP_LEN; i++){
            break_points[i] = 0;
        }
    }
}

ull GetCurRip(){
    struct user_regs_struct tmp_regs;
    ull cur_rip;

    if(ptrace(PTRACE_GETREGS, child, 0, &tmp_regs) == 0){
        cur_rip = tmp_regs.rip;
    }
        

    // fprintf(stderr, "[DEBUG] cur_rip: %lx\n", cur_rip);
    return cur_rip;
}

void Disasm(){
    
    ull cur_rip = GetCurRip();

    
    cs_insn* insn;

    unsigned char tmp_buf[0x100];
    memcpy(tmp_buf, code_buffer+cur_rip-base_addr, 0x100);

    // fprintf(stdout, "%lx %lx\n", entry_point, base_addr);
    int instr_count = cs_disasm(cshandle, tmp_buf, text_size, cur_rip, 0, &insn);
    // fprintf(stderr, "[DEBUG] instr_count: %d\n", instr_count);



    int idx = 0;
    // while((ull)insn[idx].address < cur_rip)
    //     idx++;

    // fprintf(stderr, "[DEBUG] idx: %d \n", idx);

    for(int i = idx; i < (idx+5 > instr_count ? instr_count : idx+5); i++){
        fprintf(stdout, "\t%"PRIx64": ", insn[i].address);

        for(int j = 0; j < insn[i].size; j++)
            fprintf(stdout, "%02x ", insn[i].bytes[j]);
        
        for (int j = insn[i].size; j < 9; j++) 
            fprintf(stdout, "   ");
        
        fprintf(stdout, "\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
    }

    cs_free(insn, instr_count);

    if(idx+5 > instr_count && idx < instr_count){
        fprintf(stdout, "** the address is out of the range of the text section.\n");
    }
    
}

void GetRegs(){
    struct user_regs_struct tmp_regs;

    if(ptrace(PTRACE_GETREGS, child, 0, &tmp_regs) == 0){
        fprintf(stdout, "$rax 0x%016lx    $rbx 0x%016lx    $rcx 0x%016lx\n", tmp_regs.rax, tmp_regs.rbx, tmp_regs.rcx);
        fprintf(stdout, "$rdx 0x%016lx    $rsi 0x%016lx    $rdi 0x%016lx\n", tmp_regs.rdx, tmp_regs.rsi, tmp_regs.rdi);
        fprintf(stdout, "$rbp 0x%016lx    $rsp 0x%016lx    $r8  0x%016lx\n", tmp_regs.rbp, tmp_regs.rsp, tmp_regs.r8);
        fprintf(stdout, "$r9  0x%016lx    $r10 0x%016lx    $r11 0x%016lx\n", tmp_regs.r9, tmp_regs.r10, tmp_regs.r11);
        fprintf(stdout, "$r12 0x%016lx    $r13 0x%016lx    $r14 0x%016lx\n", tmp_regs.r12, tmp_regs.r13, tmp_regs.r14);
        fprintf(stdout, "$r15 0x%016lx    $rip 0x%016lx    $eflags 0x%016lx\n", tmp_regs.r15, tmp_regs.rip, tmp_regs.eflags);
    }
}

void GetBreaks(){

    if(break_cnt == 0){
        fprintf(stdout, "** no breakpoints.\n");
        return;
    }

    fprintf(stdout, "Num     Address\n");
    for(int i=0; i<BP_LEN; i++){
        if(break_points[i] != 0){
            fprintf(stdout, "%d\t0x%lx\n", i, break_points[i]);
        }
    }
}

void SetBreak(char *addr){
    if(strncmp(addr, "0x", 2) == 0){
        addr = addr+2;
    }

    ul bp = strtoul(addr, NULL, 16);
    // fprintf(stderr, "[DEBUG] bp: %lx\n", bp);

    
    break_points[break_cnt] = bp;
    break_cnt++;

    ull code = ptrace(PTRACE_PEEKTEXT, child, bp, 0);

    if(ptrace(PTRACE_POKETEXT, child, bp, (code & 0xffffffffffffff00) | 0xcc) < 0){
        perror("SetBreak POKE");
    }

    fprintf(stdout, "** set a breakpoint at 0x%lx.\n", bp);

}

void Replace_Bp(){

    ull cur_rip = GetCurRip();
    ull offset = cur_rip - base_addr;
    uint8_t orig_byte = code_buffer[offset];

    // fprintf(stdout, "[DEBUG] %02x\n", orig_byte);
    
    ull old_code = ptrace(PTRACE_PEEKTEXT, child, cur_rip, 0);
    ull new_code = ((old_code & 0xffffffffffffff00) | orig_byte);

    if(ptrace(PTRACE_POKETEXT, child, cur_rip, new_code) < 0){
        perror("Replace_Bp POKE");
    }

    bp_reset = cur_rip;

    // for(int i=0; i<BP_LEN; i++){
    //     if(break_points[i] == cur_rip){
    //         break_points[i] = 0;
    //         break_cnt--;
    //     }
    // }


    // old_code = ptrace(PTRACE_PEEKTEXT, child, cur_rip, 0);

    // printf("DEBUG %llx\n", old_code);




}   

void Nextstep(){
    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0){
        perror("ptrace single step");
    }

    if(waitpid(child, &status, 0) < 0){
        perror("wait");
    }
        
    if((WIFEXITED(status))){
        fprintf(stdout, "** the target program terminated.\n");
        finished = 1;
        return;
    }

    // printf("%x\n", bp_reset);
    if(bp_reset != 0){
        ull code = ptrace(PTRACE_PEEKTEXT, child, bp_reset, 0);
        if(ptrace(PTRACE_POKETEXT, child, bp_reset, (code & 0xffffffffffffff00) | 0xcc) < 0){
            perror("SetBreak POKE");
        }
        bp_reset = 0;
    }



    ull cur_rip = GetCurRip();
    // printf("cur_rip: %x\n", cur_rip);
    ull code = ptrace(PTRACE_PEEKTEXT, child, cur_rip, 0);
    if((code & 0x00000000000000ff) == 0xcc){
        fprintf(stdout, "** hit a breakpoint at 0x%llx.\n", cur_rip);
        Replace_Bp();
    }


    Disasm();
    
}

void Cont(){


    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0){
        perror("ptrace single step");
    }

    if(waitpid(child, &status, 0) < 0){
        perror("wait");
    }

    


    // printf("%x\n", bp_reset);
    if(bp_reset != 0){
        ull code = ptrace(PTRACE_PEEKTEXT, child, bp_reset, 0);
        if(ptrace(PTRACE_POKETEXT, child, bp_reset, (code & 0xffffffffffffff00) | 0xcc) < 0){
            perror("SetBreak POKE");
        }
        bp_reset = 0;
    }
    // printf("%x\n", bp_reset);







    if(ptrace(PTRACE_CONT, child, 0, 0) < 0){
        perror("ptrace cont");
    }
    
    if(waitpid(child, &status, 0) < 0){
        perror("wait");
    }
    
    if((WIFEXITED(status))){
        fprintf(stdout, "** the target program terminated.\n");
        finished = 1;
        return;
    }

    //stop at breakpoint
    struct user_regs_struct tmp_regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &tmp_regs) < 0){
        perror("ptrace GETREGS");
    }

    tmp_regs.rip = tmp_regs.rip-1;

    if(ptrace(PTRACE_SETREGS, child, 0, &tmp_regs) < 0){
        perror("ptrace SETREGS");
    }
    
    ull cur_rip = GetCurRip();
    fprintf(stdout, "** hit a breakpoint at 0x%llx.\n", cur_rip);
    
    Replace_Bp();

    Disasm(cur_rip);

}

void DelBreak(char *bp_num){
    int bp = strtol(bp_num, NULL, 10);

    if(break_points[bp] == 0){
        fprintf(stdout, "** breakpoint %d does not exist.\n", bp);
    }
    else{
        fprintf(stdout, "** delete breakpoint %d.\n", bp);
        
        ull offset = break_points[bp] - base_addr;
        uint8_t orig_byte = code_buffer[offset];

        // fprintf(stdout, "[DEBUG] %02x\n", orig_byte);
        
        ull old_code = ptrace(PTRACE_PEEKTEXT, child, break_points[bp], 0);
        ull new_code = ((old_code & 0xffffffffffffff00) | orig_byte);

        if(ptrace(PTRACE_POKETEXT, child, break_points[bp], new_code) < 0){
            perror("DELBP POKE");
        }

        break_points[bp] = 0;
    }    
}

void Patch(char* addr, char* content, char* len){

    // string -> number
    if(strncmp(addr, "0x", 2) == 0){
       addr = addr + 2; 
    }


    ul addr_i = strtoul(addr, NULL, 16);

    ull content_i = strtoull(content, NULL, 16);
    int len_i = strtol(len, NULL, 10);

    // fprintf(stdout, "[DEBUG] %lx, %llx, %d\n", addr_i, content_i, len_i);

    // write patched code back to buffer
    ull offset = addr_i - base_addr;
    ull tmp_content = content_i;

    for(int i=offset; i<offset+len_i; i++){
        code_buffer[i] = (tmp_content & 0xff);
        tmp_content /= 256;
    }

    // write patched code back to memory
    ull old_code = ptrace(PTRACE_PEEKTEXT, child, addr_i, 0);
    ull new_code;
    if(len_i == 1){
        new_code = ((old_code & 0xffffffffffffff00) | content_i);
    }
    else if(len_i == 2){
        new_code = ((old_code & 0xffffffffffff0000) | content_i);
    }
    else if(len_i == 4){
        new_code = ((old_code & 0xffffffff00000000) | content_i);
    }
    else{
        new_code = ((old_code & 0x0000000000000000) | content_i);
    }

    if(ptrace(PTRACE_POKETEXT, child, addr_i, new_code) < 0){
        perror("Patch POKE");
    }

    // make sure no break point be covered
    for(int i=0; i<BP_LEN; i++){
        if(break_points[i] != 0 && break_points[i] >= addr_i && break_points[i] < addr_i + 8*len_i){
            ull code = ptrace(PTRACE_PEEKTEXT, child, break_points[i], 0);
            if(ptrace(PTRACE_POKETEXT, child, break_points[i], (code & 0xffffffffffffff00) | 0xcc) < 0){
                perror("SetBreak POKE");
            }
        }
    }

    // printf("%llx %llx\n", old_code, new_code);
    fprintf(stdout, "** patch memory at address 0x%lx.\n", addr_i);
}

void Syscall(){
    if(ptrace(PTRACE_SYSCALL, child, 0, 0) < 0){
        perror("ptrace cont");
    }

    if(waitpid(child, &status, 0) < 0){
        perror("wait");
    }

    if((WIFEXITED(status))){
        fprintf(stdout, "** the target program terminated.\n");
        finished = 1;
        return;
    }

    if((WSTOPSIG(status) & 0x80)){
        
        struct user_regs_struct tmp_regs;
        if(ptrace(PTRACE_GETREGS, child, 0, &tmp_regs) < 0){
            perror("ptrace GETREGS");
        }

        if(syscall_enter){
            fprintf(stdout, "** enter a syscall(%d) at 0x%lx.\n", tmp_regs.orig_rax, tmp_regs.rip-2);
            Disasm_addr(tmp_regs.rip-2);
        }
        else{
            fprintf(stdout, "** leave a syscall(%d) = %d at 0x%lx.\n", tmp_regs.orig_rax, tmp_regs.rax, tmp_regs.rip-2);
            Disasm_addr(tmp_regs.rip-2);
        }
        
        syscall_enter ^= 1;
    }
    else{
        struct user_regs_struct tmp_regs;
        if(ptrace(PTRACE_GETREGS, child, 0, &tmp_regs) < 0){
            perror("ptrace GETREGS");
        }

        tmp_regs.rip = tmp_regs.rip-1;

        if(ptrace(PTRACE_SETREGS, child, 0, &tmp_regs) < 0){
            perror("ptrace SETREGS");
        }
        
        ull cur_rip = GetCurRip();
        fprintf(stdout, "** hit a breakpoint at 0x%llx.\n", cur_rip);
        
        Replace_Bp();
        Disasm();
    }

}

void Disasm_addr(ull addr){
    
    ull cur_rip = addr;

    cs_insn* insn;

    // fprintf(stdout, "%lx %lx\n", entry_point, base_addr);
    int instr_count = cs_disasm(cshandle, &code_buffer[entry_point-base_addr], text_size, entry_point, 0, &insn);
    // fprintf(stderr, "[DEBUG] instr_count: %d\n", instr_count);



    int idx = 0;
    while((ull)insn[idx].address < cur_rip)
        idx++;

    // fprintf(stderr, "[DEBUG] idx: %d \n", idx);


    for(int i = idx; i < (idx+5 > instr_count ? instr_count : idx+5); i++){
        fprintf(stdout, "\t%llx, ", insn[i].address);

        for(int j = 0; j < insn[i].size; j++)
            fprintf(stdout, "%02x ", insn[i].bytes[j]);
        
        for (int j = insn[i].size; j < 9; j++) 
            fprintf(stdout, "   ");
        
        fprintf(stdout, "\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
    }

    cs_free(insn, instr_count);

    if(idx+5 > instr_count && idx < instr_count){
        fprintf(stdout, "** the address is out of the range of the text section.\n");
    }
    
}

