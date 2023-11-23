#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <stdlib.h>
char newstack[0x1000];

void free_gadgets()
{
    __asm__("syscall;");
}

void free_gadgets_forpwntools2()
{
    __asm__("mov $0xf, %rax; ret");
}
void seccomp(){
    scmp_filter_ctx ctx;

    // 初始化Seccomp过滤器，使用SCMP_ACT_KILL表示白名单模式
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        perror("seccomp_init");
        exit(EXIT_FAILURE);
    }

    // 添加规则，允许write系统调用
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0) {
        perror("seccomp_rule_add");
        exit(EXIT_FAILURE);
    }

    // 添加规则，允许read系统调用
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0) {
        perror("seccomp_rule_add");
        exit(EXIT_FAILURE);
    }

    // 添加规则，允许open系统调用
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) < 0) {
        perror("seccomp_rule_add");
        exit(EXIT_FAILURE);
    }

    // 添加规则，允许chmod系统调用
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0) < 0) {
        perror("seccomp_rule_add");
        exit(EXIT_FAILURE);
    }

    // 添加规则，允许exit系统调用
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0) {
        perror("seccomp_rule_add");
        exit(EXIT_FAILURE);
    }

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0) < 0) {
        perror("seccomp_rule_add");
        exit(EXIT_FAILURE);
    }

    // 将规则加载到内核中
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        exit(EXIT_FAILURE);
    }
}
int challenge()
{
    //char string[24] = "I'v got permissions:rws\n";
    char string[24] = "Do u know what is SGID?\n";
    char buff[10] = "easyhack\n";
    syscall(1, 1, buff, 9);
    syscall(0, 0, newstack, 0x1000);
    syscall(1, 1, string, 24);
    syscall(0, 0, buff, 58);
    return 0;
}
void init()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(int argc, char **argv)
{
    init();
    seccomp();
    int result = challenge();
    if (result == 12)
    {
        // free_gadgets();
        // free_gadgets_forpwntools2();
    }
    return 0;
}
