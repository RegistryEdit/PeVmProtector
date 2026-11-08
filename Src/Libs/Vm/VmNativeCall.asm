option casemap:none
.code
PeVmCallNative PROC FRAME
 push rbp
 .pushreg rbp
 push rbx
 .pushreg rbx
 push rsi
 .pushreg rsi
 push rdi
 .pushreg rdi
 push r12
 .pushreg r12
 push r13
 .pushreg r13
 push r14
 .pushreg r14
 push r15
 .pushreg r15
 sub rsp,712
 .allocstack 712
 movdqu xmmword ptr [rsp+544],xmm6
 .savexmm128 xmm6,544
 movdqu xmmword ptr [rsp+560],xmm7
 .savexmm128 xmm7,560
 movdqu xmmword ptr [rsp+576],xmm8
 .savexmm128 xmm8,576
 movdqu xmmword ptr [rsp+592],xmm9
 .savexmm128 xmm9,592
 movdqu xmmword ptr [rsp+608],xmm10
 .savexmm128 xmm10,608
 movdqu xmmword ptr [rsp+624],xmm11
 .savexmm128 xmm11,624
 movdqu xmmword ptr [rsp+640],xmm12
 .savexmm128 xmm12,640
 movdqu xmmword ptr [rsp+656],xmm13
 .savexmm128 xmm13,656
 movdqu xmmword ptr [rsp+672],xmm14
 .savexmm128 xmm14,672
 movdqu xmmword ptr [rsp+688],xmm15
 .savexmm128 xmm15,688
 .endprolog
 stmxcsr dword ptr [rsp+704]
 mov [rsp+512],rcx
 mov rax,[rcx+392]
 mov [rsp+520],rax
 mov rsi,[rcx+400]
 mov rdi,rsp
 mov ecx,64
 cld
 rep movsq
 mov r11,[rsp+512]
 ldmxcsr dword ptr [r11+408]
 movdqu xmm0,xmmword ptr [r11+128]
 movdqu xmm1,xmmword ptr [r11+144]
 movdqu xmm2,xmmword ptr [r11+160]
 movdqu xmm3,xmmword ptr [r11+176]
 movdqu xmm4,xmmword ptr [r11+192]
 movdqu xmm5,xmmword ptr [r11+208]
 movdqu xmm6,xmmword ptr [r11+224]
 movdqu xmm7,xmmword ptr [r11+240]
 movdqu xmm8,xmmword ptr [r11+256]
 movdqu xmm9,xmmword ptr [r11+272]
 movdqu xmm10,xmmword ptr [r11+288]
 movdqu xmm11,xmmword ptr [r11+304]
 movdqu xmm12,xmmword ptr [r11+320]
 movdqu xmm13,xmmword ptr [r11+336]
 movdqu xmm14,xmmword ptr [r11+352]
 movdqu xmm15,xmmword ptr [r11+368]
 push qword ptr [r11+384]
 popfq
 mov rax,[r11+0]
 mov rcx,[r11+8]
 mov rdx,[r11+16]
 mov rbx,[r11+24]
 mov rbp,[r11+40]
 mov rsi,[r11+48]
 mov rdi,[r11+56]
 mov r8,[r11+64]
 mov r9,[r11+72]
 mov r10,[r11+80]
 mov r12,[r11+96]
 mov r13,[r11+104]
 mov r14,[r11+112]
 mov r15,[r11+120]
 mov r11,[r11+88]
 call qword ptr [rsp+520]
 mov [rsp+528],r11
 mov r11,[rsp+512]
 stmxcsr dword ptr [r11+408]
 mov [r11+0],rax
 mov [r11+8],rcx
 mov [r11+16],rdx
 mov [r11+24],rbx
 mov [r11+40],rbp
 mov [r11+48],rsi
 mov [r11+56],rdi
 mov [r11+64],r8
 mov [r11+72],r9
 mov [r11+80],r10
 mov [r11+96],r12
 mov [r11+104],r13
 mov [r11+112],r14
 mov [r11+120],r15
 mov rax,[rsp+528]
 mov [r11+88],rax
 pushfq
 pop rax
 mov [r11+384],rax
 movdqu xmmword ptr [r11+128],xmm0
 movdqu xmmword ptr [r11+144],xmm1
 movdqu xmmword ptr [r11+160],xmm2
 movdqu xmmword ptr [r11+176],xmm3
 movdqu xmmword ptr [r11+192],xmm4
 movdqu xmmword ptr [r11+208],xmm5
 movdqu xmmword ptr [r11+224],xmm6
 movdqu xmmword ptr [r11+240],xmm7
 movdqu xmmword ptr [r11+256],xmm8
 movdqu xmmword ptr [r11+272],xmm9
 movdqu xmmword ptr [r11+288],xmm10
 movdqu xmmword ptr [r11+304],xmm11
 movdqu xmmword ptr [r11+320],xmm12
 movdqu xmmword ptr [r11+336],xmm13
 movdqu xmmword ptr [r11+352],xmm14
 movdqu xmmword ptr [r11+368],xmm15
 movdqu xmm6,xmmword ptr [rsp+544]
 movdqu xmm7,xmmword ptr [rsp+560]
 movdqu xmm8,xmmword ptr [rsp+576]
 movdqu xmm9,xmmword ptr [rsp+592]
 movdqu xmm10,xmmword ptr [rsp+608]
 movdqu xmm11,xmmword ptr [rsp+624]
 movdqu xmm12,xmmword ptr [rsp+640]
 movdqu xmm13,xmmword ptr [rsp+656]
 movdqu xmm14,xmmword ptr [rsp+672]
 movdqu xmm15,xmmword ptr [rsp+688]
 ldmxcsr dword ptr [rsp+704]
 add rsp,712
 pop r15
 pop r14
 pop r13
 pop r12
 pop rdi
 pop rsi
 pop rbx
 pop rbp
 ret
PeVmCallNative ENDP
END
