option casemap:none
EXTERN VirtualizedFunctionBridge:PROC
.code
PeVmNativeEntry PROC FRAME
 push rbp
 .pushreg rbp
 mov rbp,rsp
 .setframe rbp,0
 pushfq
 and rsp,-16
 sub rsp,448
 .endprolog
 mov [rsp+32],rax
 mov [rsp+40],rcx
 mov [rsp+48],rdx
 mov [rsp+56],rbx
 mov [rsp+80],rsi
 mov [rsp+88],rdi
 mov [rsp+96],r8
 mov [rsp+104],r9
 mov [rsp+112],r10
 mov [rsp+120],r11
 mov [rsp+128],r12
 mov [rsp+136],r13
 mov [rsp+144],r14
 mov [rsp+152],r15
 lea rax,[rbp+24]
 mov [rsp+64],rax
 mov rax,[rbp]
 mov [rsp+72],rax
 mov rax,[rbp-8]
 mov [rsp+416],rax
 stmxcsr dword ptr [rsp+440]
 movdqu xmmword ptr [rsp+160],xmm0
 movdqu xmmword ptr [rsp+176],xmm1
 movdqu xmmword ptr [rsp+192],xmm2
 movdqu xmmword ptr [rsp+208],xmm3
 movdqu xmmword ptr [rsp+224],xmm4
 movdqu xmmword ptr [rsp+240],xmm5
 movdqu xmmword ptr [rsp+256],xmm6
 movdqu xmmword ptr [rsp+272],xmm7
 movdqu xmmword ptr [rsp+288],xmm8
 movdqu xmmword ptr [rsp+304],xmm9
 movdqu xmmword ptr [rsp+320],xmm10
 movdqu xmmword ptr [rsp+336],xmm11
 movdqu xmmword ptr [rsp+352],xmm12
 movdqu xmmword ptr [rsp+368],xmm13
 movdqu xmmword ptr [rsp+384],xmm14
 movdqu xmmword ptr [rsp+400],xmm15
 lea rcx,[rsp+32]
 mov edx,[rbp+16]
 call VirtualizedFunctionBridge
 movdqu xmm0,xmmword ptr [rsp+160]
 movdqu xmm1,xmmword ptr [rsp+176]
 movdqu xmm2,xmmword ptr [rsp+192]
 movdqu xmm3,xmmword ptr [rsp+208]
 movdqu xmm4,xmmword ptr [rsp+224]
 movdqu xmm5,xmmword ptr [rsp+240]
 movdqu xmm6,xmmword ptr [rsp+256]
 movdqu xmm7,xmmword ptr [rsp+272]
 movdqu xmm8,xmmword ptr [rsp+288]
 movdqu xmm9,xmmword ptr [rsp+304]
 movdqu xmm10,xmmword ptr [rsp+320]
 movdqu xmm11,xmmword ptr [rsp+336]
 movdqu xmm12,xmmword ptr [rsp+352]
 movdqu xmm13,xmmword ptr [rsp+368]
 movdqu xmm14,xmmword ptr [rsp+384]
 movdqu xmm15,xmmword ptr [rsp+400]
 push qword ptr [rsp+416]
 popfq
 ldmxcsr dword ptr [rsp+440]
 mov rax,[rsp+32]
 mov rcx,[rsp+40]
 mov rdx,[rsp+48]
 mov rbx,[rsp+56]
 mov rsi,[rsp+80]
 mov rdi,[rsp+88]
 mov r8,[rsp+96]
 mov r9,[rsp+104]
 mov r10,[rsp+112]
 mov r11,[rsp+120]
 mov r12,[rsp+128]
 mov r13,[rsp+136]
 mov r14,[rsp+144]
 mov r15,[rsp+152]
 lea rsp,[rbp]
 pop rbp
 ret
PeVmNativeEntry ENDP
END
