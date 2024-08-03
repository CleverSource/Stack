local enum_counter = 0
local function enum(reset)
    if reset then
        enum_counter = 0
    end
    local result = enum_counter
    enum_counter = enum_counter + 1
    return result
end

local OP_PUSH = enum(true)
local OP_PLUS = enum()
local OP_MINUS = enum()
local OP_DUMP = enum()
local COUNT_OPS = enum()

local function push(x)
    return { OP_PUSH, x }
end

local function plus()
    return { OP_PLUS }
end

local function minus()
    return { OP_MINUS }
end

local function dump()
    return { OP_DUMP }
end

local function simulate_program(program)
    local stack = {}
    for _, op in ipairs(program) do
        assert(COUNT_OPS == 4, "Exhaustive handling of operations in simulation")
        if op[1] == OP_PUSH then
            table.insert(stack, op[2])
        elseif op[1] == OP_PLUS then
            local a = table.remove(stack)
            local b = table.remove(stack)
            table.insert(stack, a + b)
        elseif op[1] == OP_MINUS then
            local a = table.remove(stack)
            local b = table.remove(stack)
            table.insert(stack, b - a)
        elseif op[1] == OP_DUMP then
            local a = table.remove(stack)
            print(a)
        else
            assert(false, "unreachable")
        end
    end
end

local function compile_program(program)
    local out = io.open("output.asm", "w")
    if out then
        out:write("segment .text\n")
        out:write("dump:\n")
        out:write("    mov r9, -3689348814741910323\n")
        out:write("    sub rsp, 40\n")
        out:write("    mov BYTE [rsp+31], 10\n")
        out:write("    lea rcx, [rsp+30]\n")
        out:write(".L2:\n")
        out:write("    mov rax, rdi\n")
        out:write("    lea r8, [rsp+32]\n")
        out:write("    mul r9\n")
        out:write("    mov rax, rdi\n")
        out:write("    sub r8, rcx\n")
        out:write("    shr rdx, 3\n")
        out:write("    lea rsi, [rdx+rdx*4]\n")
        out:write("    add rsi, rsi\n")
        out:write("    sub rax, rsi\n")
        out:write("    add eax, 48\n")
        out:write("    mov BYTE [rcx], al\n")
        out:write("    mov rax, rdi\n")
        out:write("    mov rdi, rdx\n")
        out:write("    mov rdx, rcx\n")
        out:write("    sub rcx, 1\n")
        out:write("    cmp rax, 9\n")
        out:write("    ja .L2\n")
        out:write("    lea rax, [rsp+32]\n")
        out:write("    mov edi, 1\n")
        out:write("    sub rdx, rax\n")
        out:write("    xor eax, eax\n")
        out:write("    lea rsi, [rsp+32+rdx]\n")
        out:write("    mov rdx, r8\n")
        out:write("    mov rax, 1\n")
        out:write("    syscall\n")
        out:write("    add rsp, 40\n")
        out:write("    ret\n")
        out:write("global _start\n")
        out:write("_start:\n")
        for _, op in ipairs(program) do
            assert(COUNT_OPS == 4, "Exhaustive handling of ops in compilation")
            if op[1] == OP_PUSH then
                out:write(("    ;; -- push %d --\n"):format(op[2]))
                out:write(("    push %d\n"):format(op[2]))
            elseif op[1] == OP_PLUS then
                out:write("    ;; -- plus --\n")
                out:write("    pop rax\n")
                out:write("    pop rbx\n")
                out:write("    add rax, rbx\n")
                out:write("    push rax\n")
            elseif op[1] == OP_MINUS then
                out:write("    ;; -- minus --\n")
                out:write("    pop rax\n")
                out:write("    pop rbx\n")
                out:write("    sub rbx, rax\n")
                out:write("    push rbx\n")
            elseif op[1] == OP_DUMP then
                out:write("    ;; -- dump --\n")
                out:write("    pop rdi\n")
                out:write("    call dump\n")
            else
                assert(false, "unreachable")
            end
        end
        out:write("    mov rax, 60\n")
        out:write("    mov rdi, 0\n")
        out:write("    syscall\n")
    end
end

local function parse_word_as_op(word)
    assert(COUNT_OPS == 4, "Exhaustive op handling in parse_word_as_op")
    if word == "+" then
        return plus()
    elseif word == "-" then
        return minus()
    elseif word == "." then
        return dump()
    else
        return push(tonumber(word))
    end
end

local function load_program_from_file(file_path)
    local f = io.open(file_path, "r")
    local program = {}
    if f then
        for word in f:read("*a"):gmatch("%S+") do
            table.insert(program, parse_word_as_op(word))
        end
    end
    return program
end

local function usage()
    print("USAGE: lua stack.lua <SUBCOMMAND> [ARGS]")
    print("SUBCOMMANDS:")
    print("    sim <file>        Simulate the program")
    print("    com <file>        Compile the program")
end

local function call_cmd(cmd)
    print(cmd)
    os.execute(cmd)
end

local function uncons(xs)
    return xs[1], { table.unpack(xs, 2) }
end

local argv = arg
local subcommand = nil
local program_path = nil

assert(#argv >= 1)

if #argv < 1 then
    usage()
    print("ERROR: no subcommand is provided")
    os.exit(1)
end

subcommand, argv = uncons(argv)

if subcommand == "sim" then
    if #argv < 1 then
        usage()
        print("ERROR: no input file is provided for the simulation")
        os.exit(1)
    end
    program_path, argv = uncons(argv)
    local program = load_program_from_file(program_path)
    simulate_program(program)
elseif subcommand == "com" then
    if #argv < 1 then
        usage()
        print("ERROR: no input file is provided for the compilation")
        os.exit(1)
    end
    program_path, argv = uncons(argv)
    local program = load_program_from_file(program_path)
    compile_program(program)
    call_cmd("nasm -f elf64 output.asm")
    call_cmd("ld -o output output.o")
else
    usage()
    print(("ERROR: unknown subcommand %s"):format(subcommand))
    os.exit(1)
end