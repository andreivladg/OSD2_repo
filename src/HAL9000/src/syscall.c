#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread_internal.h"
#include "thread.h"
#include "mutex.h"

extern void SyscallEntry();

typedef struct _GlobalVariable{
    char* Name;
    QWORD Value;
}GlobalVariable;

static GlobalVariable reviewVar;


#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdFileWrite:
            status = SyscallFileWrite(
                (UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]
                );
            break;
        case SyscallIdMemset:
            status = SyscallMemset(
                (PBYTE)pSyscallParameters[0],
                (DWORD)pSyscallParameters[1],
                (BYTE)pSyscallParameters[2]
            );
            break;
        case SyscallIdDisableSyscalls:
            status = SyscallDisableSyscalls(
                (BOOLEAN)pSyscallParameters[0]
            );
            break;
        case SyscallIdSetGlobalVariable:
            status = SyscallSetGlobalVariable(
                (char*)pSyscallParameters[0],
                (DWORD)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2]
            );
            break;
        case SyscallIdGetGlobalVariable:
            status = SyscallGetGlobalVariable(
                (char*)pSyscallParameters[0],
                (DWORD)pSyscallParameters[1],
                (PQWORD)pSyscallParameters[2]
            );
            break;
        case SyscallIdMutexInit:
            status = SyscallMutexInit(
                (UM_HANDLE*)pSyscallParameters[0]
            );
            break;
        case SyscallIdMutexAquire:
            status = SyscallMutexAcquire(
                (UM_HANDLE)pSyscallParameters[0]
            );
            break;
        case SyscallIdMutexRelease:
            status = SyscallMutexRelease(
                (UM_HANDLE)pSyscallParameters[0]
            );
            break;
        /*case SyscallIdProcessCreate:
            status = SyscallProcessCreate(
                (PBYTE)pSyscallParameters[0],
                (DWORD)pSyscallParameters[1],
                (BYTE)pSyscallParameters[2]
            );
            break;*/
        // STUDENT TODO: implement the rest of the syscalls
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls

STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    PPROCESS Process;
    Process = GetCurrentProcess();
    Process->TerminationStatus = ExitStatus;
    ProcessTerminate(Process);
    return STATUS_SUCCESS;
    
}

STATUS
SyscallThreadExit(
    IN  STATUS                      ExitStatus
)
{
    ThreadExit(ExitStatus);
    return STATUS_SUCCESS;
}

STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                       Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    if (BytesWritten == NULL) {
        return STATUS_UNSUCCESSFUL;

    }

    if (FileHandle == UM_FILE_HANDLE_STDOUT) {

        *BytesWritten = BytesToWrite;
        LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);
        return STATUS_SUCCESS;


    }

    *BytesWritten = BytesToWrite;
    return STATUS_SUCCESS;
}

STATUS
SyscallMemset(
    OUT_WRITES(BytesToWrite)    PBYTE   Address,
    IN                          DWORD   BytesToWrite,
    IN                          BYTE    ValueToWrite
) {
    memset(Address, ValueToWrite, BytesToWrite);
    return STATUS_SUCCESS;
}

STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)  char* ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength) char* Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE*       ProcessHandle
) 
{
    PPROCESS process;
    UNREFERENCED_PARAMETER(PathLength);
    UNREFERENCED_PARAMETER(ArgLength);
    ProcessCreate(ProcessPath, Arguments, &process);
    *ProcessHandle = (UM_HANDLE) process->Id;
    return STATUS_SUCCESS;
}

STATUS 
SyscallDisableSyscalls(
    IN BOOLEAN Disable
) {
    if (Disable == TRUE) {
        //Disable syscalls
    }
    else if (Disable == FALSE){
        //All syscalls work normally
    }

    return STATUS_SUCCESS;
}


STATUS
SyscallSetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    IN                              QWORD   Value
) {
    UNREFERENCED_PARAMETER(VariableName);
    cl_memset(&reviewVar, sizeof(Value), VarLength);
    return STATUS_SUCCESS;
}

STATUS
SyscallGetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    OUT                             PQWORD   Value
) {
    UNREFERENCED_PARAMETER(VariableName);
    UNREFERENCED_PARAMETER(VarLength);
    Value = (PQWORD) reviewVar.Name;
    return STATUS_SUCCESS;
}

STATUS
SyscallMutexInit(
    OUT         UM_HANDLE* Mutex
) {
    PMUTEX m;
    m = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(PMUTEX), HEAP_THREAD_TAG, 0);
    MutexInit(m, TRUE);
    Mutex = (UM_HANDLE*)m;
    return STATUS_SUCCESS;
}

STATUS
SyscallMutexAcquire(
    IN       UM_HANDLE          Mutex
) {
    MutexAcquire((PMUTEX)Mutex);
    return STATUS_SUCCESS;
}

STATUS
SyscallMutexRelease(
    IN       UM_HANDLE          Mutex
) {
    MutexRelease((PMUTEX)Mutex);
    return STATUS_SUCCESS;
}